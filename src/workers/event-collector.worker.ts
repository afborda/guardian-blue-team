import { ServerService } from '../services/server.service.js';
import { AuditLogger } from '../utils/audit-logger.js';
import { LogCollector } from '../collectors/log-collector.js';
import { ProcessCollector } from '../collectors/process-collector.js';
import { NetworkCollector } from '../collectors/network-collector.js';
import { ContainerRuntimeCollector } from '../collectors/container-runtime-collector.js';
import { SudoCollector } from '../collectors/sudo-collector.js';
import { DNSCollector } from '../collectors/dns-collector.js';
import { SyslogCollector } from '../collectors/syslog-collector.js';
import { ProxyCollector } from '../collectors/proxy-collector.js';
import { PackageCollector } from '../collectors/package-collector.js';
import { SystemdCollector } from '../collectors/systemd-collector.js';
import { SystemCollector } from '../collectors/system-collector.js';
import { HealthCollector } from '../collectors/health-collector.js';
import { HostSecurityService } from '../services/host-security.service.js';
import { AuditCollector } from '../collectors/audit-collector.js';
import { LoginHistoryCollector } from '../collectors/login-history-collector.js';
import { AppLogCollector } from '../collectors/app-log-collector.js';
import { EventNormalizer } from '../pipeline/normalizer.js';
import { EventEnricher } from '../pipeline/enricher.js';
import { EventDetector } from '../pipeline/detector.js';
import { enrichWithDgaScore } from '../intelligence/dga-enricher.js';
import { enrichWithMarkovScore } from '../intelligence/markov-enricher.js';
import { EventCorrelator, type CorrelationResult } from '../pipeline/correlator.js';
import { EventIngestor } from '../pipeline/ingestor.js';
import { PlaybookRegistry } from '../playbooks/registry.js';
import { PlaybookEngine, type PlaybookContext } from '../playbooks/engine.js';
import { AIBlockAdvisor } from '../services/ai-block-advisor.service.js';
import { blockIP, syncBlocksToServer } from '../playbooks/actions/block-ip.js';
import { requestPlaybookApproval } from '../telegram/callbacks.js';
import { addWebPendingApproval } from '../dashboard/routes.js';
import { requestLoginVerification } from '../telegram/login-verification.js';
import { db, dbTrue, dbNow } from '../database/connection.js';
import { socIncidents, blockedIps } from '../database/schema.js';
import { eq, and } from 'drizzle-orm';
import { config } from '../config/environment.js';
import { CONSTANTS } from '../config/constants.js';
import { logger } from '../utils/logger.js';
import { CVEMonitorWorker } from './cve-monitor.worker.js';

export class EventCollectorWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 2 * 60 * 1000;
  private static running = false;

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.collect().catch(err => logger.error({ err }, 'Event collector error'));
    }, 10_000);

    // One-time global block sync on startup
    setTimeout(() => {
      this.syncAllBlocks().catch(err => logger.error({ err }, 'Startup block sync failed'));
    }, 20_000);

    this.intervalId = setInterval(() => {
      this.collect().catch(err => logger.error({ err }, 'Event collector error'));
    }, this.INTERVAL_MS);

    logger.info('Event collector worker started (every 2min)');
  }

  static async collect(): Promise<void> {
    if (this.running) return;
    this.running = true;

    try {
      const servers = await ServerService.getEnabled();
      if (servers.length === 0) {
        logger.debug('No servers registered, skipping event collection');
        return;
      }

      let totalEvents = 0;
      const newIncidentResults: CorrelationResult[] = [];

      // Also monitor Guardian's own host (id=0, name='local') — not registered in DB
      const guardianHost = HostSecurityService.getDefaultTarget();
      const allTargets: Array<{ id: number; name: string; target: typeof guardianHost }> = [
        ...servers.map(s => ({ id: s.id, name: s.name, target: ServerService.toSSHTarget(s) })),
        { id: guardianHost.id, name: guardianHost.name, target: guardianHost },
      ];

      for (const { id: serverId, name: serverName, target } of allTargets) {
        const [authLogs, ufwLogs, dockerEvents, suspiciousProcs, networkAnomaly, sudoLogs, dnsLogs, syslogLogs, proxyLogs, packageLogs, systemdLogs, auditLogs, containerProcs, loginSessions, failedLogins, currentSessions, kernelEntries, appLogs, diskEntries, rebootEntries] = await Promise.all([
          LogCollector.collectAuthLogs(target, 3),
          LogCollector.collectUfwLogs(target, 3),
          LogCollector.collectDockerEvents(target, 3),
          ProcessCollector.detectSuspiciousProcesses(target),
          NetworkCollector.collectAllThreats(target),
          SudoCollector.collect(target, 3),
          DNSCollector.collect(target, 3),
          SyslogCollector.collect(target, 3),
          ProxyCollector.collect(target, 3),
          PackageCollector.collect(target, 5),
          SystemdCollector.collect(target, 3),
          AuditCollector.collect(target, 3),
          ContainerRuntimeCollector.collectContainerProcesses(target),
          LoginHistoryCollector.collectSessions(target, 50),
          LoginHistoryCollector.collectFailedLogins(target, 50),
          LoginHistoryCollector.collectCurrentSessions(target),
          SystemCollector.collectAsRawEntries(target),
          AppLogCollector.collect(target),
          HealthCollector.collectCriticalDiskEntries(target),
          HealthCollector.collectRebootEntry(target),
        ]);

        const rawLogs = [...authLogs, ...ufwLogs, ...dockerEvents, ...suspiciousProcs, ...networkAnomaly, ...sudoLogs, ...dnsLogs, ...syslogLogs, ...proxyLogs, ...packageLogs, ...systemdLogs, ...auditLogs, ...containerProcs, ...loginSessions, ...failedLogins, ...currentSessions, ...kernelEntries, ...appLogs, ...diskEntries, ...rebootEntries];
        if (rawLogs.length === 0) {
          await AuditLogger.operational(serverId, 'collection_cycle', 'skipped', { server: serverName, reason: 'no_logs' });
          continue;
        }

        logger.debug({
          server: serverName,
          auth: authLogs.length, ufw: ufwLogs.length, docker: dockerEvents.length,
          process: suspiciousProcs.length, network: networkAnomaly.length, sudo: sudoLogs.length,
          dns: dnsLogs.length, syslog: syslogLogs.length, proxy: proxyLogs.length,
          package: packageLogs.length, systemd: systemdLogs.length, audit: auditLogs.length,
          containerProcs: containerProcs.length, loginSessions: loginSessions.length,
          failedLogins: failedLogins.length, currentSessions: currentSessions.length,
          kernel: kernelEntries.length, appLogs: appLogs.length,
          diskCritical: diskEntries.length, reboot: rebootEntries.length,
        }, 'Collector results');

        let normalized = EventNormalizer.normalizeBatch(rawLogs);
        if (normalized.length === 0) continue;

        // Pre-classify DNS queries against the DGA model so the synchronous
        // detector rule can read the score from event.metadata.dgaScore.
        normalized = await enrichWithDgaScore(normalized);

        // Pre-score sudo command transitions for the synchronous detector rule
        // — Markov surprisal vs. each user's own p99 threshold.
        normalized = await enrichWithMarkovScore(normalized);

        const detected = EventDetector.detect(normalized);
        if (detected.length > 0) {
          normalized = [...normalized, ...detected];
        }

        // Trigger a CVE re-scan if new packages were installed or upgraded
        const hasPackageChange = normalized.some(e =>
          e.eventType === 'package_installed' || e.eventType === 'package_removed',
        );
        if (hasPackageChange) {
          CVEMonitorWorker.run().catch(err =>
            logger.warn({ err, server: serverName }, 'CVE re-scan after package change failed'),
          );
        }

        normalized = await EventEnricher.enrich(normalized);

        const correlated = await EventCorrelator.correlate(normalized);
        await EventIngestor.persist(correlated);

        totalEvents += correlated.length;
        await AuditLogger.operational(serverId, 'collection_cycle', 'success', {
          server: serverName,
          events: correlated.length,
          auth: authLogs.length, ufw: ufwLogs.length, docker: dockerEvents.length,
          process: suspiciousProcs.length, network: networkAnomaly.length,
        });
        // Trigger playbooks for new incidents AND for events correlated to existing incidents with a source IP (ensures auto-block)
        newIncidentResults.push(...correlated.filter(r => r.isNewIncident || (r.incidentId && r.incidentCategory && r.event.sourceIp)));

        if (serverId > 0) {
          await ServerService.updateLastSeen(serverId);
        }
      }

      if (totalEvents > 0) {
        logger.info({ events: totalEvents, newIncidents: newIncidentResults.length, servers: servers.length }, 'Event collection cycle complete');
      }

      if (newIncidentResults.length > 0) {
        // Only send the aggregate "N novos incidentes" header when N>1.
        // For a single incident the Playbook Alert that follows already has
        // all the detail (server, IP, severity, actions) — sending both is
        // pure noise.
        const newCount = newIncidentResults.filter(r => r.isNewIncident).length;
        if (newCount > 1) {
          await this.notifyNewIncidents(newCount);
        }
        await this.triggerPlaybooks(newIncidentResults);
      }

      // Ensure all open incidents with IPs have those IPs blocked
      await this.enforceBlocks();
    } finally {
      this.running = false;
    }
  }

  private static async enforceBlocks(): Promise<void> {
    try {
      const openIncidents = await db.select().from(socIncidents)
        .where(eq(socIncidents.status, 'open'));

      if (openIncidents.length === 0) return;

      const servers = await ServerService.getEnabled();

      for (const incident of openIncidents) {
        const ips = (incident.sourceIps ?? []) as string[];
        if (ips.length === 0) continue;

        let allBlocked = true;

        for (const ip of ips) {
          for (const server of servers) {
            const existing = await db.select({ id: blockedIps.id }).from(blockedIps)
              .where(and(
                eq(blockedIps.ip, ip),
                eq(blockedIps.serverId, server.id),
                eq(blockedIps.active, dbTrue),
              ))
              .then(rows => rows[0]);

            if (existing) continue;

            const ctx: PlaybookContext = {
              serverId: server.id,
              serverName: server.name,
              incidentId: incident.id,
              sourceIp: ip,
              triggeredBy: 'auto-enforce',
              variables: {},
            };

            const result = await blockIP(ctx, { duration: 'permanent' });
            if (result.success && !result.message.includes('already blocked')) {
              logger.info({ ip, server: server.name, incidentId: incident.id }, 'Auto-enforced block for open incident');
              await AuditLogger.block(ip, server.id, 'auto-enforce', incident.id, { method: result.message });
            } else if (!result.success) {
              allBlocked = false;
            }
          }
        }

        if (allBlocked) {
          await db.update(socIncidents)
            .set({ status: 'resolved', resolvedAt: dbNow() })
            .where(eq(socIncidents.id, incident.id));
          logger.info({ incidentId: incident.id, ips }, 'Incident auto-resolved — all IPs blocked');
        }
      }
    } catch (err) {
      logger.error({ err }, 'enforceBlocks failed');
    }
  }

  private static recentlyTriggered = new Map<string, number>();

  // Public so non-worker code (Falco webhook) can reuse the dedupe + trigger
  // logic without re-implementing it. Promoting to public is cheaper than
  // extracting to a module — refactor when a third caller appears.
  static async triggerPlaybooks(results: CorrelationResult[]): Promise<void> {
    const serverCache = new Map<number, string>();
    const now = Date.now();

    // Clean stale entries (>5min old)
    for (const [key, ts] of this.recentlyTriggered) {
      if (now - ts > 5 * 60_000) this.recentlyTriggered.delete(key);
    }

    for (const result of results) {
      // Match playbooks by event type OR incident category (port_scan incidents come from firewall_block events)
      const matchingPlaybooks = [
        ...PlaybookRegistry.getByTrigger(result.event.eventType),
        ...(result.incidentCategory ? PlaybookRegistry.getByTrigger(result.incidentCategory) : []),
      ].filter((p, i, arr) => arr.findIndex(x => x.name === p.name) === i);

      let serverName = serverCache.get(result.event.serverId);
      if (!serverName) {
        const server = await ServerService.getById(result.event.serverId);
        serverName = server?.name ?? `server-${result.event.serverId}`;
        serverCache.set(result.event.serverId, serverName);
      }

      for (const playbook of matchingPlaybooks) {
        // Dedup: same playbook+IP within 5min only fires once across the
        // whole fleet. Previously included serverId in the key — that meant
        // an IP scanning 3 servers triggered 3 alerts in 30 seconds, which
        // was the visible source of the "spam" pattern.
        const dedupKey = `${playbook.name}:${result.event.sourceIp ?? `srv-${result.event.serverId}`}`;
        if (this.recentlyTriggered.has(dedupKey)) continue;

        const ctx: PlaybookContext = {
          serverId: result.event.serverId,
          serverName,
          incidentId: result.incidentId ?? undefined,
          sourceIp: result.event.sourceIp ?? undefined,
          triggeredBy: 'auto',
          variables: {
            ...(result.event.processName ? { containerName: result.event.processName } : {}),
            ...(result.event.metadata?.containerName ? { containerName: result.event.metadata.containerName as string } : {}),
            ...(result.event.metadata?.command ? { command: result.event.metadata.command as string } : {}),
          },
        };

        if (playbook.requiresApproval) {
          requestPlaybookApproval(playbook.name, ctx);
          addWebPendingApproval(playbook.name, ctx);
          continue;
        }

        // Consult AI before auto-executing blocking playbooks (skip for clear-cut threats)
        const hasBlockAction = playbook.steps.some(s => s.action === 'block-ip');
        const alwaysBlock = ['port_scan', 'brute_force', 'ddos', 'crypto_mining', 'lateral_movement'].includes(result.incidentCategory ?? '');
        if (hasBlockAction && result.event.sourceIp && alwaysBlock) {
          // Bypass advisor but still capture TI signal for FP audit (v2 hardening §7.1, option B).
          AIBlockAdvisor.logTiHint(ctx, {
            eventType: result.event.eventType,
            sourceIp: result.event.sourceIp,
          }).catch(() => {});
        }
        if (hasBlockAction && result.event.sourceIp && !alwaysBlock) {
          try {
            const recommendation = await AIBlockAdvisor.getRecommendation(ctx, {
              eventType: result.event.eventType,
              severity: result.event.severity,
              eventCount: result.event.metadata?.eventCount as number | undefined,
              sourceIp: result.event.sourceIp,
            });

            // Trust the advisor's `action`. The advisor already encodes the
            // TI+AI gate and downgrades low-confidence-block decisions to
            // 'monitor'/'ignore' itself, so there's no need to re-check
            // confidence here — doing so was the source of a bug where a
            // 60%-conf monitor recommendation was overruled and the block
            // executed anyway.
            if (recommendation.action === 'monitor' || recommendation.action === 'ignore') {
              logger.info({
                ip: result.event.sourceIp, playbook: playbook.name,
                action: recommendation.action, confidence: recommendation.confidence,
                source: recommendation.source, tiScore: recommendation.tiScore,
                reasoning: recommendation.reasoning,
              }, 'AI advisor: skipping block');
              continue;
            }
            if (recommendation.action === 'rate_limit' && recommendation.confidence >= 70) {
              ctx.variables = { ...ctx.variables, aiOverride: 'rate_limit' };
            }

            // Always log final decision so audit can replay why each block fired.
            logger.info({
              ip: result.event.sourceIp, playbook: playbook.name,
              action: recommendation.action, confidence: recommendation.confidence,
              source: recommendation.source, tiScore: recommendation.tiScore,
            }, 'AI advisor: decision');
          } catch (err) {
            logger.debug({ err }, 'AI advisor failed — proceeding with rule-based block');
          }
        }

        try {
          await Promise.race([
            PlaybookEngine.execute(playbook, ctx),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Playbook timeout')), CONSTANTS.telegram.playbookTimeoutMs)),
          ]);
        } catch (err) {
          logger.error({ err, playbook: playbook.name }, 'Auto-triggered playbook failed');
        }

        this.recentlyTriggered.set(dedupKey, now);
        logger.info({ playbook: playbook.name, ip: result.event.sourceIp, incident: result.incidentId }, 'Playbook auto-triggered');
      }

      if (result.event.eventType === 'unauthorized_login' && result.incidentId && result.event.sourceIp) {
        const alreadyBlocked = await db.select({ id: blockedIps.id }).from(blockedIps)
          .where(and(eq(blockedIps.ip, result.event.sourceIp), eq(blockedIps.active, dbTrue)))
          .limit(1);
        if (alreadyBlocked.length > 0) {
          logger.debug({ ip: result.event.sourceIp }, 'Skipping login verification — IP already blocked');
        } else {
          requestLoginVerification({
            incidentId: result.incidentId,
            sourceIp: result.event.sourceIp,
            userName: result.event.userName ?? 'unknown',
            serverName,
            authMethod: (result.event.metadata?.authMethod as string) ?? 'unknown',
            fingerprint: (result.event.metadata?.fingerprint as string) ?? null,
            timestamp: result.event.timestamp,
          });
        }
      }
    }
  }

  private static async notifyNewIncidents(count: number): Promise<void> {
    try {
      const text = [
        `&#128680; <b>${count} novo(s) incidente(s) detectado(s)</b>`,
        ``,
        `<b>O que fazer:</b>`,
        `  /incidents — ver detalhes e tomar acao`,
        `  /dashboard — painel visual com botoes de acao`,
        `  /scores — verificar impacto no score de seguranca`,
        ``,
        `<i>Incidentes criticos sao tratados automaticamente. Verifique os que precisam de aprovacao.</i>`,
      ].join('\n');

      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text,
          parse_mode: 'HTML',
        }),
      });
    } catch {
      logger.warn('Failed to notify new incidents');
    }
  }

  private static async syncAllBlocks(): Promise<void> {
    try {
      const servers = await ServerService.getEnabled();
      let totalSynced = 0;
      for (const server of servers) {
        const synced = await syncBlocksToServer(server.id);
        totalSynced += synced;
      }
      if (totalSynced > 0) {
        logger.info({ totalSynced, servers: servers.length }, 'Startup block sync complete');
      }
    } catch (err) {
      logger.error({ err }, 'syncAllBlocks failed');
    }
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.running = false;
    logger.info('Event collector worker stopped');
  }
}
