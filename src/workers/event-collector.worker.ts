import { ServerService } from '../services/server.service.js';
import { LogCollector } from '../collectors/log-collector.js';
import { ProcessCollector } from '../collectors/process-collector.js';
import { NetworkCollector } from '../collectors/network-collector.js';
import { SudoCollector } from '../collectors/sudo-collector.js';
import { DNSCollector } from '../collectors/dns-collector.js';
import { SyslogCollector } from '../collectors/syslog-collector.js';
import { ProxyCollector } from '../collectors/proxy-collector.js';
import { PackageCollector } from '../collectors/package-collector.js';
import { SystemdCollector } from '../collectors/systemd-collector.js';
import { AuditCollector } from '../collectors/audit-collector.js';
import { EventNormalizer } from '../pipeline/normalizer.js';
import { EventEnricher } from '../pipeline/enricher.js';
import { EventDetector } from '../pipeline/detector.js';
import { EventCorrelator, type CorrelationResult } from '../pipeline/correlator.js';
import { EventIngestor } from '../pipeline/ingestor.js';
import { PlaybookRegistry } from '../playbooks/registry.js';
import { PlaybookEngine, type PlaybookContext } from '../playbooks/engine.js';
import { AIBlockAdvisor } from '../services/ai-block-advisor.service.js';
import { blockIP } from '../playbooks/actions/block-ip.js';
import { requestPlaybookApproval } from '../telegram/callbacks.js';
import { addWebPendingApproval } from '../dashboard/routes.js';
import { requestLoginVerification } from '../telegram/login-verification.js';
import { db, dbTrue, dbNow } from '../database/connection.js';
import { socIncidents, blockedIps } from '../database/schema.js';
import { eq, and } from 'drizzle-orm';
import { config } from '../config/environment.js';
import { CONSTANTS } from '../config/constants.js';
import { logger } from '../utils/logger.js';

export class EventCollectorWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 2 * 60 * 1000;
  private static running = false;

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.collect().catch(err => logger.error({ err }, 'Event collector error'));
    }, 10_000);

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

      for (const server of servers) {
        const target = ServerService.toSSHTarget(server);

        const [authLogs, ufwLogs, dockerEvents, suspiciousProcs, networkAnomaly, sudoLogs, dnsLogs, syslogLogs, proxyLogs, packageLogs, systemdLogs, auditLogs] = await Promise.all([
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
        ]);

        const rawLogs = [...authLogs, ...ufwLogs, ...dockerEvents, ...suspiciousProcs, ...networkAnomaly, ...sudoLogs, ...dnsLogs, ...syslogLogs, ...proxyLogs, ...packageLogs, ...systemdLogs, ...auditLogs];
        if (rawLogs.length === 0) continue;

        logger.debug({
          server: server.name,
          auth: authLogs.length, ufw: ufwLogs.length, docker: dockerEvents.length,
          process: suspiciousProcs.length, network: networkAnomaly.length, sudo: sudoLogs.length,
          dns: dnsLogs.length, syslog: syslogLogs.length, proxy: proxyLogs.length,
          package: packageLogs.length, systemd: systemdLogs.length, audit: auditLogs.length,
        }, 'Collector results');

        let normalized = EventNormalizer.normalizeBatch(rawLogs);
        if (normalized.length === 0) continue;

        const detected = EventDetector.detect(normalized);
        if (detected.length > 0) {
          normalized = [...normalized, ...detected];
        }

        normalized = await EventEnricher.enrich(normalized);

        const correlated = await EventCorrelator.correlate(normalized);
        await EventIngestor.persist(correlated);

        totalEvents += correlated.length;
        // Trigger playbooks for new incidents AND for events correlated to existing incidents with a source IP (ensures auto-block)
        newIncidentResults.push(...correlated.filter(r => r.isNewIncident || (r.incidentId && r.incidentCategory && r.event.sourceIp)));

        await ServerService.updateLastSeen(server.id);
      }

      if (totalEvents > 0) {
        logger.info({ events: totalEvents, newIncidents: newIncidentResults.length, servers: servers.length }, 'Event collection cycle complete');
      }

      if (newIncidentResults.length > 0) {
        await this.notifyNewIncidents(newIncidentResults.filter(r => r.isNewIncident).length);
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

  private static async triggerPlaybooks(results: CorrelationResult[]): Promise<void> {
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
        // Dedup: skip if same playbook+IP+server triggered in last 5min
        const dedupKey = `${playbook.name}:${result.event.sourceIp ?? ''}:${result.event.serverId}`;
        if (this.recentlyTriggered.has(dedupKey)) continue;

        const ctx: PlaybookContext = {
          serverId: result.event.serverId,
          serverName,
          incidentId: result.incidentId ?? undefined,
          sourceIp: result.event.sourceIp ?? undefined,
          triggeredBy: 'auto',
          variables: {},
        };

        if (playbook.requiresApproval) {
          requestPlaybookApproval(playbook.name, ctx);
          addWebPendingApproval(playbook.name, ctx);
          continue;
        }

        // Consult AI before auto-executing blocking playbooks (skip for clear-cut threats)
        const hasBlockAction = playbook.steps.some(s => s.action === 'block-ip');
        const alwaysBlock = ['port_scan', 'brute_force', 'ddos', 'crypto_mining', 'lateral_movement'].includes(result.incidentCategory ?? '');
        if (hasBlockAction && result.event.sourceIp && !alwaysBlock) {
          try {
            const recommendation = await AIBlockAdvisor.getRecommendation(ctx, {
              eventType: result.event.eventType,
              severity: result.event.severity,
              eventCount: result.event.metadata?.eventCount as number | undefined,
              sourceIp: result.event.sourceIp,
            });

            if (recommendation.confidence >= 70) {
              if (recommendation.action === 'monitor' || recommendation.action === 'ignore') {
                logger.info({
                  ip: result.event.sourceIp, playbook: playbook.name,
                  action: recommendation.action, confidence: recommendation.confidence,
                  reasoning: recommendation.reasoning,
                }, 'AI advisor: skipping block');
                continue;
              }
              if (recommendation.action === 'rate_limit') {
                ctx.variables = { ...ctx.variables, aiOverride: 'rate_limit' };
              }
            }
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

  private static async notifyNewIncidents(count: number): Promise<void> {
    try {
      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text: `🚨 <b>${count} novo(s) incidente(s) detectado(s)</b>\nUse /incidents para detalhes.`,
          parse_mode: 'HTML',
        }),
      });
    } catch {
      logger.warn('Failed to notify new incidents');
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
