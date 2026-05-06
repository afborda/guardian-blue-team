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
import { requestPlaybookApproval } from '../telegram/callbacks.js';
import { requestLoginVerification } from '../telegram/login-verification.js';
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
          NetworkCollector.detectSuspiciousConnections(target),
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
        newIncidentResults.push(...correlated.filter(r => r.isNewIncident));

        await ServerService.updateLastSeen(server.id);
      }

      if (totalEvents > 0) {
        logger.info({ events: totalEvents, newIncidents: newIncidentResults.length, servers: servers.length }, 'Event collection cycle complete');
      }

      if (newIncidentResults.length > 0) {
        await this.notifyNewIncidents(newIncidentResults.length);
        await this.triggerPlaybooks(newIncidentResults);
      }
    } finally {
      this.running = false;
    }
  }

  private static async triggerPlaybooks(results: CorrelationResult[]): Promise<void> {
    const serverCache = new Map<number, string>();

    for (const result of results) {
      const matchingPlaybooks = PlaybookRegistry.getByTrigger(result.event.eventType);

      let serverName = serverCache.get(result.event.serverId);
      if (!serverName) {
        const server = await ServerService.getById(result.event.serverId);
        serverName = server?.name ?? `server-${result.event.serverId}`;
        serverCache.set(result.event.serverId, serverName);
      }

      for (const playbook of matchingPlaybooks) {
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
          continue;
        }

        try {
          await Promise.race([
            PlaybookEngine.execute(playbook, ctx),
            new Promise((_, reject) => setTimeout(() => reject(new Error('Playbook timeout')), CONSTANTS.telegram.playbookTimeoutMs)),
          ]);
        } catch (err) {
          logger.error({ err, playbook: playbook.name }, 'Auto-triggered playbook failed');
        }

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
