import { ServerService } from '../services/server.service.js';
import { discoverRemoteServer } from '../discovery/remote.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';
import type { DiscoveryResult } from '../discovery/types.js';

export class DiscoveryWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static running = false;
  private static readonly INTERVAL_MS = 24 * 60 * 60 * 1000;

  static start(): void {
    setTimeout(() => this.runDiscovery(), 5 * 60_000);
    this.intervalId = setInterval(() => this.runDiscovery(), this.INTERVAL_MS);
    logger.info('DiscoveryWorker started (24h cycle)');
  }

  static stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('DiscoveryWorker stopped');
  }

  private static async runDiscovery(): Promise<void> {
    if (this.running) return;
    this.running = true;

    try {
      const servers = await ServerService.getEnabled();
      if (servers.length === 0) return;

      logger.info({ count: servers.length }, 'Re-discovery cycle starting');

      for (const server of servers) {
        try {
          const target = ServerService.toSSHTarget(server);
          const result = await discoverRemoteServer(target);

          if (!result) {
            logger.debug({ server: server.name }, 'Re-discovery: server unreachable, skipping');
            continue;
          }

          const changes = detectChanges(server.name, result.analysis);
          if (changes.length > 0) {
            await notifyChanges(server.name, changes);
          }
        } catch (err) {
          logger.warn({ err, server: server.name }, 'Re-discovery: error scanning server');
        }
      }

      logger.info({ count: servers.length }, 'Re-discovery cycle complete');
    } catch (err) {
      logger.error({ err }, 'Re-discovery cycle failed');
    } finally {
      this.running = false;
    }
  }
}

const lastKnownState = new Map<string, { services: string[]; ports: number[]; architecture: string }>();

function detectChanges(serverName: string, analysis: DiscoveryResult): string[] {
  const previous = lastKnownState.get(serverName);
  const current = {
    services: analysis.monitoringProfile.services,
    ports: analysis.monitoringProfile.criticalPorts,
    architecture: analysis.architecture,
  };

  lastKnownState.set(serverName, current);

  if (!previous) return [];

  const changes: string[] = [];

  const newServices = current.services.filter(s => !previous.services.includes(s));
  const removedServices = previous.services.filter(s => !current.services.includes(s));
  const newPorts = current.ports.filter(p => !previous.ports.includes(p));
  const closedPorts = previous.ports.filter(p => !current.ports.includes(p));

  if (newServices.length > 0) changes.push(`New services: ${newServices.join(', ')}`);
  if (removedServices.length > 0) changes.push(`Stopped services: ${removedServices.join(', ')}`);
  if (newPorts.length > 0) changes.push(`New ports: ${newPorts.join(', ')}`);
  if (closedPorts.length > 0) changes.push(`Closed ports: ${closedPorts.join(', ')}`);
  if (current.architecture !== previous.architecture) {
    changes.push(`Architecture changed: ${previous.architecture} → ${current.architecture}`);
  }

  return changes;
}

async function notifyChanges(serverName: string, changes: string[]): Promise<void> {
  const text = [
    `🔄 <b>Re-Discovery: changes detected</b>`,
    `🖥️ Server: <b>${serverName}</b>`,
    '',
    ...changes.map(c => `• ${c}`),
    '',
    '⚠️ Review recommended. No auto-changes applied.',
  ].join('\n');

  await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: config.telegram.chatId, text, parse_mode: 'HTML' }),
  }).catch(err => logger.warn({ err }, 'Re-discovery notification failed'));
}
