import { ServerService } from '../services/server.service.js';
import { discoverRemoteServer } from '../discovery/remote.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';
import { db, dbDate } from '../database/connection.js';
import { discoveryBaselines } from '../database/schema.js';
import { eq, sql } from 'drizzle-orm';
import type { DiscoveryResult } from '../discovery/types.js';

interface Baseline {
  services: string[];
  ports: number[];
  architecture: string;
  knownContainers: string[];
}

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

          const previous = await loadBaseline(server.name);
          const current: Baseline = {
            services: result.analysis.monitoringProfile.services,
            ports: result.analysis.monitoringProfile.criticalPorts,
            architecture: result.analysis.architecture,
            knownContainers: previous?.knownContainers ?? [],
          };

          const changes = previous ? diffBaseline(previous, current) : [];
          if (changes.length > 0) {
            await notifyChanges(server.name, changes);
          }

          const enrolledContainers = await proposeAutoEnrollment(server.name, result.analysis, current.knownContainers);
          current.knownContainers = enrolledContainers;

          await saveBaseline(server.name, current);
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

async function loadBaseline(serverName: string): Promise<Baseline | null> {
  try {
    const row = await db
      .select()
      .from(discoveryBaselines)
      .where(eq(discoveryBaselines.serverName, serverName))
      .then((rows) => rows[0]);
    if (!row) return null;
    return {
      services: (row.services as string[]) ?? [],
      ports: (row.ports as number[]) ?? [],
      architecture: row.architecture ?? '',
      knownContainers: (row.knownContainers as string[]) ?? [],
    };
  } catch (err) {
    logger.warn({ err, serverName }, 'discovery baseline load failed');
    return null;
  }
}

async function saveBaseline(serverName: string, baseline: Baseline): Promise<void> {
  try {
    await db
      .insert(discoveryBaselines)
      .values({
        serverName,
        services: baseline.services,
        ports: baseline.ports,
        architecture: baseline.architecture,
        knownContainers: baseline.knownContainers,
        capturedAt: dbDate(new Date()),
      })
      .onConflictDoUpdate({
        target: discoveryBaselines.serverName,
        set: {
          services: baseline.services,
          ports: baseline.ports,
          architecture: baseline.architecture,
          knownContainers: baseline.knownContainers,
          capturedAt: sql`NOW()`,
        },
      });
  } catch (err) {
    logger.warn({ err, serverName }, 'discovery baseline save failed');
  }
}

function diffBaseline(previous: Baseline, current: Baseline): string[] {
  const changes: string[] = [];

  const newServices = current.services.filter((s) => !previous.services.includes(s));
  const removedServices = previous.services.filter((s) => !current.services.includes(s));
  const newPorts = current.ports.filter((p) => !previous.ports.includes(p));
  const closedPorts = previous.ports.filter((p) => !current.ports.includes(p));

  if (newServices.length > 0) changes.push(`New services: ${newServices.join(', ')}`);
  if (removedServices.length > 0) changes.push(`Stopped services: ${removedServices.join(', ')}`);
  if (newPorts.length > 0) changes.push(`New ports: ${newPorts.join(', ')}`);
  if (closedPorts.length > 0) changes.push(`Closed ports: ${closedPorts.join(', ')}`);
  if (current.architecture !== previous.architecture) {
    changes.push(`Architecture changed: ${previous.architecture} → ${current.architecture}`);
  }

  return changes;
}

async function proposeAutoEnrollment(
  serverName: string,
  analysis: DiscoveryResult,
  alreadyKnown: string[],
): Promise<string[]> {
  const newServices = analysis.monitoringProfile.services;
  const known = new Set(alreadyKnown);
  const brandNew = newServices.filter((s) => !known.has(s));

  if (brandNew.length === 0) return Array.from(known);

  for (const svc of brandNew) known.add(svc);

  // First-ever discovery for this server: silently absorb. Otherwise, alert.
  if (alreadyKnown.length === 0) return Array.from(known);

  const text = [
    `🆕 <b>Auto-Discovery: new services found</b>`,
    `🖥️ Server: <b>${serverName}</b>`,
    '',
    `New services detected:`,
    ...brandNew.map((s) => `  • ${s}`),
    '',
    `These are now automatically monitored.`,
    `Log paths: ${analysis.monitoringProfile.logPaths.join(', ') || 'default'}`,
    `Critical ports: ${analysis.monitoringProfile.criticalPorts.join(', ') || 'none'}`,
  ].join('\n');

  await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: config.telegram.chatId, text, parse_mode: 'HTML' }),
  }).catch((err) => logger.warn({ err }, 'Auto-enrollment notification failed'));

  logger.info({ serverName, newServices: brandNew }, 'Auto-enrolled new services in monitoring');
  return Array.from(known);
}

async function notifyChanges(serverName: string, changes: string[]): Promise<void> {
  const text = [
    `🔄 <b>Re-Discovery: changes detected</b>`,
    `🖥️ Server: <b>${serverName}</b>`,
    '',
    ...changes.map((c) => `• ${c}`),
    '',
    '⚠️ Review recommended. No auto-changes applied.',
  ].join('\n');

  await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: config.telegram.chatId, text, parse_mode: 'HTML' }),
  }).catch((err) => logger.warn({ err }, 'Re-discovery notification failed'));
}
