import { ServerService } from '../services/server.service.js';
import { discoverRemoteServer } from '../discovery/remote.js';
import { telegram } from '../telegram/messaging/sender.js';
import { logger } from '../utils/logger.js';
import { db, dbDate } from '../database/connection.js';
import { discoveryBaselines } from '../database/schema.js';
import { eq, sql } from 'drizzle-orm';
import type { DiscoveryResult } from '../discovery/types.js';
import { describeDiscoveryChanges, fingerprintFromSnapshot, isLabelMigration } from '../discovery/baseline-diff.js';

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

          // Persist os_family (Tier 0 PR1) if Discovery captured it.
          // os.id from /etc/os-release is already normalized (ubuntu, debian, rhel, ...).
          // Skip the UPDATE when value is unchanged to keep the soc_servers
          // row hot path quiet across the 24h cycle.
          const probedOsId = result.snapshot.probes.system.data.os.id?.trim();
          if (probedOsId && probedOsId !== server.osFamily) {
            try {
              await ServerService.setOsFamily(server.id, probedOsId);
              logger.info({ server: server.name, osFamily: probedOsId }, 'Discovery: os_family updated');
            } catch (err) {
              logger.warn({ err, server: server.name }, 'Discovery: failed to persist os_family');
            }
          }

          const previous = await loadBaseline(server.name);
          const fingerprint = fingerprintFromSnapshot(result.snapshot, result.analysis.architecture);
          const current: Baseline = {
            services: fingerprint.services,
            ports: fingerprint.ports,
            architecture: fingerprint.architecture,
            knownContainers: previous?.knownContainers ?? [],
          };

          const migrating = previous ? isLabelMigration(previous.services, current.services) : false;
          const changes = previous && !migrating
            ? describeDiscoveryChanges(previous, current)
            : [];
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
    `🆕 <b>Novos serviços em ${serverName}</b>`,
    '',
    'O Guardian passou a monitorar:',
    ...brandNew.map((s) => `  • ${s}`),
    '',
    `Caminhos de log: ${analysis.monitoringProfile.logPaths.join(', ') || 'padrão'}`,
    `Portas críticas: ${analysis.monitoringProfile.criticalPorts.join(', ') || 'nenhuma'}`,
  ].join('\n');

  await telegram.sendText(text).catch((err) => logger.warn({ err }, 'Auto-enrollment notification failed'));

  logger.info({ serverName, newServices: brandNew }, 'Auto-enrolled new services in monitoring');
  return Array.from(known);
}

async function notifyChanges(serverName: string, changes: string[]): Promise<void> {
  const text = [
    `🔄 <b>Mudou algo visível em ${serverName}</b>`,
    '',
    ...changes.map((c) => `• ${c}`),
    '',
    'Isso compara portas abertas na internet e containers em execução. Não é um ataque e nada foi alterado sozinho.',
    'Se você não fez deploy nem fechou uma porta, vale olhar. Se fez, pode ignorar.',
  ].join('\n');

  await telegram.sendText(text).catch((err) => logger.warn({ err }, 'Re-discovery notification failed'));
}
