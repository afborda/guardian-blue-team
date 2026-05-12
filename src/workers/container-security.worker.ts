import { ServerService } from '../services/server.service.js';
import { ContainerRuntimeCollector } from '../collectors/container-runtime-collector.js';
import { EventNormalizer } from '../pipeline/normalizer.js';
import { EventDetector } from '../pipeline/detector.js';
import { EventEnricher } from '../pipeline/enricher.js';
import { EventCorrelator } from '../pipeline/correlator.js';
import { EventIngestor } from '../pipeline/ingestor.js';
import { db, dbNow } from '../database/connection.js';
import { containerSnapshots } from '../database/schema.js';
import { eq, and } from 'drizzle-orm';
import { CONSTANTS } from '../config/constants.js';
import { logger } from '../utils/logger.js';

export class ContainerSecurityWorker {
  private static networkIntervalId: NodeJS.Timeout | null = null;
  private static filesystemIntervalId: NodeJS.Timeout | null = null;
  private static configIntervalId: NodeJS.Timeout | null = null;
  private static running = { network: false, filesystem: false, config: false };

  static start(): void {
    // Network scan: every 5 min
    setTimeout(() => this.collectNetwork().catch(e => logger.error({ err: e }, 'Container network collector error')), 30_000);
    this.networkIntervalId = setInterval(
      () => this.collectNetwork().catch(e => logger.error({ err: e }, 'Container network collector error')),
      CONSTANTS.container.networkIntervalMs
    );

    // Filesystem diff: every 30 min
    setTimeout(() => this.collectFilesystem().catch(e => logger.error({ err: e }, 'Container filesystem collector error')), 60_000);
    this.filesystemIntervalId = setInterval(
      () => this.collectFilesystem().catch(e => logger.error({ err: e }, 'Container filesystem collector error')),
      CONSTANTS.container.filesystemIntervalMs
    );

    // Config audit: every 1h
    setTimeout(() => this.collectConfig().catch(e => logger.error({ err: e }, 'Container config collector error')), 90_000);
    this.configIntervalId = setInterval(
      () => this.collectConfig().catch(e => logger.error({ err: e }, 'Container config collector error')),
      CONSTANTS.container.configAuditIntervalMs
    );

    logger.info('Container security worker started (network:5m, fs:30m, config:1h)');
  }

  static stop(): void {
    if (this.networkIntervalId) clearInterval(this.networkIntervalId);
    if (this.filesystemIntervalId) clearInterval(this.filesystemIntervalId);
    if (this.configIntervalId) clearInterval(this.configIntervalId);
  }

  private static async collectNetwork(): Promise<void> {
    if (this.running.network) return;
    this.running.network = true;

    try {
      const servers = await ServerService.getEnabled();
      for (const server of servers) {
        const target = ServerService.toSSHTarget(server);
        const rawLogs = await ContainerRuntimeCollector.collectContainerNetwork(target);
        if (rawLogs.length === 0) continue;

        await this.processThroughPipeline(rawLogs);

        // Update snapshots with network data
        await this.updateNetworkSnapshots(server.id, rawLogs);
      }
    } finally {
      this.running.network = false;
    }
  }

  private static async collectFilesystem(): Promise<void> {
    if (this.running.filesystem) return;
    this.running.filesystem = true;

    try {
      const servers = await ServerService.getEnabled();
      for (const server of servers) {
        const target = ServerService.toSSHTarget(server);
        const rawLogs = await ContainerRuntimeCollector.collectContainerFilesystem(target);
        if (rawLogs.length === 0) continue;

        await this.processThroughPipeline(rawLogs);
      }
    } finally {
      this.running.filesystem = false;
    }
  }

  private static async collectConfig(): Promise<void> {
    if (this.running.config) return;
    this.running.config = true;

    try {
      const servers = await ServerService.getEnabled();
      for (const server of servers) {
        const target = ServerService.toSSHTarget(server);
        const rawLogs = await ContainerRuntimeCollector.auditContainerConfig(target);
        if (rawLogs.length === 0) continue;

        await this.processThroughPipeline(rawLogs);

        // Update snapshots with config data
        await this.updateConfigSnapshots(server.id, rawLogs);
      }
    } finally {
      this.running.config = false;
    }
  }

  /**
   * Collects container processes and persists snapshot data.
   * Called from EventCollectorWorker every 2 min (lightweight).
   */
  static async collectAndSnapshotProcesses(serverId: number): Promise<void> {
    const servers = await ServerService.getEnabled();
    const server = servers.find(s => s.id === serverId);
    if (!server) return;

    const target = ServerService.toSSHTarget(server);
    const rawLogs = await ContainerRuntimeCollector.collectContainerProcesses(target);
    if (rawLogs.length === 0) return;

    // Group processes by container
    const containerProcesses = new Map<string, Array<{ pid: number; user: string; cpu: number; mem: number; command: string; args: string }>>();

    for (const entry of rawLogs) {
      const parsed = ContainerRuntimeCollector.parseProcessLine(entry.line);
      if (!parsed) continue;

      const procs = containerProcesses.get(parsed.container) ?? [];
      procs.push({ pid: parsed.pid, user: parsed.user, cpu: parsed.cpu, mem: parsed.mem, command: parsed.command, args: parsed.args });
      containerProcesses.set(parsed.container, procs);
    }

    // Upsert snapshots
    for (const [containerName, processes] of containerProcesses) {
      const existing = await db.select({ id: containerSnapshots.id })
        .from(containerSnapshots)
        .where(and(
          eq(containerSnapshots.serverId, serverId),
          eq(containerSnapshots.containerName, containerName)
        ))
        .then(rows => rows[0]);

      if (existing) {
        await db.update(containerSnapshots)
          .set({ processes, collectedAt: dbNow(), status: 'running' })
          .where(eq(containerSnapshots.id, existing.id));
      } else {
        await db.insert(containerSnapshots).values({
          serverId,
          containerName,
          processes,
          status: 'running',
        });
      }
    }
  }

  private static async updateNetworkSnapshots(serverId: number, rawLogs: { line: string }[]): Promise<void> {
    const containerNetwork = new Map<string, Array<{ remoteIp: string; remotePort: number; localPort: number; state: string }>>();

    for (const entry of rawLogs) {
      const parsed = ContainerRuntimeCollector.parseNetworkLine(entry.line);
      if (!parsed) continue;

      const conns = containerNetwork.get(parsed.container) ?? [];
      conns.push({ remoteIp: parsed.remoteIp, remotePort: parsed.remotePort, localPort: parsed.localPort, state: parsed.state });
      containerNetwork.set(parsed.container, conns);
    }

    for (const [containerName, network] of containerNetwork) {
      const existing = await db.select({ id: containerSnapshots.id })
        .from(containerSnapshots)
        .where(and(
          eq(containerSnapshots.serverId, serverId),
          eq(containerSnapshots.containerName, containerName)
        ))
        .then(rows => rows[0]);

      if (existing) {
        await db.update(containerSnapshots)
          .set({ network, collectedAt: dbNow() })
          .where(eq(containerSnapshots.id, existing.id));
      } else {
        await db.insert(containerSnapshots).values({ serverId, containerName, network });
      }
    }
  }

  private static async updateConfigSnapshots(serverId: number, rawLogs: { line: string }[]): Promise<void> {
    for (const entry of rawLogs) {
      const parsed = ContainerRuntimeCollector.parseConfigLine(entry.line);
      if (!parsed) continue;

      const securityConfig = {
        readOnly: parsed.readOnly,
        noNewPrivs: parsed.noNewPrivs,
        capDrop: parsed.capDrop,
        memoryLimit: parsed.memoryLimit,
        cpuQuota: parsed.cpuQuota,
      };

      const existing = await db.select({ id: containerSnapshots.id })
        .from(containerSnapshots)
        .where(and(
          eq(containerSnapshots.serverId, serverId),
          eq(containerSnapshots.containerName, parsed.container)
        ))
        .then(rows => rows[0]);

      if (existing) {
        await db.update(containerSnapshots)
          .set({ securityConfig, imageName: parsed.image, collectedAt: dbNow() })
          .where(eq(containerSnapshots.id, existing.id));
      } else {
        await db.insert(containerSnapshots).values({
          serverId,
          containerName: parsed.container,
          imageName: parsed.image,
          securityConfig,
        });
      }
    }
  }

  private static async processThroughPipeline(rawLogs: { serverId: number; serverName: string; source: string; timestamp: Date; line: string }[]): Promise<void> {
    let normalized = EventNormalizer.normalizeBatch(rawLogs);
    if (normalized.length === 0) return;

    const detected = EventDetector.detect(normalized);
    if (detected.length > 0) {
      normalized = [...normalized, ...detected];
      logger.info({ detectedCount: detected.length }, 'Container security detection triggered');
    }

    normalized = await EventEnricher.enrich(normalized);
    const correlated = await EventCorrelator.correlate(normalized);
    await EventIngestor.persist(correlated);
  }
}
