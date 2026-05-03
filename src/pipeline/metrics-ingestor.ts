import { db, dbDate } from '../database/connection.js';
import { serverMetrics } from '../database/schema.js';
import type { RawHealthMetrics } from '../collectors/health-collector.js';
import type { RawSystemMetrics } from '../collectors/system-collector.js';
import type { RawPerformanceMetrics } from '../collectors/performance-collector.js';
import { logger } from '../utils/logger.js';

export interface MetricsBundle {
  health: RawHealthMetrics | null;
  system: RawSystemMetrics | null;
  performance: RawPerformanceMetrics | null;
}

export class MetricsIngestor {
  static async persist(bundles: MetricsBundle[]): Promise<number> {
    const values = bundles
      .filter(b => b.health !== null)
      .map(b => {
        const h = b.health!;
        const s = b.system;
        const p = b.performance;

        return {
          serverId: h.serverId,
          collectedAt: dbDate(h.collectedAt),
          load1: h.load1,
          load5: h.load5,
          load15: h.load15,
          cpuCount: h.cpuCount,
          memTotalBytes: h.memTotalBytes,
          memUsedBytes: h.memUsedBytes,
          memAvailableBytes: h.memAvailableBytes,
          swapTotalBytes: h.swapTotalBytes,
          swapUsedBytes: h.swapUsedBytes,
          disks: h.disks,
          uptimeSeconds: h.uptimeSeconds,
          diskIo: p?.diskIo ?? null,
          networkIo: p?.networkIo ?? null,
          failedUnits: s?.failedUnits ?? [],
          kernelErrors: s?.kernelErrors.length ?? 0,
          journalErrors: s?.journalErrors.length ?? 0,
        };
      });

    if (values.length === 0) return 0;

    const BATCH_SIZE = 50;
    let total = 0;

    for (let i = 0; i < values.length; i += BATCH_SIZE) {
      const batch = values.slice(i, i + BATCH_SIZE);
      await db.insert(serverMetrics).values(batch);
      total += batch.length;
    }

    logger.debug({ count: total }, 'Metrics persisted to server_metrics');
    return total;
  }
}
