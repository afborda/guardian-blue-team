import { db, dbDate } from '../database/connection.js';
import { serverMetrics } from '../database/schema.js';
import { lte } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export class MetricsRetentionWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 24 * 60 * 60 * 1000;
  private static readonly RETENTION_DAYS = 30;

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.cleanup().catch(err => logger.error({ err }, 'Metrics retention cleanup error'));
    }, 60 * 60 * 1000);

    this.intervalId = setInterval(() => {
      this.cleanup().catch(err => logger.error({ err }, 'Metrics retention cleanup error'));
    }, this.INTERVAL_MS);

    logger.info(`Metrics retention worker started (deletes >=${this.RETENTION_DAYS}d)`);
  }

  static async cleanup(): Promise<void> {
    const cutoff = new Date(Date.now() - this.RETENTION_DAYS * 24 * 60 * 60 * 1000);

    try {
      await db.delete(serverMetrics).where(
        lte(serverMetrics.collectedAt, dbDate(cutoff))
      );
      logger.info({ cutoffDate: cutoff.toISOString() }, 'Old metrics purged');
    } catch (err) {
      logger.error({ err }, 'Metrics retention cleanup failed');
    }
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Metrics retention worker stopped');
  }
}
