import { db, dbTrue } from '../database/connection.js';
import { blockedIps } from '../database/schema.js';
import { and, eq, isNotNull } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';

export class BlockCleanupWorker {
  private static intervalId: NodeJS.Timeout | null = null;

  static start(): void {
    if (this.intervalId) return;

    this.intervalId = setInterval(() => {
      this.cleanup().catch(err => logger.error({ err }, 'Block cleanup error'));
    }, CONSTANTS.blocking.cleanupIntervalMs);

    logger.info('Block cleanup worker started');
  }

  static async cleanup(): Promise<void> {
    // Blocks are permanent — no auto-unblock, no expiration notifications.
    // This worker now only clears stale expiresAt from legacy entries.
    const legacyWithExpiry = await db.select({ id: blockedIps.id }).from(blockedIps)
      .where(and(
        eq(blockedIps.active, dbTrue),
        isNotNull(blockedIps.expiresAt),
      ));

    if (legacyWithExpiry.length > 0) {
      for (const row of legacyWithExpiry) {
        await db.update(blockedIps)
          .set({ expiresAt: null })
          .where(eq(blockedIps.id, row.id));
      }
      logger.info({ count: legacyWithExpiry.length }, 'Cleared legacy expiresAt from active blocks (all blocks are now permanent)');
    }
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Block cleanup worker stopped');
  }
}
