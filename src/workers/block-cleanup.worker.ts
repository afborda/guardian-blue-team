import { db, dbTrue, dbFalse, dbNow } from '../database/connection.js';
import { blockedIps } from '../database/schema.js';
import { and, eq, lte } from 'drizzle-orm';
import { SSHCollector } from '../collectors/ssh-collector.js';
import { ServerService } from '../services/server.service.js';
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
    const expired = await db.select().from(blockedIps)
      .where(and(
        eq(blockedIps.active, dbTrue),
        lte(blockedIps.expiresAt, dbNow()),
      ));

    if (expired.length === 0) return;

    const servers = await ServerService.getEnabled();
    let unblocked = 0;

    for (const block of expired) {
      const server = servers.find(s => s.id === block.serverId);
      if (!server) {
        await db.update(blockedIps)
          .set({ active: dbFalse, unblockedAt: dbNow() })
          .where(eq(blockedIps.id, block.id));
        continue;
      }

      const target = ServerService.toSSHTarget(server);
      const result = await SSHCollector.run(target, `sudo ufw delete deny from ${block.ip}`, 10_000);

      if (result.success) {
        await db.update(blockedIps)
          .set({ active: dbFalse, unblockedAt: dbNow() })
          .where(eq(blockedIps.id, block.id));
        unblocked++;
        logger.info({ ip: block.ip, server: server.name, blockedAt: block.blockedAt }, 'IP auto-unblocked (TTL expired)');
      } else {
        logger.warn({ ip: block.ip, server: server.name }, 'Failed to unblock IP via UFW');
      }
    }

    if (unblocked > 0) {
      logger.info({ unblocked, total: expired.length }, 'Block cleanup cycle complete');
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
