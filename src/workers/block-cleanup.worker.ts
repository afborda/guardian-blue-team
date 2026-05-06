import { db, dbTrue, dbFalse, dbNow } from '../database/connection.js';
import { blockedIps } from '../database/schema.js';
import { and, eq, lte, gte } from 'drizzle-orm';
import { SSHCollector } from '../collectors/ssh-collector.js';
import { ServerService } from '../services/server.service.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';
import { isValidIp } from '../utils/sanitize.js';

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
    await this.notifyExpiringSoon();
    await this.removeExpired();
  }

  private static async notifyExpiringSoon(): Promise<void> {
    const oneHourFromNow = new Date(Date.now() + 60 * 60 * 1000);
    const now = new Date();

    const expiringSoon = await db.select().from(blockedIps)
      .where(and(
        eq(blockedIps.active, dbTrue),
        gte(blockedIps.expiresAt, now),
        lte(blockedIps.expiresAt, oneHourFromNow),
      ));

    if (expiringSoon.length === 0) return;

    const servers = await ServerService.getEnabled();
    const lines = expiringSoon.map(b => {
      const server = servers.find(s => s.id === b.serverId);
      const mins = Math.round((b.expiresAt.getTime() - Date.now()) / 60_000);
      return `  • ${b.ip} (${server?.name ?? 'unknown'}) — expira em ${mins}min`;
    });

    await NotifierManager.notify({
      title: 'Blocks Expirando',
      body: `${expiringSoon.length} IP(s) serão desbloqueados em breve:\n${lines.join('\n')}`,
      severity: 'low',
      metadata: { type: 'block_expiring', count: String(expiringSoon.length) },
    });
  }

  private static async removeExpired(): Promise<void> {
    const expired = await db.select().from(blockedIps)
      .where(and(
        eq(blockedIps.active, dbTrue),
        lte(blockedIps.expiresAt, dbNow()),
      ));

    if (expired.length === 0) return;

    const servers = await ServerService.getEnabled();
    let unblocked = 0;
    const unblockedIps: string[] = [];

    for (const block of expired) {
      const server = servers.find(s => s.id === block.serverId);
      if (!server) {
        await db.update(blockedIps)
          .set({ active: dbFalse, unblockedAt: dbNow() })
          .where(eq(blockedIps.id, block.id));
        continue;
      }

      const target = ServerService.toSSHTarget(server);

      if (!isValidIp(block.ip)) {
        logger.warn({ ip: block.ip, blockId: block.id }, 'Skipping invalid IP in block cleanup');
        continue;
      }

      const result = await SSHCollector.run(target, `sudo ufw delete deny from ${block.ip}`, 10_000);

      if (result.success) {
        await db.update(blockedIps)
          .set({ active: dbFalse, unblockedAt: dbNow() })
          .where(eq(blockedIps.id, block.id));
        unblocked++;
        unblockedIps.push(`${block.ip} (${server.name})`);
        logger.info({ ip: block.ip, server: server.name, blockedAt: block.blockedAt }, 'IP auto-unblocked (TTL expired)');
      } else {
        logger.warn({ ip: block.ip, server: server.name }, 'Failed to unblock IP via UFW');
      }
    }

    if (unblocked > 0) {
      await NotifierManager.notify({
        title: 'Blocks Removidos',
        body: `${unblocked} IP(s) desbloqueados (TTL expirado):\n${unblockedIps.map(ip => `  • ${ip}`).join('\n')}`,
        severity: 'low',
        metadata: { type: 'block_removed', count: String(unblocked) },
      });
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
