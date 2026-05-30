import { db, dbTrue, dbDate } from '../database/connection.js';
import { blockedIps, blockPropagationQueue } from '../database/schema.js';
import { and, eq, lte } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { ServerService } from '../services/server.service.js';
import { SSHCollector } from '../collectors/ssh-collector.js';
import { isValidIp } from '../utils/sanitize.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { verifyBlock, type BlockMethod } from '../playbooks/actions/block-ip.js';

const DRAIN_INTERVAL_MS = 60_000; // every 1 min — rapid for first attempts; ladder spaces them out
const BATCH_SIZE = 25;

// Retry ladder: 1m, 5m, 15m, 1h, 6h. After the 5th failure we mark `gave_up`
// and Telegram-alert so a human can investigate (server unreachable, sshd
// down, fail2ban removed, etc.).
export const BACKOFF_MINUTES = [1, 5, 15, 60, 360];

/**
 * Returns the delay in ms before the next retry, given how many attempts
 * have already failed. `attempts=1` → 1 minute (just failed once); attempts
 * past the end of the ladder are clamped to the longest delay (6h).
 */
export function backoffDelayMs(attempts: number): number {
  const idx = Math.min(Math.max(attempts - 1, 0), BACKOFF_MINUTES.length - 1);
  return BACKOFF_MINUTES[idx] * 60_000;
}

export class BlockPropagationWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static draining = false;

  static start(): void {
    if (this.intervalId) return;
    this.intervalId = setInterval(() => {
      void this.drain();
    }, DRAIN_INTERVAL_MS);
    // Kick once immediately so a freshly-enqueued block doesn't wait a minute.
    void this.drain();
    logger.info('Block propagation worker started');
  }

  static async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      const now = new Date();
      const pending = await db
        .select()
        .from(blockPropagationQueue)
        .where(
          and(
            eq(blockPropagationQueue.status, 'pending'),
            lte(blockPropagationQueue.nextRetryAt, dbDate(now)),
          ),
        )
        .limit(BATCH_SIZE);

      if (pending.length === 0) return;

      logger.info({ count: pending.length }, 'Draining block propagation queue');
      for (const row of pending) {
        await this.processOne(row).catch((err) =>
          logger.error({ err, row: row.id }, 'BlockPropagationWorker.processOne failed'),
        );
      }
    } finally {
      this.draining = false;
    }
  }

  private static async processOne(row: typeof blockPropagationQueue.$inferSelect): Promise<void> {
    const { id, ip, targetServerId, incidentId, reason, attempts, maxAttempts } = row;

    if (!isValidIp(ip)) {
      await db
        .update(blockPropagationQueue)
        .set({ status: 'gave_up', lastError: 'Invalid IP', completedAt: dbDate(new Date()) })
        .where(eq(blockPropagationQueue.id, id));
      return;
    }

    const server = await ServerService.getEnabled().then((s) => s.find((sv) => sv.id === targetServerId));
    if (!server) {
      await db
        .update(blockPropagationQueue)
        .set({
          status: 'gave_up',
          lastError: `Server ${targetServerId} no longer enabled`,
          completedAt: dbDate(new Date()),
        })
        .where(eq(blockPropagationQueue.id, id));
      return;
    }

    // Idempotency check — another path (manual block, reconciliation) may have
    // already applied this block. If so, mark complete and move on.
    const already = await db
      .select({ id: blockedIps.id })
      .from(blockedIps)
      .where(
        and(
          eq(blockedIps.ip, ip),
          eq(blockedIps.serverId, targetServerId),
          eq(blockedIps.active, dbTrue),
        ),
      )
      .then((rows) => rows[0]);

    if (already) {
      await db
        .update(blockPropagationQueue)
        .set({ status: 'completed', completedAt: dbDate(new Date()), lastTriedAt: dbDate(new Date()) })
        .where(eq(blockPropagationQueue.id, id));
      return;
    }

    // Try fail2ban first, fall back to UFW. Permanent block (-1).
    const target = ServerService.toSSHTarget(server);
    let method: BlockMethod | null = null;
    let errMessage: string | null = null;

    try {
      const f2bCheck = await SSHCollector.run(target, 'which fail2ban-client', 5_000);
      if (f2bCheck.success && f2bCheck.stdout.trim()) {
        const f2b = await SSHCollector.run(
          target,
          `sudo fail2ban-client set guardian-jail banip --bantime -1 ${ip}`,
          10_000,
        );
        if (f2b.success) method = 'fail2ban';
        else errMessage = `fail2ban: ${(f2b.error || '').slice(0, 200)}`;
      }

      if (!method) {
        const ufw = await SSHCollector.run(
          target,
          `sudo ufw deny from ${ip} comment 'guardian-prop-${Date.now()}'`,
          10_000,
        );
        if (ufw.success) method = 'ufw';
        else errMessage = `${errMessage ? errMessage + ' | ' : ''}ufw: ${(ufw.error || '').slice(0, 200)}`;
      }
    } catch (err: any) {
      errMessage = `ssh: ${(err?.message || String(err)).slice(0, 200)}`;
    }

    const nextAttempt = attempts + 1;

    if (!method) {
      await this.recordFailure(id, ip, targetServerId, server.name, nextAttempt, maxAttempts, errMessage ?? 'unknown');
      return;
    }

    const verifyResult = await verifyBlock(target, ip, method).catch(() => ({ verified: false, method }));
    const verified = verifyResult.verified;

    try {
      await db.insert(blockedIps).values({
        ip,
        serverId: targetServerId,
        reason: reason ?? 'Propagated',
        playbookExecutionId: null,
        incidentId: incidentId ?? null,
        expiresAt: null,
        verified,
        method,
        lastVerifiedAt: verified ? dbDate(new Date()) : null,
      });
    } catch (err: any) {
      const isDup = err?.code === '23505' || err?.message?.includes('UNIQUE constraint');
      if (!isDup) {
        await this.recordFailure(
          id, ip, targetServerId, server.name, nextAttempt, maxAttempts,
          `db: ${(err?.message || String(err)).slice(0, 200)}`,
        );
        return;
      }
    }

    await db
      .update(blockPropagationQueue)
      .set({
        status: 'completed',
        attempts: nextAttempt,
        lastTriedAt: dbDate(new Date()),
        completedAt: dbDate(new Date()),
      })
      .where(eq(blockPropagationQueue.id, id));

    logger.info({ ip, server: server.name, method, verified, attempts: nextAttempt }, 'Block propagated successfully');
  }

  private static async recordFailure(
    queueId: number,
    ip: string,
    serverId: number,
    serverName: string,
    attempts: number,
    maxAttempts: number,
    errMessage: string,
  ): Promise<void> {
    if (attempts >= maxAttempts) {
      await db
        .update(blockPropagationQueue)
        .set({
          status: 'gave_up',
          attempts,
          lastTriedAt: dbDate(new Date()),
          completedAt: dbDate(new Date()),
          lastError: errMessage.slice(0, 500),
        })
        .where(eq(blockPropagationQueue.id, queueId));

      logger.error({ ip, server: serverName, attempts, errMessage }, 'Block propagation: gave up');

      await NotifierManager.notify({
        title: 'Block propagation failed',
        body:
          `Could not propagate block of ${ip} to ${serverName} after ${attempts} attempts.\n` +
          `Last error: ${errMessage}\n\n` +
          `This server is currently *unprotected* against this IP. Investigate SSH access, fail2ban, and UFW.`,
        severity: 'high',
        metadata: { type: 'block_propagation_gave_up', ip, serverId: String(serverId), serverName },
      }).catch((err) => logger.error({ err }, 'Failed to send gave_up notification'));
      return;
    }

    const backoffMs = backoffDelayMs(attempts);
    const nextRetry = new Date(Date.now() + backoffMs);

    await db
      .update(blockPropagationQueue)
      .set({
        attempts,
        lastTriedAt: dbDate(new Date()),
        nextRetryAt: dbDate(nextRetry),
        lastError: errMessage.slice(0, 500),
      })
      .where(eq(blockPropagationQueue.id, queueId));

    logger.warn(
      { ip, server: serverName, attempts, nextRetry: nextRetry.toISOString(), errMessage },
      'Block propagation failed — will retry',
    );
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    // Wait briefly for an in-flight drain to finish so we don't tear down mid-SSH.
    const start = Date.now();
    while (this.draining && Date.now() - start < 5_000) {
      await new Promise((r) => setTimeout(r, 100));
    }
    logger.info('Block propagation worker stopped');
  }
}
