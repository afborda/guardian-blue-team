import { db, dbTrue, dbDate } from '../database/connection.js';
import { blockedIps, blockPropagationQueue } from '../database/schema.js';
import { and, eq } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { ServerService } from '../services/server.service.js';
import { isValidIp } from '../utils/sanitize.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { verifyBlock } from '../playbooks/actions/block-ip.js';

const RECONCILE_INTERVAL_MS = 60 * 60_000;     // 1 hour
const REVERIFY_INTERVAL_MS = 6 * 60 * 60_000;  // 6 hours
const REVERIFY_FAILURE_THRESHOLD = 2;          // 2 strikes → reapply + alert

/**
 * Two periodic sweeps over the global block state:
 *
 * 1. Reconciliation (hourly): every IP that's blocked anywhere should be
 *    blocked everywhere. Compares `blocked_ips` against `soc_servers` and
 *    enqueues any missing (ip, server) pairs through the propagation queue.
 *
 * 2. Re-verify (every 6h): for each active block row, runs `verifyBlock`
 *    against the firewall on the target server. Two consecutive verify
 *    failures means the block was lost (someone flushed iptables, fail2ban
 *    restarted without persistence, etc.) — re-enqueue + Telegram alert.
 */
export class BlockReconcileWorker {
  private static reconcileTimer: NodeJS.Timeout | null = null;
  private static reverifyTimer: NodeJS.Timeout | null = null;
  private static running = { reconcile: false, reverify: false };

  static start(): void {
    if (this.reconcileTimer || this.reverifyTimer) return;
    this.reconcileTimer = setInterval(() => void this.reconcile(), RECONCILE_INTERVAL_MS);
    this.reverifyTimer = setInterval(() => void this.reverify(), REVERIFY_INTERVAL_MS);
    logger.info('Block reconcile worker started');
  }

  /**
   * For every distinct IP in active blocks, ensure each enabled server has its
   * own active row. Missing rows are enqueued (the propagation worker handles
   * the actual SSH).
   */
  static async reconcile(): Promise<void> {
    if (this.running.reconcile) return;
    this.running.reconcile = true;
    try {
      const enabled = await ServerService.getEnabled();
      if (enabled.length < 2) return; // Nothing to reconcile against

      const distinctIps = await db
        .selectDistinct({ ip: blockedIps.ip })
        .from(blockedIps)
        .where(eq(blockedIps.active, dbTrue));

      let enqueued = 0;
      for (const { ip } of distinctIps) {
        if (!isValidIp(ip)) continue;

        const present = await db
          .select({ serverId: blockedIps.serverId })
          .from(blockedIps)
          .where(and(eq(blockedIps.ip, ip), eq(blockedIps.active, dbTrue)));

        const presentSet = new Set(present.map((r) => r.serverId));
        const missing = enabled.filter((s) => !presentSet.has(s.id));
        if (missing.length === 0) continue;

        // Skip rows already pending in the queue for this (ip, target).
        const alreadyPending = await db
          .select({ targetServerId: blockPropagationQueue.targetServerId })
          .from(blockPropagationQueue)
          .where(
            and(
              eq(blockPropagationQueue.ip, ip),
              eq(blockPropagationQueue.status, 'pending'),
            ),
          );
        const pendingSet = new Set(alreadyPending.map((r) => r.targetServerId));
        const toEnqueue = missing.filter((s) => !pendingSet.has(s.id));
        if (toEnqueue.length === 0) continue;

        await db.insert(blockPropagationQueue).values(
          toEnqueue.map((s) => ({
            ip,
            targetServerId: s.id,
            sourceServerId: null,
            incidentId: null,
            reason: 'Reconciliation: missing on this server',
            attempts: 0,
            maxAttempts: 5,
            status: 'pending' as const,
            nextRetryAt: dbDate(new Date()),
          })),
        );
        enqueued += toEnqueue.length;
      }

      if (enqueued > 0) {
        logger.info({ enqueued }, 'Reconciliation enqueued missing block rows');
      } else {
        logger.debug('Reconciliation: no gaps found');
      }
    } catch (err) {
      logger.error({ err }, 'Reconciliation failed');
    } finally {
      this.running.reconcile = false;
    }
  }

  /**
   * Re-verify every active block. After 2 consecutive verify failures,
   * re-enqueue and Telegram-alert.
   */
  static async reverify(): Promise<void> {
    if (this.running.reverify) return;
    this.running.reverify = true;
    try {
      const active = await db
        .select()
        .from(blockedIps)
        .where(eq(blockedIps.active, dbTrue));

      const enabled = await ServerService.getEnabled();
      const serverMap = new Map(enabled.map((s) => [s.id, s]));

      let verified = 0;
      let failed = 0;
      let reapplied = 0;

      for (const row of active) {
        if (!isValidIp(row.ip)) continue;
        const server = serverMap.get(row.serverId);
        if (!server) continue; // server disabled — leave alone, reconcile handles it

        const storedMethod = (row.method as 'fail2ban' | 'ufw' | null) ?? null;
        const target = ServerService.toSSHTarget(server);

        let isVerified = false;
        let resolvedMethod: 'fail2ban' | 'ufw' | null = storedMethod;
        try {
          const result = await verifyBlock(target, row.ip, storedMethod);
          isVerified = result.verified;
          resolvedMethod = result.method;
        } catch (err) {
          logger.warn({ err, ip: row.ip, server: server.name }, 'verifyBlock threw — counting as failure');
          isVerified = false;
        }

        if (isVerified) {
          verified++;
          // Persist resolved method when discovered for the first time, so
          // the next reverify pass can target the right backend without
          // probing both.
          const methodChanged = resolvedMethod && resolvedMethod !== storedMethod;
          if (row.consecutiveVerifyFailures > 0 || !row.verified || methodChanged) {
            await db
              .update(blockedIps)
              .set({
                verified: true,
                lastVerifiedAt: dbDate(new Date()),
                consecutiveVerifyFailures: 0,
                ...(methodChanged ? { method: resolvedMethod } : {}),
              })
              .where(eq(blockedIps.id, row.id));
          } else {
            await db
              .update(blockedIps)
              .set({ lastVerifiedAt: dbDate(new Date()) })
              .where(eq(blockedIps.id, row.id));
          }
          continue;
        }

        // Verify failed
        failed++;
        const newFailures = (row.consecutiveVerifyFailures ?? 0) + 1;
        await db
          .update(blockedIps)
          .set({
            verified: false,
            consecutiveVerifyFailures: newFailures,
            lastVerifiedAt: dbDate(new Date()),
          })
          .where(eq(blockedIps.id, row.id));

        if (newFailures >= REVERIFY_FAILURE_THRESHOLD) {
          // Re-enqueue. The propagation worker is idempotent — if the firewall
          // somehow has the rule and verify is just lying, the worker's
          // own check against blocked_ips will short-circuit safely.
          await db.insert(blockPropagationQueue).values({
            ip: row.ip,
            targetServerId: row.serverId,
            sourceServerId: null,
            incidentId: row.incidentId ?? null,
            reason: `Re-verify failed ${newFailures}x — reapplying`,
            attempts: 0,
            maxAttempts: 5,
            status: 'pending',
            nextRetryAt: dbDate(new Date()),
          });
          reapplied++;

          await NotifierManager.notify({
            title: 'Block lost on monitored server',
            body:
              `Block of ${row.ip} on ${server.name} failed verification ${newFailures} times.\n` +
              `Method: ${storedMethod ?? 'unknown'}. Last verified: ${row.lastVerifiedAt ? new Date(row.lastVerifiedAt).toISOString() : 'never'}.\n\n` +
              `Re-enqueued for reapply. If this repeats, the firewall on this server may have been flushed.`,
            severity: 'high',
            metadata: {
              type: 'block_lost',
              ip: row.ip,
              serverId: String(row.serverId),
              serverName: server.name,
              failures: String(newFailures),
            },
          }).catch((err) => logger.error({ err }, 'Re-verify alert failed'));
        }
      }

      logger.info({ active: active.length, verified, failed, reapplied }, 'Block re-verify pass complete');
    } catch (err) {
      logger.error({ err }, 'Re-verify failed');
    } finally {
      this.running.reverify = false;
    }
  }

  static async stop(): Promise<void> {
    if (this.reconcileTimer) {
      clearInterval(this.reconcileTimer);
      this.reconcileTimer = null;
    }
    if (this.reverifyTimer) {
      clearInterval(this.reverifyTimer);
      this.reverifyTimer = null;
    }
    const start = Date.now();
    while ((this.running.reconcile || this.running.reverify) && Date.now() - start < 10_000) {
      await new Promise((r) => setTimeout(r, 100));
    }
    logger.info('Block reconcile worker stopped');
  }
}
