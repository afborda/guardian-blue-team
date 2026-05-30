import { SSHCollector } from '../../collectors/ssh-collector.js';
import { ServerService } from '../../services/server.service.js';
import { db, dbTrue, dbFalse, dbNow, dbDate } from '../../database/connection.js';
import { blockedIps, blockPropagationQueue } from '../../database/schema.js';
import { and, eq } from 'drizzle-orm';
import type { PlaybookContext } from '../engine.js';
import { logger } from '../../utils/logger.js';
import { AuditLogger } from '../../utils/audit-logger.js';
import { isValidIp } from '../../utils/sanitize.js';
import { ensureGuardianChain, GUARDIAN_CHAIN } from './iptables-chain.js';

export type BlockMethod = 'fail2ban' | 'ufw' | 'iptables';

function isPermanent(duration: string): boolean {
  return duration === 'permanent' || duration === 'perm' || duration === '-1';
}

function parseDuration(duration: string): number {
  if (isPermanent(duration)) return -1;
  const match = duration.match(/^(\d+)(m|h|d)$/);
  if (!match) return -1; // default permanent
  const [, num, unit] = match;
  const ms = { m: 60_000, h: 3_600_000, d: 86_400_000 }[unit] ?? 3_600_000;
  return parseInt(num) * ms;
}

function durationToSeconds(duration: string): number {
  if (isPermanent(duration)) return -1;
  return Math.floor(parseDuration(duration) / 1000);
}

async function tryFail2ban(target: ReturnType<typeof ServerService.toSSHTarget>, ip: string, duration: string): Promise<boolean> {
  if (!isValidIp(ip)) return false;
  const checkResult = await SSHCollector.run(target, 'which fail2ban-client', 5_000);
  if (!checkResult.success || !checkResult.stdout.trim()) return false;

  const banTime = durationToSeconds(duration);
  const result = await SSHCollector.run(target,
    `sudo fail2ban-client set guardian-jail banip --bantime ${banTime} ${ip}`,
    10_000
  );

  return result.success;
}

async function tryUfw(target: ReturnType<typeof ServerService.toSSHTarget>, ip: string): Promise<boolean> {
  if (!isValidIp(ip)) return false;
  const result = await SSHCollector.run(target,
    `sudo ufw deny from ${ip} comment 'guardian-block-${Date.now()}'`,
    10_000
  );
  return result.success;
}

/**
 * Last-resort fallback: append a DROP rule to GUARDIAN-INPUT chain.
 *
 * Only reached when fail2ban is absent AND UFW failed. Uses Guardian's
 * dedicated chain so that `iptables -F INPUT` (operator troubleshooting)
 * cannot wipe blocks — only `iptables -F GUARDIAN-INPUT` can.
 *
 * No native TTL — caller persists `expiresAt` and `BlockCleanupWorker`
 * removes via `unblockIP` when the row expires.
 */
async function tryIptables(
  target: ReturnType<typeof ServerService.toSSHTarget>,
  ip: string,
  serverId: number,
): Promise<boolean> {
  if (!isValidIp(ip)) return false;
  const chainOk = await ensureGuardianChain(target, serverId);
  if (!chainOk) return false;
  const result = await SSHCollector.run(
    target,
    `sudo iptables -A ${GUARDIAN_CHAIN} -s ${ip} -j DROP`,
    10_000,
  );
  return result.success;
}

export async function verifyBlock(
  target: ReturnType<typeof ServerService.toSSHTarget>,
  ip: string,
  method: BlockMethod | null
): Promise<{ verified: boolean; method: BlockMethod | null }> {
  if (!isValidIp(ip)) return { verified: false, method };

  // When method is known, check only that backend.
  if (method === 'fail2ban') {
    const result = await SSHCollector.run(target, `sudo fail2ban-client status guardian-jail 2>/dev/null | grep -q "${ip}"`, 10_000);
    return { verified: result.success, method: 'fail2ban' };
  }
  if (method === 'ufw') {
    const result = await SSHCollector.run(target, `sudo ufw status | grep -q "${ip}"`, 10_000);
    return { verified: result.success, method: 'ufw' };
  }
  if (method === 'iptables') {
    const result = await SSHCollector.run(
      target,
      `sudo iptables -S ${GUARDIAN_CHAIN} 2>/dev/null | grep -q -- "-s ${ip}/32"`,
      10_000,
    );
    return { verified: result.success, method: 'iptables' };
  }

  // Unknown method (legacy rows where the column was never populated). Probe
  // UFW first because that's what enforceBlocks() uses by default; fall back
  // to fail2ban for hosts that have a guardian-jail configured, then iptables
  // for hosts where Guardian had to use the chain fallback. Whichever backend
  // confirms the rule wins and the caller persists `method` so the next
  // reverify is cheap.
  const ufwResult = await SSHCollector.run(target, `sudo ufw status | grep -q "${ip}"`, 10_000);
  if (ufwResult.success) return { verified: true, method: 'ufw' };

  const f2bResult = await SSHCollector.run(target, `sudo fail2ban-client status guardian-jail 2>/dev/null | grep -q "${ip}"`, 10_000);
  if (f2bResult.success) return { verified: true, method: 'fail2ban' };

  const iptResult = await SSHCollector.run(
    target,
    `sudo iptables -S ${GUARDIAN_CHAIN} 2>/dev/null | grep -q -- "-s ${ip}/32"`,
    10_000,
  );
  if (iptResult.success) return { verified: true, method: 'iptables' };

  return { verified: false, method: null };
}

export async function blockIP(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  if (!ctx.sourceIp) {
    return { success: false, message: 'No source IP to block' };
  }

  const duration = (params?.duration as string) ?? '24h';
  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );

  if (!server) {
    return { success: false, message: `Server ${ctx.serverId} not found` };
  }

  // Check if already blocked — handle race condition gracefully via try-catch on insert
  const existing = await db.select().from(blockedIps)
    .where(and(
      eq(blockedIps.ip, ctx.sourceIp),
      eq(blockedIps.serverId, ctx.serverId),
      eq(blockedIps.active, dbTrue),
    ))
    .then(rows => rows[0]);

  if (existing) {
    const expiresLabel = existing.expiresAt ? `expires ${existing.expiresAt.toISOString()}` : 'permanent';
    return { success: true, message: `IP ${ctx.sourceIp} already blocked on ${ctx.serverName} (${expiresLabel})` };
  }

  const target = ServerService.toSSHTarget(server);

  // Try fail2ban first (has native TTL), then UFW, then raw iptables in our
  // dedicated chain. Iptables fallback exists so the block survives even on
  // hosts where ufw is misconfigured/uninstalled and fail2ban isn't running.
  let method: BlockMethod;
  const f2bSuccess = await tryFail2ban(target, ctx.sourceIp, duration);

  if (f2bSuccess) {
    method = 'fail2ban';
  } else {
    const ufwSuccess = await tryUfw(target, ctx.sourceIp);
    if (ufwSuccess) {
      method = 'ufw';
    } else {
      const iptSuccess = await tryIptables(target, ctx.sourceIp, ctx.serverId);
      if (!iptSuccess) {
        return { success: false, message: 'fail2ban, UFW and iptables block all failed' };
      }
      method = 'iptables';
    }
  }

  // Verify the block actually exists in the firewall
  const { verified } = await verifyBlock(target, ctx.sourceIp, method);

  const durationMs = parseDuration(duration);
  const expiresAt = durationMs === -1 ? null : new Date(Date.now() + durationMs);

  // Insert with conflict handling — if unique index rejects (race condition), treat as already blocked
  try {
    await db.insert(blockedIps).values({
      ip: ctx.sourceIp,
      serverId: ctx.serverId,
      reason: `${ctx.triggeredBy === 'telegram' ? 'Manual' : 'Playbook auto'}-block via ${method} (incident #${ctx.incidentId ?? 'n/a'})`,
      playbookExecutionId: null,
      incidentId: ctx.incidentId ?? null,
      expiresAt,
      verified,
      method,
    });
  } catch (err: any) {
    // Unique constraint violation (race condition) — another process inserted first
    if (err?.code === '23505' || err?.message?.includes('UNIQUE constraint')) {
      logger.info({ ip: ctx.sourceIp, server: ctx.serverName }, 'IP block race condition — already inserted by another process');
      return { success: true, message: `IP ${ctx.sourceIp} already blocked on ${ctx.serverName} (concurrent insert)` };
    }
    throw err;
  }

  const expiresLabel = expiresAt ? `expires in ${duration}` : 'permanent';
  const verifiedLabel = verified ? 'verified' : 'unverified';
  logger.info({ ip: ctx.sourceIp, server: ctx.serverName, duration, method, expiresAt, verified }, 'IP blocked via playbook');
  await AuditLogger.block(ctx.sourceIp, ctx.serverId, ctx.triggeredBy ?? 'system', ctx.incidentId, {
    method, duration, verified, server: ctx.serverName,
  });

  // Propagate to every other monitored server. Time-limited blocks propagate
  // too — otherwise an attacker hitting server A simply pivots to server B.
  propagateBlock(ctx.sourceIp, ctx.serverId, ctx.incidentId);

  return { success: true, message: `Blocked ${ctx.sourceIp} on ${ctx.serverName} via ${method} (${expiresLabel}, ${verifiedLabel})` };
}

/**
 * Enqueue a block to be applied on every other monitored server. Returns
 * immediately — the BlockPropagationWorker drains the queue with retry/backoff.
 *
 * Inserting via `ON CONFLICT DO NOTHING` is impractical here because the queue
 * has no natural unique key (the same IP/server pair can be re-queued after a
 * previous attempt was completed or gave up). Idempotency is enforced by the
 * worker checking `blocked_ips` before re-applying.
 */
export function propagateBlock(
  ip: string,
  excludeServerId: number,
  incidentId?: number,
): void {
  if (!isValidIp(ip)) return;

  ServerService.getEnabled()
    .then(async (servers) => {
      const targets = servers.filter((s) => s.id !== excludeServerId);
      if (targets.length === 0) return;

      const rows = targets.map((s) => ({
        ip,
        targetServerId: s.id,
        sourceServerId: excludeServerId,
        incidentId: incidentId ?? null,
        reason: `Propagated from server ${excludeServerId}`,
        attempts: 0,
        maxAttempts: 5,
        status: 'pending' as const,
        nextRetryAt: dbDate(new Date()),
      }));

      try {
        await db.insert(blockPropagationQueue).values(rows);
        logger.info(
          { ip, queued: rows.length, excludeServerId, incidentId },
          'Block enqueued for propagation',
        );
      } catch (err) {
        logger.error({ err, ip, excludeServerId }, 'Failed to enqueue block propagation');
      }
    })
    .catch((err) => logger.error({ err, ip }, 'propagateBlock: getEnabled failed'));
}

export async function syncBlocksToServer(serverId: number): Promise<number> {
  const server = await ServerService.getEnabled().then(s => s.find(sv => sv.id === serverId));
  if (!server) return 0;

  const allBlocked = await db.selectDistinct({ ip: blockedIps.ip }).from(blockedIps)
    .where(eq(blockedIps.active, dbTrue));

  const uniqueIps = [...new Set(allBlocked.map(r => r.ip))];
  let synced = 0;

  for (const ip of uniqueIps) {
    if (!isValidIp(ip)) continue;

    const existing = await db.select({ id: blockedIps.id }).from(blockedIps)
      .where(and(
        eq(blockedIps.ip, ip),
        eq(blockedIps.serverId, serverId),
        eq(blockedIps.active, dbTrue),
      ))
      .then(rows => rows[0]);

    if (existing) continue;

    const target = ServerService.toSSHTarget(server);
    let method: BlockMethod;
    const f2bSuccess = await tryFail2ban(target, ip, 'permanent');

    if (f2bSuccess) {
      method = 'fail2ban';
    } else {
      const ufwSuccess = await tryUfw(target, ip);
      if (ufwSuccess) {
        method = 'ufw';
      } else {
        const iptSuccess = await tryIptables(target, ip, serverId);
        if (!iptSuccess) {
          logger.debug({ ip, server: server.name }, 'Sync block skipped (all methods failed)');
          continue;
        }
        method = 'iptables';
      }
    }

    const { verified } = await verifyBlock(target, ip, method);

    try {
      await db.insert(blockedIps).values({
        ip,
        serverId,
        reason: 'Synced from existing blocks',
        playbookExecutionId: null,
        incidentId: null,
        expiresAt: null,
        verified,
        method,
      });
      synced++;
    } catch {
      // duplicate — skip
    }
  }

  logger.info({ serverId, server: server.name, synced, total: uniqueIps.length }, 'Blocks synced to server');
  return synced;
}

export async function unblockIP(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const ip = (params?.ip as string) ?? ctx.sourceIp;
  if (!ip) return { success: false, message: 'No IP specified' };
  if (!isValidIp(ip)) return { success: false, message: `Invalid IP format: ${ip}` };

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );

  if (!server) return { success: false, message: `Server not found` };

  const target = ServerService.toSSHTarget(server);

  // Try every backend. We don't trust the stored `method` because the operator
  // may have reapplied via a different tool out of band. First success wins;
  // if none verified the IP existed in any backend, return failure.
  const f2bResult = await SSHCollector.run(target, `sudo fail2ban-client set guardian-jail unbanip ${ip}`, 10_000);
  let unblocked = f2bResult.success;
  if (!unblocked) {
    const ufwResult = await SSHCollector.run(target, `sudo ufw delete deny from ${ip}`, 10_000);
    unblocked = ufwResult.success;
  }
  if (!unblocked) {
    const iptResult = await SSHCollector.run(
      target,
      `sudo iptables -D ${GUARDIAN_CHAIN} -s ${ip} -j DROP`,
      10_000,
    );
    unblocked = iptResult.success;
  }
  if (!unblocked) return { success: false, message: 'Unblock failed (fail2ban, UFW and iptables all returned error)' };

  await db.update(blockedIps)
    .set({ active: dbFalse, unblockedAt: dbNow() })
    .where(and(
      eq(blockedIps.ip, ip),
      eq(blockedIps.serverId, ctx.serverId),
      eq(blockedIps.active, dbTrue),
    ));

  return { success: true, message: `Unblocked ${ip} on ${ctx.serverName}` };
}
