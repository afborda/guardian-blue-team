import { SSHCollector } from '../../collectors/ssh-collector.js';
import { ServerService } from '../../services/server.service.js';
import { db, dbTrue, dbFalse, dbNow } from '../../database/connection.js';
import { blockedIps } from '../../database/schema.js';
import { and, eq } from 'drizzle-orm';
import type { PlaybookContext } from '../engine.js';
import { logger } from '../../utils/logger.js';
import { isValidIp } from '../../utils/sanitize.js';

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

export async function verifyBlock(
  target: ReturnType<typeof ServerService.toSSHTarget>,
  ip: string,
  method: 'fail2ban' | 'ufw'
): Promise<boolean> {
  if (!isValidIp(ip)) return false;

  if (method === 'fail2ban') {
    const result = await SSHCollector.run(target, `sudo fail2ban-client status guardian-jail 2>/dev/null | grep -q "${ip}"`, 10_000);
    return result.success;
  }

  const result = await SSHCollector.run(target, `sudo ufw status | grep -q "${ip}"`, 10_000);
  return result.success;
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

  // Try fail2ban first (has native TTL), fall back to UFW
  let method: 'fail2ban' | 'ufw';
  const f2bSuccess = await tryFail2ban(target, ctx.sourceIp, duration);

  if (f2bSuccess) {
    method = 'fail2ban';
  } else {
    const ufwSuccess = await tryUfw(target, ctx.sourceIp);
    if (!ufwSuccess) {
      return { success: false, message: 'Both fail2ban and UFW block failed' };
    }
    method = 'ufw';
  }

  // Verify the block actually exists in the firewall
  const verified = await verifyBlock(target, ctx.sourceIp, method);

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
  return { success: true, message: `Blocked ${ctx.sourceIp} on ${ctx.serverName} via ${method} (${expiresLabel}, ${verifiedLabel})` };
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

  // Try fail2ban unban first, then UFW as fallback
  const f2bResult = await SSHCollector.run(target, `sudo fail2ban-client set guardian-jail unbanip ${ip}`, 10_000);
  if (!f2bResult.success) {
    const ufwResult = await SSHCollector.run(target, `sudo ufw delete deny from ${ip}`, 10_000);
    if (!ufwResult.success) return { success: false, message: 'Unblock failed (both fail2ban and UFW)' };
  }

  await db.update(blockedIps)
    .set({ active: dbFalse, unblockedAt: dbNow() })
    .where(and(
      eq(blockedIps.ip, ip),
      eq(blockedIps.serverId, ctx.serverId),
      eq(blockedIps.active, dbTrue),
    ));

  return { success: true, message: `Unblocked ${ip} on ${ctx.serverName}` };
}
