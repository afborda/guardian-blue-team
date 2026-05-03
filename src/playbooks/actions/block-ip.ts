import { SSHCollector } from '../../collectors/ssh-collector.js';
import { ServerService } from '../../services/server.service.js';
import { db } from '../../database/connection.js';
import { blockedIps } from '../../database/schema.js';
import { and, eq } from 'drizzle-orm';
import type { PlaybookContext } from '../engine.js';
import { logger } from '../../utils/logger.js';

function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)(m|h|d)$/);
  if (!match) return 24 * 60 * 60 * 1000; // default 24h
  const [, num, unit] = match;
  const ms = { m: 60_000, h: 3_600_000, d: 86_400_000 }[unit] ?? 3_600_000;
  return parseInt(num) * ms;
}

function durationToSeconds(duration: string): number {
  return Math.floor(parseDuration(duration) / 1000);
}

async function tryFail2ban(target: ReturnType<typeof ServerService.toSSHTarget>, ip: string, duration: string): Promise<boolean> {
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
  const result = await SSHCollector.run(target,
    `sudo ufw deny from ${ip} comment 'guardian-block-${Date.now()}'`,
    10_000
  );
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

  const existing = await db.select().from(blockedIps)
    .where(and(
      eq(blockedIps.ip, ctx.sourceIp),
      eq(blockedIps.serverId, ctx.serverId),
      eq(blockedIps.active, true),
    ))
    .then(rows => rows[0]);

  if (existing) {
    return { success: true, message: `IP ${ctx.sourceIp} already blocked on ${ctx.serverName} (expires ${existing.expiresAt.toISOString()})` };
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

  const expiresAt = new Date(Date.now() + parseDuration(duration));

  await db.insert(blockedIps).values({
    ip: ctx.sourceIp,
    serverId: ctx.serverId,
    reason: `Playbook auto-block via ${method} (incident #${ctx.incidentId ?? 'n/a'})`,
    playbookExecutionId: null,
    incidentId: ctx.incidentId ?? null,
    expiresAt,
  });

  logger.info({ ip: ctx.sourceIp, server: ctx.serverName, duration, method, expiresAt }, 'IP blocked via playbook');
  return { success: true, message: `Blocked ${ctx.sourceIp} on ${ctx.serverName} via ${method} (expires in ${duration})` };
}

export async function unblockIP(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const ip = (params?.ip as string) ?? ctx.sourceIp;
  if (!ip) return { success: false, message: 'No IP specified' };

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
    .set({ active: false, unblockedAt: new Date() })
    .where(and(
      eq(blockedIps.ip, ip),
      eq(blockedIps.serverId, ctx.serverId),
      eq(blockedIps.active, true),
    ));

  return { success: true, message: `Unblocked ${ip} on ${ctx.serverName}` };
}
