import { SSHCollector } from '../../collectors/ssh-collector.js';
import { ServerService } from '../../services/server.service.js';
import { db, dbTrue, dbFalse, dbNow } from '../../database/connection.js';
import { rateLimitedIps } from '../../database/schema.js';
import { and, eq } from 'drizzle-orm';
import type { PlaybookContext } from '../engine.js';
import { logger } from '../../utils/logger.js';
import { isValidIp } from '../../utils/sanitize.js';
import { CONSTANTS } from '../../config/constants.js';
import { ensureGuardianChain, GUARDIAN_CHAIN } from './iptables-chain.js';

export async function rateLimit(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  if (!ctx.sourceIp) return { success: false, message: 'No source IP to rate-limit' };
  if (!isValidIp(ctx.sourceIp)) return { success: false, message: `Invalid IP: ${ctx.sourceIp}` };

  const limitPerSec = (params?.limitPerSec as number) ?? CONSTANTS.ddos.rateLimitPerSec;
  const burst = (params?.burst as number) ?? CONSTANTS.ddos.rateLimitBurst;

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: `Server ${ctx.serverId} not found` };

  // Check if already rate-limited
  const existing = await db.select().from(rateLimitedIps)
    .where(and(
      eq(rateLimitedIps.ip, ctx.sourceIp),
      eq(rateLimitedIps.serverId, ctx.serverId),
      eq(rateLimitedIps.active, dbTrue),
    ))
    .then(rows => rows[0]);

  if (existing) {
    return { success: true, message: `IP ${ctx.sourceIp} already rate-limited on ${ctx.serverName}` };
  }

  const target = ServerService.toSSHTarget(server);
  const ip = ctx.sourceIp;

  // Stage Guardian's dedicated chain before inserting rules. If this fails the
  // chain helper logs and returns false; we abort rather than risk inserting
  // into INPUT (which is what we're trying to stop doing).
  const chainOk = await ensureGuardianChain(target, ctx.serverId);
  if (!chainOk) {
    return { success: false, message: `Failed to ensure ${GUARDIAN_CHAIN} chain — refusing to fall back to INPUT` };
  }

  // Apply iptables rate limiting in GUARDIAN-INPUT: allow limited traffic, drop excess.
  const acceptCmd = `sudo iptables -I ${GUARDIAN_CHAIN} -s ${ip} -m limit --limit ${limitPerSec}/sec --limit-burst ${burst} -j ACCEPT`;
  const dropCmd = `sudo iptables -A ${GUARDIAN_CHAIN} -s ${ip} -j DROP`;

  const acceptResult = await SSHCollector.run(target, acceptCmd, 10_000);
  if (!acceptResult.success) {
    return { success: false, message: `Failed to apply rate-limit ACCEPT rule` };
  }

  const dropResult = await SSHCollector.run(target, dropCmd, 10_000);
  if (!dropResult.success) {
    // Rollback accept rule
    await SSHCollector.run(target, `sudo iptables -D ${GUARDIAN_CHAIN} -s ${ip} -m limit --limit ${limitPerSec}/sec --limit-burst ${burst} -j ACCEPT`, 10_000);
    return { success: false, message: `Failed to apply rate-limit DROP rule` };
  }

  await db.insert(rateLimitedIps).values({
    ip: ctx.sourceIp,
    serverId: ctx.serverId,
    limitPerSec,
    burst,
    reason: `DDoS rate-limit (incident #${ctx.incidentId ?? 'n/a'})`,
    incidentId: ctx.incidentId ?? null,
  });

  logger.info({ ip: ctx.sourceIp, server: ctx.serverName, limitPerSec, burst }, 'IP rate-limited via iptables');
  return { success: true, message: `Rate-limited ${ctx.sourceIp} on ${ctx.serverName} (${limitPerSec}/sec, burst ${burst})` };
}

export async function removeRateLimit(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const ip = (params?.ip as string) ?? ctx.sourceIp;
  if (!ip || !isValidIp(ip)) return { success: false, message: 'Invalid or missing IP' };

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: 'Server not found' };

  const target = ServerService.toSSHTarget(server);

  // Remove both rules from GUARDIAN-INPUT (order matters: drop first, then accept)
  await SSHCollector.run(target, `sudo iptables -D ${GUARDIAN_CHAIN} -s ${ip} -j DROP`, 10_000);
  await SSHCollector.run(target, `sudo iptables -D ${GUARDIAN_CHAIN} -s ${ip} -m limit --limit-burst 0 -j ACCEPT 2>/dev/null; sudo iptables -D ${GUARDIAN_CHAIN} -s ${ip} -m limit -j ACCEPT 2>/dev/null`, 10_000);

  await db.update(rateLimitedIps)
    .set({ active: dbFalse, removedAt: dbNow() })
    .where(and(eq(rateLimitedIps.ip, ip), eq(rateLimitedIps.serverId, ctx.serverId), eq(rateLimitedIps.active, dbTrue)));

  logger.info({ ip, server: ctx.serverName }, 'Rate-limit removed');
  return { success: true, message: `Rate-limit removed for ${ip} on ${ctx.serverName}` };
}
