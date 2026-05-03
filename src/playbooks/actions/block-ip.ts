import { SSHCollector } from '../../collectors/ssh-collector.js';
import { ServerService } from '../../services/server.service.js';
import type { PlaybookContext } from '../engine.js';
import { logger } from '../../utils/logger.js';

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

  const target = ServerService.toSSHTarget(server);

  const result = await SSHCollector.run(target,
    `sudo ufw deny from ${ctx.sourceIp} comment 'guardian-block-${Date.now()}'`,
    10_000
  );

  if (!result.success) {
    return { success: false, message: 'UFW block command failed' };
  }

  logger.info({ ip: ctx.sourceIp, server: ctx.serverName, duration }, 'IP blocked via playbook');
  return { success: true, message: `Blocked ${ctx.sourceIp} on ${ctx.serverName} (${duration})` };
}

export async function unblockIP(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const ip = (params?.ip as string) ?? ctx.sourceIp;
  if (!ip) return { success: false, message: 'No IP specified' };

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );

  if (!server) return { success: false, message: `Server not found` };

  const target = ServerService.toSSHTarget(server);
  const result = await SSHCollector.run(target, `sudo ufw delete deny from ${ip}`, 10_000);

  if (!result.success) return { success: false, message: 'UFW unblock failed' };

  return { success: true, message: `Unblocked ${ip} on ${ctx.serverName}` };
}
