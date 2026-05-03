import { SSHCollector } from '../../collectors/ssh-collector.js';
import { ServerService } from '../../services/server.service.js';
import type { PlaybookContext } from '../engine.js';
import { logger } from '../../utils/logger.js';

export async function pauseContainer(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const container = (params?.container as string) ?? (ctx.variables['containerName'] as string);
  if (!container) {
    return { success: false, message: 'No container name specified' };
  }

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: `Server ${ctx.serverId} not found` };

  const target = ServerService.toSSHTarget(server);
  const result = await SSHCollector.run(target, `docker pause ${container}`, 10_000);

  if (!result.success) {
    return { success: false, message: `Failed to pause container '${container}'` };
  }

  logger.info({ container, server: ctx.serverName }, 'Container paused via playbook');
  return { success: true, message: `Paused container '${container}' on ${ctx.serverName}` };
}

export async function disconnectContainer(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const container = (params?.container as string) ?? (ctx.variables['containerName'] as string);
  if (!container) {
    return { success: false, message: 'No container name specified' };
  }

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: `Server ${ctx.serverId} not found` };

  const target = ServerService.toSSHTarget(server);

  // Get all networks the container is connected to
  const networksResult = await SSHCollector.run(target,
    `docker inspect --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' ${container}`,
    10_000
  );

  if (!networksResult.success || !networksResult.stdout.trim()) {
    return { success: false, message: `Failed to get networks for container '${container}'` };
  }

  const networks = networksResult.stdout.trim().split(/\s+/).filter(Boolean);
  let disconnected = 0;

  for (const network of networks) {
    const result = await SSHCollector.run(target,
      `docker network disconnect ${network} ${container}`,
      10_000
    );
    if (result.success) disconnected++;
  }

  logger.info({ container, networks: disconnected, server: ctx.serverName }, 'Container isolated (networks disconnected)');
  return { success: true, message: `Isolated '${container}' — disconnected from ${disconnected}/${networks.length} networks on ${ctx.serverName}` };
}
