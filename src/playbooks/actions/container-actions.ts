import { SSHCollector } from '../../collectors/ssh-collector.js';
import { ServerService } from '../../services/server.service.js';
import type { PlaybookContext } from '../engine.js';
import { logger } from '../../utils/logger.js';
import { isValidContainerName } from '../../utils/sanitize.js';

export async function pauseContainer(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const container = (params?.container as string) ?? (ctx.variables['containerName'] as string);
  if (!container) {
    return { success: false, message: 'No container name specified' };
  }
  if (!isValidContainerName(container)) {
    return { success: false, message: 'Invalid container name: contains unsafe characters' };
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
  if (!isValidContainerName(container)) {
    return { success: false, message: 'Invalid container name: contains unsafe characters' };
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

export async function killContainerProcess(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const container = (params?.container as string) ?? (ctx.variables['containerName'] as string);
  if (!container || !isValidContainerName(container)) {
    return { success: false, message: 'Invalid or missing container name' };
  }

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: `Server ${ctx.serverId} not found` };

  const target = ServerService.toSSHTarget(server);

  // Kill specific PID if provided, otherwise kill all suspicious processes
  const pid = params?.pid as string;
  let cmd: string;
  if (pid && /^\d+$/.test(pid)) {
    cmd = `docker exec ${container} kill -9 ${pid} 2>/dev/null`;
  } else {
    // Kill processes matching crypto mining patterns inside the container
    cmd = `docker exec ${container} sh -c "ps aux 2>/dev/null | grep -iE 'xmrig|minerd|cpuminer|cryptonight|kdevtmpfsi|kinsing' | grep -v grep | awk '{print \\$2}' | xargs -r kill -9" 2>/dev/null`;
  }

  await SSHCollector.run(target, cmd, 10_000);

  logger.info({ container, pid, server: ctx.serverName }, 'Container process kill attempted');
  return { success: true, message: `Kill signal sent to suspicious processes in '${container}' on ${ctx.serverName}` };
}

export async function restartContainer(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const container = (params?.container as string) ?? (ctx.variables['containerName'] as string);
  if (!container || !isValidContainerName(container)) {
    return { success: false, message: 'Invalid or missing container name' };
  }

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: `Server ${ctx.serverId} not found` };

  const target = ServerService.toSSHTarget(server);
  const result = await SSHCollector.run(target, `docker restart ${container}`, 30_000);

  if (!result.success) {
    return { success: false, message: `Failed to restart container '${container}'` };
  }

  logger.info({ container, server: ctx.serverName }, 'Container restarted via playbook');
  return { success: true, message: `Restarted container '${container}' on ${ctx.serverName}` };
}

export async function pullContainerImage(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const container = (params?.container as string) ?? (ctx.variables['containerName'] as string);
  if (!container || !isValidContainerName(container)) {
    return { success: false, message: 'Invalid or missing container name' };
  }

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: `Server ${ctx.serverId} not found` };

  const target = ServerService.toSSHTarget(server);

  // Get the image name from the running container
  const inspectResult = await SSHCollector.run(target,
    `docker inspect --format '{{.Config.Image}}' ${container} 2>/dev/null`,
    10_000
  );
  if (!inspectResult.success || !inspectResult.stdout.trim()) {
    return { success: false, message: `Could not determine image for container '${container}'` };
  }

  const image = inspectResult.stdout.trim();
  const pullResult = await SSHCollector.run(target, `docker pull ${image}`, 120_000);

  if (!pullResult.success) {
    return { success: false, message: `Failed to pull image '${image}'` };
  }

  logger.info({ container, image, server: ctx.serverName }, 'Container image pulled via playbook');
  return { success: true, message: `Pulled latest '${image}' for container '${container}' on ${ctx.serverName}` };
}

export async function recreateContainer(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const container = (params?.container as string) ?? (ctx.variables['containerName'] as string);
  if (!container || !isValidContainerName(container)) {
    return { success: false, message: 'Invalid or missing container name' };
  }

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: `Server ${ctx.serverId} not found` };

  const target = ServerService.toSSHTarget(server);

  // Try docker compose recreate first (preferred), fallback to restart
  const composeResult = await SSHCollector.run(target,
    `cd /opt/$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' ${container} 2>/dev/null) 2>/dev/null && docker compose up -d --force-recreate ${container} 2>/dev/null`,
    60_000
  );

  if (composeResult.success) {
    logger.info({ container, server: ctx.serverName }, 'Container recreated via docker compose');
    return { success: true, message: `Recreated '${container}' via compose on ${ctx.serverName}` };
  }

  // Fallback: simple restart with the new image
  const restartResult = await SSHCollector.run(target, `docker restart ${container}`, 30_000);
  if (!restartResult.success) {
    return { success: false, message: `Failed to recreate container '${container}'` };
  }

  logger.info({ container, server: ctx.serverName }, 'Container restarted (compose fallback)');
  return { success: true, message: `Restarted '${container}' on ${ctx.serverName} (compose path not found, used restart)` };
}
