import { SSHCollector } from '../../collectors/ssh-collector.js';
import { ServerService } from '../../services/server.service.js';
import type { PlaybookContext } from '../engine.js';
import { logger } from '../../utils/logger.js';

export async function killProcess(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const processName = (params?.processName as string) ?? (ctx.variables['processName'] as string);
  if (!processName) {
    return { success: false, message: 'No process name specified' };
  }

  const server = await ServerService.getEnabled().then(servers =>
    servers.find(s => s.id === ctx.serverId)
  );
  if (!server) return { success: false, message: `Server ${ctx.serverId} not found` };

  const target = ServerService.toSSHTarget(server);

  // Find PIDs matching the process name
  const findResult = await SSHCollector.run(target, `pgrep -f '${processName}' | head -5`, 10_000);
  if (!findResult.success || !findResult.stdout.trim()) {
    return { success: true, message: `Process '${processName}' not found (may have already exited)` };
  }

  const pids = findResult.stdout.trim().split('\n').filter(Boolean);

  const killResult = await SSHCollector.run(target,
    `sudo kill -9 ${pids.join(' ')}`,
    10_000
  );

  if (!killResult.success) {
    return { success: false, message: `Failed to kill process '${processName}' (PIDs: ${pids.join(', ')})` };
  }

  logger.info({ processName, pids, server: ctx.serverName }, 'Process killed via playbook');
  return { success: true, message: `Killed '${processName}' (PIDs: ${pids.join(', ')}) on ${ctx.serverName}` };
}
