import { SSHExecutor } from './executor.js';
import { runAllProbes } from './probes/index.js';
import { analyzeSnapshot } from './analyzer.js';
import { formatTelegramMessage } from './presenter.js';
import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { logger } from '../utils/logger.js';
import type { DiscoveryResult, ServerSnapshot } from './types.js';

export interface RemoteDiscoveryResult {
  snapshot: ServerSnapshot;
  analysis: DiscoveryResult;
  telegramMessage: string;
}

export async function discoverRemoteServer(target: SSHTarget): Promise<RemoteDiscoveryResult | null> {
  const reachable = await SSHCollector.isReachable(target);
  if (!reachable) {
    logger.warn({ server: target.name }, 'Discovery: server not reachable');
    return null;
  }

  logger.info({ server: target.name }, 'Discovery: starting remote scan');
  const exec = new SSHExecutor(target);
  const snapshot = await runAllProbes(
    exec,
    { host: target.host, port: target.sshPort, user: target.sshUser },
    'ssh',
  );

  logger.info({ server: target.name, durationMs: snapshot.scanDurationMs }, 'Discovery: probes complete');
  const analysis = await analyzeSnapshot(snapshot);
  const telegramMessage = formatTelegramMessage(snapshot, analysis);

  return { snapshot, analysis, telegramMessage };
}

export function formatDiscoveryApprovalKeyboard(serverId: number): object {
  return {
    inline_keyboard: [[
      { text: 'Aprovar', callback_data: `discovery_approve_${serverId}` },
      { text: 'Cancelar', callback_data: `discovery_cancel_${serverId}` },
    ]],
  };
}
