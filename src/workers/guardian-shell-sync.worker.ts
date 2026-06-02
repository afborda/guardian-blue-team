import { ServerService } from '../services/server.service.js';
import { GuardianShellSyncService } from '../services/guardian-shell-sync.service.js';
import { logger } from '../utils/logger.js';

const INTERVAL_MS = 6 * 60 * 60 * 1000; // 6h

export class GuardianShellSyncWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static running = false;

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.sync().catch((e) => logger.error({ err: e }, 'guardian-shell-sync worker error'));
    }, 30_000);

    this.intervalId = setInterval(() => {
      this.sync().catch((e) => logger.error({ err: e }, 'guardian-shell-sync worker error'));
    }, INTERVAL_MS);

    logger.info('Guardian shell sync worker started (every 6h)');
  }

  static stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  private static async sync(): Promise<void> {
    if (this.running) return;
    this.running = true;

    try {
      const servers = await ServerService.getEnabled();
      const guardianServers = servers.filter((s) => s.installMode === 'guardian');

      if (guardianServers.length === 0) {
        logger.debug('guardian-shell-sync: no guardian-mode servers, skipping');
        return;
      }

      for (const server of guardianServers) {
        const result = await GuardianShellSyncService.check(server);
        if (result.action === 'updated') {
          logger.info(
            {
              server: result.serverName,
              fromVersion: result.fromVersion,
              toVersion: result.toVersion,
              durationMs: result.durationMs,
            },
            'guardian-shell-sync: shell updated',
          );
        } else if (result.action === 'failed') {
          logger.warn(
            { server: result.serverName, error: result.error, durationMs: result.durationMs },
            'guardian-shell-sync: update failed',
          );
        }
      }
    } finally {
      this.running = false;
    }
  }
}
