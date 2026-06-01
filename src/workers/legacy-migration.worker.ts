import { ServerService } from '../services/server.service.js';
import { ServerUpgradeService } from '../services/server-upgrade.service.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';
import type { ServerInfo } from '../services/server.service.js';

const INTERVAL_MS = 6 * 60 * 60 * 1000;

export class LegacyMigrationWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static running = false;

  static start(): void {
    if (!config.legacyMigration.enabled) {
      logger.info('LegacyMigrationWorker started (gated — LEGACY_MIGRATION_ENABLED=false, auto-upgrade disabled)');
    } else {
      logger.info('LegacyMigrationWorker started (LEGACY_MIGRATION_ENABLED=true, 6h cycle)');
      setTimeout(() => this.runCycle(), 60_000);
    }
    this.intervalId = setInterval(() => this.runCycle(), INTERVAL_MS);
  }

  static stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('LegacyMigrationWorker stopped');
  }

  static async runCycle(): Promise<void> {
    if (!config.legacyMigration.enabled) return;
    if (this.running) {
      logger.debug('LegacyMigrationWorker: previous cycle still running, skipping');
      return;
    }
    this.running = true;

    try {
      const servers = await ServerService.getEnabled();
      const legacy = servers.filter(s => s.installMode === 'legacy' || s.installMode === null);

      if (legacy.length === 0) {
        logger.info('LegacyMigrationWorker: no legacy servers found');
        return;
      }

      logger.info({ count: legacy.length }, 'LegacyMigrationWorker: starting upgrade cycle');

      for (const server of legacy) {
        await this.upgradeOne(server);
      }
    } catch (err) {
      logger.error({ err }, 'LegacyMigrationWorker cycle error');
    } finally {
      this.running = false;
    }
  }

  static async upgradeOne(server: ServerInfo): Promise<void> {
    await notify(`🔄 Iniciando upgrade Tier 0 em <b>${server.name}</b> (${server.host})…`);
    const result = await ServerUpgradeService.upgrade(server);

    if (result.success) {
      await notify(
        `✅ <b>${server.name}</b> migrado para Tier 0\n` +
        `${result.steps.length} etapas em ${(result.totalDurationMs / 1000).toFixed(1)}s`,
      );
      logger.info({ server: server.name, durationMs: result.totalDurationMs }, 'Tier 0 upgrade complete');
    } else {
      const rolledBack = result.rolledBack ? ' (rollback aplicado)' : '';
      await notify(
        `❌ Upgrade falhou em <b>${server.name}</b>${rolledBack}\n` +
        `Erro: <code>${result.error ?? 'unknown'}</code>\n` +
        formatFailedSteps(result.steps),
      );
      logger.warn({ server: server.name, error: result.error, rolledBack: result.rolledBack }, 'Tier 0 upgrade failed');
    }
  }
}

function formatFailedSteps(steps: { name: string; status: string; detail?: string }[]): string {
  const failed = steps.filter(s => s.status === 'failed');
  if (failed.length === 0) return '';
  return '\n' + failed.map(s => `• ${s.name}: <code>${s.detail ?? ''}</code>`).join('\n');
}

async function notify(text: string): Promise<void> {
  await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: config.telegram.chatId, text, parse_mode: 'HTML' }),
  }).catch(err => logger.warn({ err }, 'LegacyMigrationWorker: Telegram notify failed'));
}
