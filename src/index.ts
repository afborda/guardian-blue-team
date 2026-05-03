import express from 'express';
import { config } from './config/environment.js';
import { logger } from './utils/logger.js';
import { testConnection, closeConnection, initDatabase } from './database/connection.js';
import { DailyReportWorker } from './workers/daily-report.worker.js';
import { EventCollectorWorker } from './workers/event-collector.worker.js';
import { VulnScannerWorker } from './workers/vuln-scanner.worker.js';
import { BlockCleanupWorker } from './workers/block-cleanup.worker.js';
import { CVEMonitorWorker } from './workers/cve-monitor.worker.js';
import { ScoreCalculatorWorker } from './workers/score-calculator.worker.js';
import { MetricsRetentionWorker } from './workers/metrics-retention.worker.js';
import { ThreatIntelManager } from './threat-intel/manager.js';
import { PlaybookRegistry } from './playbooks/registry.js';
import { handleTelegramCommand } from './telegram/commands.js';
import { handleTelegramCallback } from './telegram/callbacks.js';
import { registerBuiltinPlugins, PluginManager } from './plugins/index.js';
import { dashboardPages, dashboardApi } from './dashboard/routes.js';
import { dashboardAuth } from './dashboard/auth.js';
import { CONSTANTS } from './config/constants.js';

const app = express();
app.use(express.json());

// ─── Dashboard ──────────────────────────────────────────────────────────────

app.use('/dashboard', dashboardAuth, dashboardPages);
app.use('/api/dashboard', dashboardAuth, dashboardApi);

// ─── Health ─────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

// ─── Telegram Webhook ───────────────────────────────────────────────────────

const rateLimitMap = new Map<string, number[]>();

function isRateLimited(chatId: string): boolean {
  const now = Date.now();
  const timestamps = rateLimitMap.get(chatId) ?? [];
  const recent = timestamps.filter(t => now - t < CONSTANTS.telegram.rateLimitWindowMs);
  recent.push(now);
  rateLimitMap.set(chatId, recent);
  return recent.length > CONSTANTS.telegram.rateLimitMax;
}

app.post('/webhook/telegram', async (req, res) => {
  if (config.telegram.webhookSecret) {
    const token = req.headers['x-telegram-bot-api-secret-token'];
    if (token !== config.telegram.webhookSecret) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
  }

  const update = req.body;
  res.sendStatus(200);

  try {
    if (update.callback_query) {
      const callbackChatId = String(update.callback_query.message?.chat?.id);
      if (callbackChatId !== config.telegram.chatId) return;
      await handleTelegramCallback(update.callback_query);
    } else if (update.message?.text) {
      const text = update.message.text;
      const chatId = update.message.chat.id;

      if (String(chatId) !== config.telegram.chatId) return;

      if (isRateLimited(String(chatId))) {
        await sendTelegramMessage(chatId, '⚠️ Rate limit: máximo 10 comandos por minuto.');
        return;
      }

      if (text.startsWith('/')) {
        const response = await handleTelegramCommand(text);
        await sendTelegramMessage(chatId, response);
      }
    }
  } catch (error) {
    logger.error({ err: error }, 'Telegram webhook handler error');
  }
});

async function sendTelegramMessage(chatId: number | string, text: string): Promise<void> {
  try {
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' }),
    });
  } catch (error) {
    logger.error({ err: error }, 'Failed to send Telegram response');
  }
}

// ─── Heartbeat (Uptime Kuma push) ──────────────────────────────────────────

let heartbeatInterval: NodeJS.Timeout | null = null;

function startHeartbeat(): void {
  if (!config.health.uptimeKumaPushUrl) return;

  heartbeatInterval = setInterval(async () => {
    try {
      await fetch(config.health.uptimeKumaPushUrl!, { method: 'GET' });
    } catch { /* non-critical */ }
  }, 60_000);

  logger.info('Heartbeat started (push every 60s)');
}

// ─── Startup ────────────────────────────────────────────────────────────────

async function start(): Promise<void> {
  logger.info('Guardian starting...');

  await initDatabase();

  const dbOk = await testConnection();
  if (!dbOk) {
    logger.error('Database connection failed, exiting');
    process.exit(1);
  }
  logger.info('Database connected');

  registerBuiltinPlugins();
  await PluginManager.loadNotifiers(config.notifiers);

  app.listen(config.server.port, () => {
    logger.info(`Guardian listening on :${config.server.port}`);
  });

  EventCollectorWorker.start();
  ScoreCalculatorWorker.start();
  MetricsRetentionWorker.start();
  DailyReportWorker.start();
  VulnScannerWorker.start();
  BlockCleanupWorker.start();
  ThreatIntelManager.start();
  PlaybookRegistry.init();
  startHeartbeat();

  if (config.cveMonitor.enabled) {
    CVEMonitorWorker.start();
  }

  logger.info('All workers started');
}

// ─── Graceful Shutdown ──────────────────────────────────────────────────────

async function shutdown(signal: string): Promise<void> {
  logger.info(`${signal} received, shutting down...`);

  if (heartbeatInterval) clearInterval(heartbeatInterval);

  await Promise.allSettled([
    DailyReportWorker.stop(),
    EventCollectorWorker.stop(),
    ScoreCalculatorWorker.stop(),
    MetricsRetentionWorker.stop(),
    VulnScannerWorker.stop(),
    BlockCleanupWorker.stop(),
    CVEMonitorWorker.stop(),
  ]);
  ThreatIntelManager.stop();

  await closeConnection();
  logger.info('Guardian stopped');
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

start().catch(err => {
  logger.error({ err }, 'Guardian failed to start');
  process.exit(1);
});
