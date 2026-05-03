import express from 'express';
import { config } from './config/environment.js';
import { logger } from './utils/logger.js';
import { testConnection, closeConnection } from './database/connection.js';
import { AbuseDetectionWorker } from './workers/abuse-detection.worker.js';
import { ProfileBuilderWorker } from './workers/profile-builder.worker.js';
import { DailyReportWorker } from './workers/daily-report.worker.js';
import { EventCollectorWorker } from './workers/event-collector.worker.js';
import { VulnScannerWorker } from './workers/vuln-scanner.worker.js';
import { ThreatIntelManager } from './threat-intel/manager.js';
import { PlaybookRegistry } from './playbooks/registry.js';
import { handleTelegramCommand } from './telegram/commands.js';
import { handleTelegramCallback } from './telegram/callbacks.js';

const app = express();
app.use(express.json());

// ─── Health ─────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', uptime: Math.floor(process.uptime()) });
});

// ─── Telegram Webhook ───────────────────────────────────────────────────────

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
      await handleTelegramCallback(update.callback_query);
    } else if (update.message?.text) {
      const text = update.message.text;
      const chatId = update.message.chat.id;

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

  const dbOk = await testConnection();
  if (!dbOk) {
    logger.error('Database connection failed, exiting');
    process.exit(1);
  }
  logger.info('Database connected');

  app.listen(config.server.port, () => {
    logger.info(`Guardian listening on :${config.server.port}`);
  });

  AbuseDetectionWorker.start();
  ProfileBuilderWorker.start();
  DailyReportWorker.start();
  EventCollectorWorker.start();
  VulnScannerWorker.start();
  ThreatIntelManager.start();
  PlaybookRegistry.init();
  startHeartbeat();

  logger.info('All workers started');
}

// ─── Graceful Shutdown ──────────────────────────────────────────────────────

async function shutdown(signal: string): Promise<void> {
  logger.info(`${signal} received, shutting down...`);

  if (heartbeatInterval) clearInterval(heartbeatInterval);

  await Promise.allSettled([
    AbuseDetectionWorker.stop(),
    ProfileBuilderWorker.stop(),
    DailyReportWorker.stop(),
    EventCollectorWorker.stop(),
    VulnScannerWorker.stop(),
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
