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
import { IntelligenceWorker } from './workers/intelligence.worker.js';
import { FIMWorker } from './workers/fim.worker.js';
import { DiscoveryWorker } from './workers/discovery.worker.js';
import { ThreatIntelManager } from './threat-intel/manager.js';
import { PlaybookRegistry } from './playbooks/registry.js';
import { handleTelegramCommand } from './telegram/commands.js';
import { handleTelegramCallback } from './telegram/callbacks.js';
import { registerBuiltinPlugins, PluginManager } from './plugins/index.js';
import { dashboardPages, dashboardApi } from './dashboard/routes.js';
import { dashboardAuth } from './dashboard/auth.js';
import { CONSTANTS } from './config/constants.js';
import { safeCompare } from './utils/sanitize.js';
import { rateLimiter } from './middleware/rate-limiter.js';

const app = express();
app.use(express.json());

// ─── Dashboard ──────────────────────────────────────────────────────────────

app.use('/dashboard', rateLimiter(60), dashboardAuth, dashboardPages);
app.use('/api/dashboard', rateLimiter(60), dashboardAuth, dashboardApi);

// ─── Health ─────────────────────────────────────────────────────────────────

app.get('/health', async (_req, res) => {
  const dbOk = await testConnection().catch(() => false);
  const status = dbOk ? 'ok' : 'degraded';
  const code = dbOk ? 200 : 503;
  res.status(code).json({
    status,
    uptime: Math.floor(process.uptime()),
    database: dbOk ? 'connected' : 'unreachable',
    version: '1.5.0',
  });
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
    if (!token || !safeCompare(String(token), config.telegram.webhookSecret)) {
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
        try {
          const response = await handleTelegramCommand(text);
          await sendTelegramMessage(chatId, response);
        } catch (cmdErr) {
          logger.error({ err: cmdErr, command: text.split(/\s+/)[0] }, 'Command execution failed');
          await sendTelegramMessage(chatId, '❌ Erro interno ao processar o comando. Verifique os logs.');
        }
      }
    }
  } catch (error) {
    logger.error({ err: error }, 'Telegram webhook handler error');
  }
});

async function sendTelegramMessage(chatId: number | string, text: string): Promise<void> {
  const MAX_LENGTH = 4000;

  try {
    if (text.length <= MAX_LENGTH) {
      const res = await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' }),
      });
      if (!res.ok) {
        const err = await res.text().catch(() => '');
        logger.warn({ status: res.status, err, textLength: text.length }, 'Telegram sendMessage failed');
        if (res.status === 400 && err.includes('parse')) {
          await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, text }),
          });
        }
      }
      return;
    }

    const chunks: string[] = [];
    let remaining = text;
    while (remaining.length > 0) {
      if (remaining.length <= MAX_LENGTH) {
        chunks.push(remaining);
        break;
      }
      let splitAt = remaining.lastIndexOf('\n', MAX_LENGTH);
      if (splitAt < MAX_LENGTH * 0.5) splitAt = MAX_LENGTH;
      chunks.push(remaining.slice(0, splitAt));
      remaining = remaining.slice(splitAt);
    }

    for (const chunk of chunks) {
      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text: chunk, parse_mode: 'HTML' }),
      });
    }
  } catch (error) {
    logger.error({ err: error }, 'Failed to send Telegram response');
  }
}

// ─── Telegram Webhook Registration ─────────────────────────────────────────

async function registerTelegramWebhook(): Promise<void> {
  const baseUrl = config.telegram.baseUrl;
  if (!baseUrl) {
    logger.warn('GUARDIAN_BASE_URL not set — Telegram webhook not registered. Bot will not receive messages.');
    return;
  }

  const webhookUrl = `${baseUrl.replace(/\/$/, '')}/webhook/telegram`;
  const params: Record<string, string> = { url: webhookUrl };

  if (config.telegram.webhookSecret) {
    params.secret_token = config.telegram.webhookSecret;
  }

  try {
    const res = await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/setWebhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });

    const data = await res.json() as { ok?: boolean; description?: string };
    if (data.ok) {
      logger.info({ webhookUrl }, 'Telegram webhook registered');
    } else {
      logger.error({ response: data }, 'Telegram webhook registration failed');
    }
  } catch (err) {
    logger.error({ err }, 'Failed to register Telegram webhook');
  }
}

// ─── Heartbeat (Uptime Kuma push) ──────────────────────────────────────────

let heartbeatInterval: NodeJS.Timeout | null = null;

function startHeartbeat(): void {
  if (!config.health.uptimeKumaPushUrl) return;

  heartbeatInterval = setInterval(async () => {
    try {
      await fetch(config.health.uptimeKumaPushUrl!, { method: 'GET' });
    } catch (err) {
      logger.debug({ err }, 'Heartbeat push failed');
    }
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

  PlaybookRegistry.init();
  ThreatIntelManager.start();

  app.listen(config.server.port, () => {
    logger.info(`Guardian listening on :${config.server.port}`);
  });

  await registerTelegramWebhook();

  EventCollectorWorker.start();
  FIMWorker.start();
  ScoreCalculatorWorker.start();
  MetricsRetentionWorker.start();
  IntelligenceWorker.start();
  DailyReportWorker.start();
  VulnScannerWorker.start();
  BlockCleanupWorker.start();
  DiscoveryWorker.start();
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
    FIMWorker.stop(),
    ScoreCalculatorWorker.stop(),
    MetricsRetentionWorker.stop(),
    IntelligenceWorker.stop(),
    VulnScannerWorker.stop(),
    BlockCleanupWorker.stop(),
    CVEMonitorWorker.stop(),
    DiscoveryWorker.stop(),
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
