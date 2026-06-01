import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { config } from './config/environment.js';
import { logger } from './utils/logger.js';
import { AuditLogger } from './utils/audit-logger.js';
import { testConnection, closeConnection, initDatabase } from './database/connection.js';
import { DailyReportWorker } from './workers/daily-report.worker.js';
import { EventCollectorWorker } from './workers/event-collector.worker.js';
import { VulnScannerWorker } from './workers/vuln-scanner.worker.js';
import { BlockCleanupWorker } from './workers/block-cleanup.worker.js';
import { BlockPropagationWorker } from './workers/block-propagation.worker.js';
import { BlockReconcileWorker } from './workers/block-reconcile.worker.js';
import { CVEMonitorWorker } from './workers/cve-monitor.worker.js';
import { CVEIntelFeedsWorker } from './workers/cve-intel-feeds.worker.js';
import { ScoreCalculatorWorker } from './workers/score-calculator.worker.js';
import { MetricsRetentionWorker } from './workers/metrics-retention.worker.js';
import { IntelligenceWorker } from './workers/intelligence.worker.js';
import { FIMWorker } from './workers/fim.worker.js';
import { DiscoveryWorker } from './workers/discovery.worker.js';
import { ThreatHunterWorker } from './workers/threat-hunter.worker.js';
import { DDoSEscalationWorker } from './workers/ddos-escalation.worker.js';
import { ContainerSecurityWorker } from './workers/container-security.worker.js';
import { IpThreatScorerWorker } from './workers/ip-threat-scorer.worker.js';
import { LegacyMigrationWorker } from './workers/legacy-migration.worker.js';
import { ThreatIntelManager } from './threat-intel/manager.js';
import { PlaybookRegistry } from './playbooks/registry.js';
import { loadTrustedEntities } from './pipeline/detector.js';
import { handleTelegramCommand } from './telegram/commands.js';
import { handleTelegramCallback } from './telegram/callbacks.js';
import { registerBuiltinPlugins, PluginManager } from './plugins/index.js';
import { dashboardPages, dashboardApi } from './dashboard/routes.js';
import { dashboardAuth } from './dashboard/auth.js';
import { AIProvider } from './services/ai-provider.js';
import { CONSTANTS } from './config/constants.js';
import { safeCompare } from './utils/sanitize.js';
import { rateLimiter } from './middleware/rate-limiter.js';
import { falcoWebhookHandler } from './falco/webhook.js';

const app = express();
app.use(express.json());

const APP_VERSION = ((): string => {
  try {
    const pkgPath = fileURLToPath(new URL('../package.json', import.meta.url));
    const { version } = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string };
    return typeof version === 'string' && version.length > 0 ? version : 'unknown';
  } catch {
    return 'unknown';
  }
})();

// ─── Dashboard ──────────────────────────────────────────────────────────────

app.use('/dashboard', rateLimiter(60), dashboardAuth, dashboardPages);
app.use('/api/dashboard', rateLimiter(60), dashboardAuth, dashboardApi);

// ─── Health ─────────────────────────────────────────────────────────────────

app.get('/health', async (req, res) => {
  // Public probe: minimal response suitable for uptime monitors (no sensitive data)
  const token = (req.query.token as string) ?? req.headers['x-dashboard-token'];
  const authed = token && config.dashboard.token && safeCompare(token as string, config.dashboard.token);

  if (!authed) {
    res.status(200).json({ status: 'ok' });
    return;
  }

  const dbOk = await testConnection().catch(() => false);
  const status = dbOk ? 'ok' : 'degraded';
  const code = dbOk ? 200 : 503;
  res.status(code).json({
    status,
    uptime: Math.floor(process.uptime()),
    database: dbOk ? 'connected' : 'unreachable',
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
  // Fail-closed: sem secret configurado, rota não autentica nada — recusa todos
  // os requests para evitar exposição anônima do handler de comandos do bot.
  if (!config.telegram.webhookSecret) {
    res.status(503).json({ error: 'webhook_not_configured' });
    return;
  }
  const token = req.headers['x-telegram-bot-api-secret-token'];
  if (!token || !safeCompare(String(token), config.telegram.webhookSecret)) {
    res.status(401).json({ error: 'unauthorized' });
    return;
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

// ─── Falco Webhook ──────────────────────────────────────────────────────────
// Runtime syscall events from `guardian-falco` agents on monitored hosts.
// Limit 120/min: Falco can burst when a chain of related syscalls fires.
app.post('/webhook/falco', rateLimiter(120), falcoWebhookHandler);

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

  try {
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/setMyCommands`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        commands: [
          { command: 'status', description: 'Resumo de todos os servidores' },
          { command: 'incidents', description: 'Incidentes abertos (com ações)' },
          { command: 'dashboard', description: 'URL do dashboard (token temporário)' },
          { command: 'events', description: 'Últimos eventos de segurança' },
          { command: 'health', description: 'CPU, RAM, disco' },
          { command: 'scores', description: 'Pontuação de segurança' },
          { command: 'threat', description: 'Investigar IP (reputação)' },
          { command: 'block', description: 'Bloquear IP no firewall' },
          { command: 'ask', description: 'Pergunte qualquer coisa à AI' },
          { command: 'report', description: 'Relatório de segurança' },
          { command: 'vulns', description: 'Vulnerabilidades CVE' },
          { command: 'versions', description: 'Versões de runtimes (Node, Docker, nginx…)' },
          { command: 'servers', description: 'Servidores monitorados' },
          { command: 'help', description: 'Todos os comandos disponíveis' },
        ],
      }),
    });
  } catch (_) {}
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
  await loadTrustedEntities();

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
  BlockPropagationWorker.start();
  BlockReconcileWorker.start();
  DiscoveryWorker.start();
  ThreatHunterWorker.start();
  DDoSEscalationWorker.start();
  ContainerSecurityWorker.start();
  IpThreatScorerWorker.start();
  LegacyMigrationWorker.start();
  startHeartbeat();

  if (config.cveMonitor.enabled) {
    CVEMonitorWorker.start();
  }

  if (config.cveIntelFeeds.enabled) {
    CVEIntelFeedsWorker.start();
  }

  logger.info('All workers started');
  AIProvider.warmUpOllama();
  AuditLogger.operational(null, 'guardian_start', 'success', { version: APP_VERSION }).catch(() => {});
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
    BlockPropagationWorker.stop(),
    BlockReconcileWorker.stop(),
    CVEMonitorWorker.stop(),
    CVEIntelFeedsWorker.stop(),
    DiscoveryWorker.stop(),
    ThreatHunterWorker.stop(),
    DDoSEscalationWorker.stop(),
    IpThreatScorerWorker.stop(),
    LegacyMigrationWorker.stop(),
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
