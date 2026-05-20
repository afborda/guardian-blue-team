import { config } from '../config/environment.js';
import { addTrustedIp, addTrustedFingerprint } from '../pipeline/detector.js';
import { ThreatIntelManager } from '../threat-intel/manager.js';
import { db, dbNow } from '../database/connection.js';
import { socIncidents, trustedEntities } from '../database/schema.js';
import { eq } from 'drizzle-orm';
import { secureId } from '../utils/sanitize.js';
import { logger } from '../utils/logger.js';

interface PendingVerification {
  incidentId: number;
  sourceIp: string;
  userName: string;
  serverName: string;
  authMethod: string;
  fingerprint: string | null;
  timestamp: Date;
}

const pendingVerifications = new Map<string, PendingVerification>();
const processedCallbacks = new Set<string>();

export function requestLoginVerification(data: {
  incidentId: number;
  sourceIp: string;
  userName: string;
  serverName: string;
  authMethod: string;
  fingerprint: string | null;
  timestamp: Date;
}): void {
  const verificationId = secureId();

  pendingVerifications.set(verificationId, data);

  const brtTime = data.timestamp.toLocaleString('pt-BR', {
    timeZone: 'America/Sao_Paulo',
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit',
  });

  const methodLabel = data.authMethod === 'publickey' ? '🔑 Chave pública' : '🔓 Senha';

  // Enrich IP in background and send message with geo/reputation
  ThreatIntelManager.lookupIP(data.sourceIp).then(report => {
    const lines = [
      `🔐 <b>Login SSH — Verificação</b>`,
      ``,
      `🖥️ Servidor: <b>${data.serverName}</b>`,
      `👤 Usuário: <code>${data.userName}</code>`,
      `🌐 IP: <code>${data.sourceIp}</code>`,
      `${methodLabel}`,
    ];

    if (report) {
      const riskLabel = report.score >= 80 ? '🔴 ALTO RISCO' : report.score >= 40 ? '🟡 Suspeito' : '🟢 Limpo';
      lines.push(``);
      lines.push(`📍 <b>${report.country}</b> | ${report.isp}`);
      lines.push(`⚠️ Reputação: ${riskLabel} (${report.score}/100, ${report.totalReports} reports)`);
      if (report.usageType && report.usageType !== 'unknown') {
        lines.push(`🏷️ Tipo: ${report.usageType}`);
      }
    }

    if (data.fingerprint) {
      lines.push(`🔏 <code>${data.fingerprint}</code>`);
    }

    lines.push(`🕐 ${brtTime} BRT`, ``, `<b>Foi você?</b>`);

    const keyboard = {
      inline_keyboard: [[
        { text: '✅ Sou eu', callback_data: `login_yes_${verificationId}` },
        { text: '❌ NÃO sou eu', callback_data: `login_no_${verificationId}` },
        { text: '👁️ Monitorar', callback_data: `login_watch_${verificationId}` },
      ]],
    };

    fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text: lines.join('\n'),
        parse_mode: 'HTML',
        reply_markup: keyboard,
      }),
    }).catch(err => logger.error({ err }, 'Failed to send login verification'));
  }).catch(() => {
    // Fallback: send without enrichment
    const lines = [
      `🔐 <b>Login SSH — Verificação</b>`,
      ``,
      `🖥️ Servidor: <b>${data.serverName}</b>`,
      `👤 Usuário: <code>${data.userName}</code>`,
      `🌐 IP: <code>${data.sourceIp}</code>`,
      `${methodLabel}`,
    ];

    if (data.fingerprint) {
      lines.push(`🔏 <code>${data.fingerprint}</code>`);
    }

    lines.push(`🕐 ${brtTime} BRT`, ``, `<b>Foi você?</b>`);

    const keyboard = {
      inline_keyboard: [[
        { text: '✅ Sou eu', callback_data: `login_yes_${verificationId}` },
        { text: '❌ NÃO sou eu', callback_data: `login_no_${verificationId}` },
        { text: '👁️ Monitorar', callback_data: `login_watch_${verificationId}` },
      ]],
    };

    fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text: lines.join('\n'),
        parse_mode: 'HTML',
        reply_markup: keyboard,
      }),
    }).catch(err => logger.error({ err }, 'Failed to send login verification'));
  });

  setTimeout(() => {
    pendingVerifications.delete(verificationId);
  }, 30 * 60 * 1000);
}

export async function handleLoginVerification(
  action: string,
  verificationId: string,
  callbackQuery: {
    id: string;
    message?: { message_id: number; chat: { id: number } };
    from?: { first_name?: string };
  },
): Promise<void> {
  // Prevent duplicate processing (Telegram can send same callback multiple times)
  const callbackKey = `${verificationId}:${action}`;
  if (processedCallbacks.has(callbackKey)) {
    await answerCallback(callbackQuery.id, 'Já processado');
    return;
  }
  processedCallbacks.add(callbackKey);
  setTimeout(() => processedCallbacks.delete(callbackKey), 5 * 60_000);

  const pending = pendingVerifications.get(verificationId);

  const labels: Record<string, string> = { yes: 'Confirmado!', no: 'Escalado!', watch: 'Monitorando' };
  await answerCallback(callbackQuery.id, labels[action] ?? 'OK');

  if (!pending) {
    await editMessage(callbackQuery.message, '⏰ Verificação expirada ou já processada.');
    return;
  }

  // Delete BEFORE processing to prevent race conditions
  pendingVerifications.delete(verificationId);
  const operator = callbackQuery.from?.first_name ?? 'unknown';

  if (action === 'yes') {
    addTrustedIp(pending.sourceIp);
    db.insert(trustedEntities).values({ entityType: 'ip', value: pending.sourceIp, addedBy: operator })
      .onConflictDoNothing().catch(err => logger.error({ err }, 'Failed to persist trusted IP'));

    if (pending.fingerprint) {
      const hashPart = pending.fingerprint.includes(' ')
        ? pending.fingerprint.split(' ')[1]
        : pending.fingerprint;
      addTrustedFingerprint(hashPart);
      db.insert(trustedEntities).values({ entityType: 'fingerprint', value: hashPart, addedBy: operator })
        .onConflictDoNothing().catch(err => logger.error({ err }, 'Failed to persist trusted fingerprint'));
    }
    await db.update(socIncidents)
      .set({ status: 'resolved', resolvedAt: dbNow() })
      .where(eq(socIncidents.id, pending.incidentId));

    const msg = [`✅ Confirmado por ${operator}.`, `IP <code>${pending.sourceIp}</code> adicionado à whitelist.`];
    if (pending.fingerprint) msg.push(`Fingerprint também confiável.`);
    await editMessage(callbackQuery.message, msg.join('\n'));
    logger.info({ ip: pending.sourceIp, fingerprint: pending.fingerprint, operator }, 'Login confirmed as legitimate');
    return;
  }

  if (action === 'no') {
    await db.update(socIncidents)
      .set({ severity: 'critical' })
      .where(eq(socIncidents.id, pending.incidentId));

    await editMessage(callbackQuery.message,
      `🚨 <b>INTRUSÃO REPORTADA</b> por ${operator}!\n` +
      `IP: <code>${pending.sourceIp}</code> em <b>${pending.serverName}</b>\n` +
      `Incidente #${pending.incidentId} escalado para CRITICAL.`
    );
    logger.warn({ ip: pending.sourceIp, incidentId: pending.incidentId, operator }, 'Login reported as unauthorized intrusion');
    return;
  }

  // watch
  await editMessage(callbackQuery.message,
    `👁️ Monitorando — ${operator}\n` +
    `IP: <code>${pending.sourceIp}</code> | Incidente #${pending.incidentId} aberto.`
  );
  logger.info({ ip: pending.sourceIp, incidentId: pending.incidentId }, 'Login set to monitor');
}

async function answerCallback(callbackId: string, text: string): Promise<void> {
  try {
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ callback_query_id: callbackId, text }),
    });
  } catch (err) {
    logger.debug({ err }, 'Failed to answer callback query');
  }
}

async function editMessage(message: { message_id: number; chat: { id: number } } | undefined, text: string): Promise<void> {
  if (!message) return;
  try {
    // Remove inline keyboard (buttons) when editing to prevent further clicks
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/editMessageText`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: message.chat.id,
        message_id: message.message_id,
        text,
        parse_mode: 'HTML',
        reply_markup: { inline_keyboard: [] },
      }),
    });
  } catch (err) {
    logger.debug({ err, messageId: message.message_id }, 'Failed to edit message');
  }
}
