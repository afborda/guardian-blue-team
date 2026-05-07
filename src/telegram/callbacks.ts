import { PlaybookRegistry } from '../playbooks/registry.js';
import { PlaybookEngine, type PlaybookContext } from '../playbooks/engine.js';
import { handleLoginVerification } from './login-verification.js';
import { handleCVECallback } from './cve-actions.js';
import { IncidentMemoryService } from '../services/incident-memory.service.js';
import { FalsePositiveFilter } from '../intelligence/false-positive-filter.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';
import { pendingDiscoveries } from './commands.js';

interface PendingApproval {
  playbookName: string;
  ctx: PlaybookContext;
  createdAt: number;
}

const pendingApprovals = new Map<string, PendingApproval>();

export async function handleTelegramCallback(callbackQuery: {
  id: string;
  data?: string;
  message?: { message_id: number; chat: { id: number } };
  from?: { first_name?: string };
}): Promise<void> {
  if (!callbackQuery.data) return;

  if (callbackQuery.data.startsWith('pb_approve_')) {
    const approvalId = callbackQuery.data.replace('pb_approve_', '');
    await handlePlaybookApproval(approvalId, true, callbackQuery);
    return;
  }

  if (callbackQuery.data.startsWith('pb_reject_')) {
    const approvalId = callbackQuery.data.replace('pb_reject_', '');
    await handlePlaybookApproval(approvalId, false, callbackQuery);
    return;
  }

  if (callbackQuery.data.startsWith('login_')) {
    const rest = callbackQuery.data.replace('login_', '');
    const sep = rest.indexOf('_');
    const action = rest.slice(0, sep);
    const verificationId = rest.slice(sep + 1);
    await handleLoginVerification(action, verificationId, callbackQuery);
    return;
  }

  if (callbackQuery.data.startsWith('cve_')) {
    await handleCVECallback(callbackQuery);
    return;
  }

  if (callbackQuery.data.startsWith('discovery_approve_')) {
    const serverId = parseInt(callbackQuery.data.replace('discovery_approve_', ''));
    const pending = pendingDiscoveries.get(serverId);
    if (!pending) {
      await answerCallback(callbackQuery.id, 'Discovery expirado');
      return;
    }
    pendingDiscoveries.delete(serverId);
    await answerCallback(callbackQuery.id, `Discovery aprovado para ${pending.serverName}`);
    if (callbackQuery.message) {
      await editMessage(callbackQuery.message,
        `✅ Discovery aprovado — <b>${pending.serverName}</b> monitoramento configurado.`);
    }
    return;
  }

  if (callbackQuery.data.startsWith('discovery_cancel_')) {
    const serverId = parseInt(callbackQuery.data.replace('discovery_cancel_', ''));
    pendingDiscoveries.delete(serverId);
    await answerCallback(callbackQuery.id, 'Discovery cancelado');
    if (callbackQuery.message) {
      await editMessage(callbackQuery.message, '❌ Discovery cancelado.');
    }
    return;
  }

  if (callbackQuery.data.startsWith('incident_fp_')) {
    const incidentId = parseInt(callbackQuery.data.replace('incident_fp_', ''));
    await handleIncidentFeedback(incidentId, 'false_positive', callbackQuery);
    return;
  }

  if (callbackQuery.data.startsWith('incident_confirm_')) {
    const incidentId = parseInt(callbackQuery.data.replace('incident_confirm_', ''));
    await handleIncidentFeedback(incidentId, 'resolved', callbackQuery);
    return;
  }

  if (callbackQuery.data.startsWith('incident_monitor_')) {
    const incidentId = parseInt(callbackQuery.data.replace('incident_monitor_', ''));
    await answerCallback(callbackQuery.id, 'Monitorando...');
    if (callbackQuery.message) {
      await editMessage(callbackQuery.message,
        `👁️ Incidente #${incidentId} sendo monitorado. Receberá updates se evoluir.`);
    }
    return;
  }

  if (callbackQuery.data.startsWith('incident_block_')) {
    const parts = callbackQuery.data.replace('incident_block_', '').split('_');
    const incidentId = parseInt(parts[0]);
    const ip = parts.slice(1).join('_');
    await answerCallback(callbackQuery.id, `Bloqueando ${ip}...`);

    const { handleTelegramCommand } = await import('./commands.js');
    const result = await handleTelegramCommand(`/block ${ip}`);

    if (callbackQuery.message) {
      await editMessage(callbackQuery.message,
        `🔒 Incidente #${incidentId} — IP ${ip} bloqueado.\n${result}`);
    }
    return;
  }

  if (callbackQuery.data.startsWith('incident_threat_')) {
    const parts = callbackQuery.data.replace('incident_threat_', '').split('_');
    const ip = parts.slice(1).join('_');
    await answerCallback(callbackQuery.id, `Consultando ${ip}...`);

    const { handleTelegramCommand } = await import('./commands.js');
    const result = await handleTelegramCommand(`/threat ${ip}`);

    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text: result,
        parse_mode: 'HTML',
      }),
    }).catch(() => {});
    return;
  }

  logger.debug(`Unknown callback: ${callbackQuery.data}`);
}

export function requestPlaybookApproval(playbookName: string, ctx: PlaybookContext): void {
  const approvalId = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

  pendingApprovals.set(approvalId, {
    playbookName,
    ctx,
    createdAt: Date.now(),
  });

  const text = [
    `🔒 <b>Playbook Approval Required</b>`,
    ``,
    `📋 <b>${playbookName}</b>`,
    `🖥️ Server: ${ctx.serverName}`,
    `🎯 IP: ${ctx.sourceIp ?? 'n/a'}`,
    `📂 Incident: #${ctx.incidentId ?? 'n/a'}`,
    ``,
    `Aprovar execução?`,
  ].join('\n');

  const keyboard = {
    inline_keyboard: [[
      { text: '✅ Aprovar', callback_data: `pb_approve_${approvalId}` },
      { text: '❌ Rejeitar', callback_data: `pb_reject_${approvalId}` },
    ]],
  };

  fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: config.telegram.chatId,
      text,
      parse_mode: 'HTML',
      reply_markup: keyboard,
    }),
  }).catch(err => logger.error({ err }, 'Failed to send playbook approval request'));

  setTimeout(() => {
    if (pendingApprovals.has(approvalId)) {
      pendingApprovals.delete(approvalId);
      logger.info({ approvalId, playbook: playbookName }, 'Playbook approval expired');
    }
  }, 30 * 60 * 1000);
}

async function handlePlaybookApproval(
  approvalId: string,
  approved: boolean,
  callbackQuery: { id: string; message?: { message_id: number; chat: { id: number } }; from?: { first_name?: string } }
): Promise<void> {
  const pending = pendingApprovals.get(approvalId);

  await answerCallback(callbackQuery.id, approved ? 'Aprovado!' : 'Rejeitado');

  if (!pending) {
    await editMessage(callbackQuery.message, '⏰ Aprovação expirada ou já processada.');
    return;
  }

  pendingApprovals.delete(approvalId);
  const operator = callbackQuery.from?.first_name ?? 'unknown';

  if (!approved) {
    await editMessage(callbackQuery.message, `❌ Playbook <b>${pending.playbookName}</b> rejeitado por ${operator}`);
    return;
  }

  const playbook = PlaybookRegistry.getByName(pending.playbookName);
  if (!playbook) {
    await editMessage(callbackQuery.message, '❌ Playbook não encontrado.');
    return;
  }

  await editMessage(callbackQuery.message, `✅ Playbook <b>${pending.playbookName}</b> aprovado por ${operator}. Executando...`);

  PlaybookEngine.execute(playbook, { ...pending.ctx, triggeredBy: `approval:${operator}` }).catch(err =>
    logger.error({ err, playbook: pending.playbookName }, 'Approved playbook execution failed')
  );
}

async function handleIncidentFeedback(
  incidentId: number,
  outcome: 'false_positive' | 'resolved',
  callbackQuery: { id: string; message?: { message_id: number; chat: { id: number } }; from?: { first_name?: string } }
): Promise<void> {
  const operator = callbackQuery.from?.first_name ?? 'unknown';
  const resolution = outcome === 'false_positive'
    ? `Marcado como falso positivo por ${operator}`
    : `Confirmado como ameaça real por ${operator}`;

  try {
    await IncidentMemoryService.store(incidentId, resolution, outcome);
    FalsePositiveFilter.invalidateCache();

    const emoji = outcome === 'false_positive' ? '🏷️' : '✅';
    const label = outcome === 'false_positive' ? 'FALSO POSITIVO' : 'AMEAÇA CONFIRMADA';

    await answerCallback(callbackQuery.id, label);
    if (callbackQuery.message) {
      await editMessage(callbackQuery.message,
        `${emoji} Incidente #${incidentId} — <b>${label}</b>\nPor: ${operator}\n\n💡 Guardian aprendeu com este feedback.`);
    }

    logger.info({ incidentId, outcome, operator }, 'Incident feedback received via Telegram');
  } catch (err) {
    logger.error({ err, incidentId }, 'Failed to process incident feedback');
    await answerCallback(callbackQuery.id, 'Erro ao processar feedback');
  }
}

export function buildIncidentFeedbackKeyboard(incidentId: number) {
  return {
    inline_keyboard: [[
      { text: '🏷️ Falso Positivo', callback_data: `incident_fp_${incidentId}` },
      { text: '✅ Confirmar', callback_data: `incident_confirm_${incidentId}` },
      { text: '👁️ Monitorar', callback_data: `incident_monitor_${incidentId}` },
    ]],
  };
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
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/editMessageText`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: message.chat.id,
        message_id: message.message_id,
        text,
        parse_mode: 'HTML',
      }),
    });
  } catch (err) {
    logger.debug({ err, messageId: message.message_id }, 'Failed to edit message');
  }
}
