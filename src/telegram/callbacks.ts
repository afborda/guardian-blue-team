import { PlaybookRegistry } from '../playbooks/registry.js';
import { PlaybookEngine, type PlaybookContext } from '../playbooks/engine.js';
import { handleLoginVerification } from './login-verification.js';
import { handleCVECallback } from './cve-actions.js';
import { IncidentMemoryService } from '../services/incident-memory.service.js';
import { FalsePositiveFilter } from '../intelligence/false-positive-filter.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';
import { pendingDiscoveries, pendingReadiness } from './commands.js';
import { ServerReadinessService } from '../services/server-readiness.service.js';
import { syncBlocksToServer } from '../playbooks/actions/block-ip.js';

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

  if (callbackQuery.data.startsWith('readiness_install_')) {
    const serverId = parseInt(callbackQuery.data.replace('readiness_install_', ''));
    const pending = pendingReadiness.get(serverId);
    if (!pending) {
      await answerCallback(callbackQuery.id, 'Expirado');
      return;
    }
    pendingReadiness.delete(serverId);
    await answerCallback(callbackQuery.id, 'Instalando...');

    if (callbackQuery.message) {
      await editMessage(callbackQuery.message, `⏳ Instalando ${pending.missing.length} ferramenta(s) em <b>${pending.serverName}</b>...`);
    }

    const result = await ServerReadinessService.install(pending.target, pending.missing);

    let msg = `🛠️ <b>${pending.serverName}</b> — instalação concluída\n\n`;
    if (result.success.length > 0) msg += `✅ Instalados: ${result.success.join(', ')}\n`;
    if (result.failed.length > 0) msg += `❌ Falharam: ${result.failed.join(', ')}\n`;

    const synced = await syncBlocksToServer(serverId);
    if (synced > 0) msg += `\n🔒 ${synced} IPs bloqueados sincronizados.`;

    if (callbackQuery.message) {
      await editMessage(callbackQuery.message, msg);
    }
    return;
  }

  if (callbackQuery.data.startsWith('readiness_skip_')) {
    const serverId = parseInt(callbackQuery.data.replace('readiness_skip_', ''));
    pendingReadiness.delete(serverId);
    await answerCallback(callbackQuery.id, 'Pulado');

    // Still sync blocks even if skipping tool installation
    const synced = await syncBlocksToServer(serverId);
    const syncMsg = synced > 0 ? `\n🔒 ${synced} IPs bloqueados sincronizados.` : '';

    if (callbackQuery.message) {
      await editMessage(callbackQuery.message, `⏭️ Instalação pulada.${syncMsg}\n⚠️ Algumas coletas podem falhar sem as ferramentas.`);
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

  const containerName = ctx.variables?.['containerName'] as string | undefined;
  const actionDescription = describePlaybookAction(playbookName, ctx);

  const text = [
    `&#128274; <b>Aprovacao Necessaria</b>`,
    ``,
    `<b>Playbook:</b> ${playbookName}`,
    `<b>Servidor:</b> ${ctx.serverName}`,
    containerName ? `<b>Container:</b> ${containerName}` : null,
    ctx.sourceIp ? `<b>IP:</b> <code>${ctx.sourceIp}</code>` : null,
    ctx.incidentId ? `<b>Incidente:</b> #${ctx.incidentId}` : null,
    ``,
    `<b>O que vai acontecer se aprovado:</b>`,
    actionDescription,
    ``,
    `&#9888; <i>Expira em 30 minutos se nao responder.</i>`,
  ].filter(Boolean).join('\n');

  const keyboard = {
    inline_keyboard: [[
      { text: '✅ Aprovar e Executar', callback_data: `pb_approve_${approvalId}` },
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

function describePlaybookAction(playbookName: string, ctx: PlaybookContext): string {
  const containerName = ctx.variables?.['containerName'] as string | undefined;

  switch (playbookName) {
    case 'container-auto-update':
      return [
        `  1. Baixar ultima versao da imagem Docker`,
        `  2. Recriar o container${containerName ? ` '${containerName}'` : ''}`,
        `  3. Notificar conclusao`,
        `  &#9888; O container tera ~10s de downtime durante recriacao`,
      ].join('\n');

    case 'container-fs-tampering-response':
      return [
        `  1. Notificar sobre arquivo suspeito`,
        `  &#8594; Nenhuma acao destrutiva automatica`,
        `  &#8594; Investigue manualmente no dashboard`,
      ].join('\n');

    case 'container-escape-response':
      return [
        `  1. Pausar o container (congela execucao)`,
        `  2. Desconectar todas as redes`,
        `  3. Notificar sobre tentativa de escape`,
        `  &#9888; O container ficara inacessivel ate acao manual`,
      ].join('\n');

    case 'suspicious-process':
      return [
        `  1. Notificar sobre processo suspeito`,
        `  &#8594; Acao manual necessaria`,
        `  &#8594; Use /incidents para detalhes`,
      ].join('\n');

    case 'file-integrity-response':
      return [
        `  1. Alerta critico sobre arquivo modificado`,
        `  &#8594; Nenhuma acao automatica`,
        `  &#8594; Investigue imediatamente: pode ser backdoor`,
      ].join('\n');

    default:
      return `  &#8594; Executar playbook '${playbookName}' no servidor ${ctx.serverName}`;
  }
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

export function buildIncidentFeedbackKeyboard(incidentId: number, sourceIp?: string) {
  const rows: Array<Array<{ text: string; callback_data: string }>> = [];

  // Action row only when we have an IP — these buttons replace the
  // text-instructions ("/threat <ip> — investigar IP") that the body used to
  // print. One tap, no copy-paste.
  if (sourceIp) {
    rows.push([
      { text: '🔍 Investigar IP', callback_data: `incident_threat_${incidentId}_${sourceIp}` },
      { text: '🔒 Bloquear IP', callback_data: `incident_block_${incidentId}_${sourceIp}` },
    ]);
  }

  // Feedback row — feeds the false-positive filter learning loop.
  rows.push([
    { text: '🏷️ Falso Positivo', callback_data: `incident_fp_${incidentId}` },
    { text: '✅ Confirmar', callback_data: `incident_confirm_${incidentId}` },
    { text: '👁️ Monitorar', callback_data: `incident_monitor_${incidentId}` },
  ]);

  return { inline_keyboard: rows };
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
