import { PlaybookRegistry } from '../playbooks/registry.js';
import { PlaybookEngine, type PlaybookContext } from '../playbooks/engine.js';
import { handleLoginVerification } from './login-verification.js';
import { handleCVECallback } from './cve-actions.js';
import { IncidentMemoryService } from '../services/incident-memory.service.js';
import { FalsePositiveFilter } from '../intelligence/false-positive-filter.js';
import { logger } from '../utils/logger.js';
import { telegram } from './messaging/sender.js';
import { buildApprovalResolvedSpec, buildApprovalSpec } from './copy/approval.js';
import { playbookCopy } from './copy/playbook.js';
import { IncidentAlertService } from '../services/incident-alert.service.js';
import type { MessageSpec } from './messaging/types.js';
import { pendingDiscoveries, pendingReadiness } from './commands.js';
import { ServerReadinessService } from '../services/server-readiness.service.js';
import { syncBlocksToServer } from '../playbooks/actions/block-ip.js';

interface PendingApproval {
  playbookName: string;
  ctx: PlaybookContext;
  createdAt: number;
  expiresAt: number;
  spec?: MessageSpec;
  messageId?: number;
  chatId?: string;
}

const pendingApprovals = new Map<string, PendingApproval>();
const threatReportSentAt = new Map<string, number>();
const THREAT_REPORT_COOLDOWN_MS = 30 * 60 * 1000;

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
    const operator = callbackQuery.from?.first_name ?? 'operador';
    await answerCallback(callbackQuery.id, 'Monitorando');
    const edited = await IncidentAlertService.markResolved(incidentId, 'monitoring', operator);
    if (!edited && callbackQuery.message) {
      await editMessage(callbackQuery.message,
        `Incidente #${incidentId} em monitoramento por ${operator}.`);
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
    const already = result.includes('já estava bloqueado') || result.includes('already blocked');
    const failed = !already && /falha|erro|failed|não foi possível/i.test(result);
    const label = failed
      ? `Tentei bloquear ${ip}, mas o firewall recusou. Veja os logs do Guardian.`
      : already
        ? `O IP ${ip} já estava bloqueado; nada novo foi feito.`
        : `IP ${ip} bloqueado agora.`;

    const edited = await IncidentAlertService.attachOutcome(incidentId, {
      label,
      kind: failed ? 'failed' : 'blocked',
      ip,
    });
    if (!edited && callbackQuery.message) {
      await editMessage(callbackQuery.message, label);
    }
    return;
  }

  if (callbackQuery.data.startsWith('incident_unblock_')) {
    const parts = callbackQuery.data.replace('incident_unblock_', '').split('_');
    const incidentId = parseInt(parts[0]);
    const ip = parts.slice(1).join('_');
    await answerCallback(callbackQuery.id, `Desbloqueando ${ip}...`);

    const { handleTelegramCommand } = await import('./commands.js');
    const result = await handleTelegramCommand(`/unblock ${ip}`);
    const failed = /falha|erro|failed|não foi possível/i.test(result);
    const label = failed
      ? `Tentei desbloquear ${ip}, mas o firewall recusou. Veja os logs do Guardian.`
      : `IP ${ip} removido da lista de bloqueio.`;

    const edited = await IncidentAlertService.attachOutcome(incidentId, {
      label,
      kind: failed ? 'failed' : 'unblocked',
      ip,
    });
    if (!edited && callbackQuery.message) {
      await editMessage(callbackQuery.message, label);
    }
    return;
  }

  if (callbackQuery.data.startsWith('incident_threat_')) {
    const parts = callbackQuery.data.replace('incident_threat_', '').split('_');
    const ip = parts.slice(1).join('_');
    const lastThreat = threatReportSentAt.get(ip) ?? 0;
    if (Date.now() - lastThreat < THREAT_REPORT_COOLDOWN_MS) {
      await answerCallback(callbackQuery.id, 'Relatório desse IP já foi enviado há pouco.');
      return;
    }
    threatReportSentAt.set(ip, Date.now());
    await answerCallback(callbackQuery.id, `Consultando ${ip}...`);

    const { handleTelegramCommand } = await import('./commands.js');
    const result = await handleTelegramCommand(`/threat ${ip}`);

    await telegram.sendText(result);
    return;
  }

  logger.debug(`Unknown callback: ${callbackQuery.data}`);
}

export function requestPlaybookApproval(playbookName: string, ctx: PlaybookContext): void {
  const approvalId = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const expiresAt = new Date(Date.now() + 30 * 60_000);
  const copy = playbookCopy(playbookName);
  const containerName = ctx.variables?.['containerName'] as string | undefined;

  const spec = buildApprovalSpec({
    approvalId,
    playbookName,
    serverName: ctx.serverName,
    sourceIp: ctx.sourceIp,
    containerName,
    incidentId: ctx.incidentId,
    actionTitle: copy.actionTitle,
    impact: copy.impact,
    steps: copy.steps,
    expiresAt,
  });

  const pending: PendingApproval = {
    playbookName,
    ctx,
    createdAt: Date.now(),
    expiresAt: expiresAt.getTime(),
    spec,
  };
  pendingApprovals.set(approvalId, pending);

  void telegram.sendSpec(spec).then(result => {
    if (result.ok && result.messageId && result.chatId) {
      pending.messageId = result.messageId;
      pending.chatId = result.chatId;
    } else {
      logger.warn({ approvalId, playbook: playbookName, error: result.error }, 'Falha ao enviar pedido de aprovação');
    }
  }).catch(err => logger.warn({ err, approvalId }, 'Falha ao enviar pedido de aprovação'));

  setTimeout(() => {
    const current = pendingApprovals.get(approvalId);
    if (!current) return;
    pendingApprovals.delete(approvalId);

    if (current.chatId && current.messageId && current.spec) {
      const expired: MessageSpec = {
        ...current.spec,
        title: 'Pedido expirado',
        severity: 'low',
        action: {
          required: false,
          title: 'Resultado',
          steps: ['Ninguém respondeu em 30 minutos. Nada foi executado.'],
        },
        buttons: [],
      };
      void telegram.editSpec(current.chatId, current.messageId, expired);
    }
    logger.info({ approvalId, playbook: playbookName }, 'Playbook approval expired');
  }, 30 * 60 * 1000);
}

async function handlePlaybookApproval(
  approvalId: string,
  approved: boolean,
  callbackQuery: { id: string; message?: { message_id: number; chat: { id: number } }; from?: { first_name?: string } }
): Promise<void> {
  const pending = pendingApprovals.get(approvalId);
  await answerCallback(callbackQuery.id, approved ? 'Aprovado' : 'Rejeitado');

  if (!pending) {
    await editMessage(callbackQuery.message, '⏰ Pedido expirado ou já processado. Nada foi executado.');
    return;
  }

  pendingApprovals.delete(approvalId);
  const operator = callbackQuery.from?.first_name ?? 'operador';

  if (!approved) {
    if (pending.chatId && pending.messageId && pending.spec) {
      await telegram.editSpec(pending.chatId, pending.messageId, buildApprovalResolvedSpec(pending.spec, false, operator));
    } else {
      await editMessage(callbackQuery.message, `Ação <b>${pending.playbookName}</b> rejeitada por ${operator}. Nada foi executado.`);
    }
    return;
  }

  const playbook = PlaybookRegistry.getByName(pending.playbookName);
  if (!playbook) {
    await editMessage(callbackQuery.message, 'Playbook não encontrado. Nada foi executado.');
    return;
  }

  let detail = 'Executado com sucesso.';
  try {
    const result = await PlaybookEngine.execute(playbook, { ...pending.ctx, triggeredBy: `approval:${operator}` });
    if (!result.success) detail = 'A execução falhou; veja os logs do Guardian.';
  } catch (err) {
    logger.error({ err, playbook: pending.playbookName }, 'Approved playbook execution failed');
    detail = 'A execução falhou; veja os logs do Guardian.';
  }

  if (pending.chatId && pending.messageId && pending.spec) {
    await telegram.editSpec(pending.chatId, pending.messageId, buildApprovalResolvedSpec(pending.spec, true, operator, detail));
  } else {
    await editMessage(callbackQuery.message, `Ação aprovada por ${operator}. ${detail}`);
  }
}

async function handleIncidentFeedback(
  incidentId: number,
  outcome: 'false_positive' | 'resolved',
  callbackQuery: { id: string; message?: { message_id: number; chat: { id: number } }; from?: { first_name?: string } }
): Promise<void> {
  const operator = callbackQuery.from?.first_name ?? 'operador';
  const resolution = outcome === 'false_positive'
    ? `Marcado como falso positivo por ${operator}`
    : `Confirmado como ameaça real por ${operator}`;

  try {
    await IncidentMemoryService.store(incidentId, resolution, outcome);
    FalsePositiveFilter.invalidateCache();

    const label = outcome === 'false_positive' ? 'Falso positivo' : 'Ameaça confirmada';
    await answerCallback(callbackQuery.id, label);

    const edited = await IncidentAlertService.markResolved(
      incidentId,
      outcome === 'false_positive' ? 'false_positive' : 'confirmed',
      operator,
    );
    if (!edited && callbackQuery.message) {
      await editMessage(callbackQuery.message, `Incidente #${incidentId} — ${label} por ${operator}.`);
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
  await telegram.answer(callbackId, text);
}

async function editMessage(message: { message_id: number; chat: { id: number } } | undefined, text: string): Promise<void> {
  if (!message) return;
  await telegram.editText(message.chat.id, message.message_id, text);
}
