import { NotifierManager } from '../../plugins/notifier-manager.js';
import { buildIncidentFeedbackKeyboard } from '../../telegram/callbacks.js';
import { config } from '../../config/environment.js';
import { logger } from '../../utils/logger.js';
import type { PlaybookContext } from '../engine.js';

export async function notify(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const severity = (params?.severity as string) ?? 'medium';
  const customMessage = params?.message as string | undefined;

  const body = buildNotificationBody(ctx, severity, customMessage);

  try {
    if (ctx.incidentId) {
      // Single message: alert body + inline action buttons. Replaces the
      // previous "alert + separate classify message" pair so each incident
      // costs one notification, not two.
      await sendCombinedAlert(ctx.incidentId, ctx.serverName, ctx.sourceIp, severity, body);
    } else {
      // No incident — fall back to the plugin notifier (Slack/Discord/etc.).
      await NotifierManager.notify({
        title: 'Playbook Alert',
        body,
        severity: severity as 'critical' | 'high' | 'medium' | 'low',
        metadata: { server: ctx.serverName, triggeredBy: ctx.triggeredBy },
      });
    }

    return { success: true, message: `Notified (${severity})` };
  } catch {
    return { success: false, message: 'Notification failed' };
  }
}

function buildNotificationBody(ctx: PlaybookContext, severity: string, customMessage?: string): string {
  const containerName = ctx.variables['containerName'] as string | undefined;
  const isContainerAlert = !!containerName;

  const lines: string[] = [];

  if (customMessage) {
    lines.push(customMessage);
    lines.push('');
  }

  lines.push(`🚨 <b>Playbook Alert</b>`);
  lines.push('');
  lines.push(`<b>Servidor:</b> ${ctx.serverName}`);
  if (containerName) lines.push(`<b>Container:</b> ${containerName}`);
  if (ctx.sourceIp) lines.push(`<b>IP origem:</b> <code>${ctx.sourceIp}</code>`);
  if (ctx.incidentId) lines.push(`<b>Incidente:</b> #${ctx.incidentId}`);
  lines.push(`<b>Severidade:</b> ${severityLabel(severity)}`);
  lines.push(`<b>Acionado por:</b> ${ctx.triggeredBy === 'auto' ? 'deteccao automatica' : ctx.triggeredBy}`);

  // Container alerts still need text guidance — they don't have IP-based
  // action buttons. IP alerts get the buttons via the inline keyboard, so
  // we strip the redundant "/threat ... — investigar IP" instructions.
  if (isContainerAlert) {
    lines.push('');
    lines.push('<b>O que fazer:</b>');
    lines.push(`  /incidents — ver detalhes do incidente`);
    lines.push(`  /dashboard — abrir painel com acoes visuais`);
    if (customMessage?.includes('killed') || customMessage?.includes('restarted') || customMessage?.includes('reinici')) {
      lines.push(`  &#8594; Guardian ja tomou acao automatica`);
      lines.push(`  &#8594; Verifique se o container voltou saudavel`);
    } else if (customMessage?.includes('investigate') || customMessage?.includes('Investig')) {
      lines.push(`  &#8594; Investigue manualmente antes de agir`);
      lines.push(`  &#8594; No dashboard: botoes de Kill/Isolar/Reiniciar`);
    }
  }

  return lines.join('\n');
}

function severityLabel(severity: string): string {
  switch (severity) {
    case 'critical': return '&#128308; CRITICO';
    case 'high': return '&#128992; ALTO';
    case 'medium': return '&#128993; MEDIO';
    case 'low': return '&#128309; BAIXO';
    default: return severity;
  }
}

async function sendCombinedAlert(
  incidentId: number,
  _serverName: string,
  sourceIp: string | undefined,
  _severity: string,
  body: string,
): Promise<void> {
  const keyboard = buildIncidentFeedbackKeyboard(incidentId, sourceIp);

  try {
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text: body,
        parse_mode: 'HTML',
        reply_markup: keyboard,
      }),
    });
  } catch (err) {
    logger.warn({ err, incidentId }, 'Failed to send combined alert');
  }
}
