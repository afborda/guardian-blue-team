import { NotifierManager } from '../../plugins/notifier-manager.js';
import { buildIncidentFeedbackKeyboard } from '../../telegram/callbacks.js';
import { config } from '../../config/environment.js';
import type { PlaybookContext } from '../engine.js';

export async function notify(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const severity = (params?.severity as string) ?? 'medium';
  const customMessage = params?.message as string | undefined;

  const body = buildNotificationBody(ctx, severity, customMessage);

  try {
    await NotifierManager.notify({
      title: 'Playbook Alert',
      body,
      severity: severity as 'critical' | 'high' | 'medium' | 'low',
      metadata: { server: ctx.serverName, triggeredBy: ctx.triggeredBy },
    });

    if (ctx.incidentId) {
      await sendFeedbackButtons(ctx.incidentId, ctx.serverName, ctx.sourceIp, severity, body);
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

  // Always include structured context
  lines.push(`<b>Servidor:</b> ${ctx.serverName}`);
  if (containerName) lines.push(`<b>Container:</b> ${containerName}`);
  if (ctx.sourceIp) lines.push(`<b>IP origem:</b> <code>${ctx.sourceIp}</code>`);
  if (ctx.incidentId) lines.push(`<b>Incidente:</b> #${ctx.incidentId}`);
  lines.push(`<b>Severidade:</b> ${severityLabel(severity)}`);
  lines.push(`<b>Acionado por:</b> ${ctx.triggeredBy === 'auto' ? 'deteccao automatica' : ctx.triggeredBy}`);

  // Add action guidance based on context
  lines.push('');
  if (isContainerAlert) {
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
  } else if (ctx.sourceIp) {
    lines.push('<b>O que fazer:</b>');
    lines.push(`  /threat ${ctx.sourceIp} — investigar IP`);
    lines.push(`  /block ${ctx.sourceIp} — bloquear manualmente`);
    lines.push(`  /incidents — ver todos os incidentes`);
  } else {
    lines.push(`  /incidents — ver incidentes`);
    lines.push(`  /dashboard — painel completo`);
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

async function sendFeedbackButtons(incidentId: number, serverName: string, sourceIp?: string, severity?: string, bodyPreview?: string): Promise<void> {
  const keyboard = buildIncidentFeedbackKeyboard(incidentId);
  const shortBody = (bodyPreview ?? '').split('\n').slice(0, 2).join('\n');
  const text = [
    `&#128203; <b>Incidente #${incidentId}</b> — Classificar:`,
    `&#128421; ${serverName} | &#127919; ${sourceIp ?? 'n/a'} | &#9888; ${severity}`,
    '',
    `<i>${shortBody}</i>`,
  ].join('\n');

  try {
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text,
        parse_mode: 'HTML',
        reply_markup: keyboard,
      }),
    });
  } catch {
    // Non-critical — feedback buttons are optional
  }
}
