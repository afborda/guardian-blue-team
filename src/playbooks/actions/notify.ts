import { NotifierManager } from '../../plugins/notifier-manager.js';
import { buildIncidentFeedbackKeyboard } from '../../telegram/callbacks.js';
import { config } from '../../config/environment.js';
import type { PlaybookContext } from '../engine.js';

export async function notify(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const severity = (params?.severity as string) ?? 'medium';
  const customMessage = params?.message as string | undefined;

  const body = customMessage ?? [
    `Server: ${ctx.serverName}`,
    `IP: ${ctx.sourceIp ?? 'n/a'}`,
    `Severity: ${severity}`,
  ].join('\n');

  try {
    await NotifierManager.notify({
      title: 'Playbook Alert',
      body,
      severity: severity as 'critical' | 'high' | 'medium' | 'low',
      metadata: { server: ctx.serverName, triggeredBy: ctx.triggeredBy },
    });

    if (ctx.incidentId) {
      await sendFeedbackButtons(ctx.incidentId, ctx.serverName, ctx.sourceIp, severity);
    }

    return { success: true, message: `Notified (${severity})` };
  } catch {
    return { success: false, message: 'Notification failed' };
  }
}

async function sendFeedbackButtons(incidentId: number, serverName: string, sourceIp?: string, severity?: string): Promise<void> {
  const keyboard = buildIncidentFeedbackKeyboard(incidentId);
  const text = [
    `📋 <b>Incidente #${incidentId}</b> — Como classificar?`,
    `🖥️ ${serverName} | 🎯 ${sourceIp ?? 'n/a'} | ⚠️ ${severity}`,
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
