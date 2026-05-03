import { config } from '../../config/environment.js';
import type { PlaybookContext } from '../engine.js';

export async function notify(ctx: PlaybookContext, params?: Record<string, unknown>): Promise<{ success: boolean; message: string }> {
  const severity = (params?.severity as string) ?? 'medium';
  const customMessage = params?.message as string | undefined;

  const severityIcon: Record<string, string> = {
    critical: '🔴', high: '🟠', medium: '🟡', low: '🔵',
  };

  const text = customMessage ?? [
    `${severityIcon[severity] ?? '⚪'} <b>Playbook Alert</b>`,
    `Server: ${ctx.serverName}`,
    `IP: ${ctx.sourceIp ?? 'n/a'}`,
    `Severity: ${severity}`,
  ].join('\n');

  try {
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text,
        parse_mode: 'HTML',
      }),
    });
    return { success: true, message: `Notified (${severity})` };
  } catch {
    return { success: false, message: 'Telegram notification failed' };
  }
}
