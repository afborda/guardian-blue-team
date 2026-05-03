import { NotifierManager } from '../../plugins/notifier-manager.js';
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
    return { success: true, message: `Notified (${severity})` };
  } catch {
    return { success: false, message: 'Notification failed' };
  }
}
