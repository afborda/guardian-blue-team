import type { FormattedAlert, InteractiveAction, CallbackResult, NotifierPlugin } from '../../plugins/types.js';
import { telegram } from '../../telegram/messaging/sender.js';
import { config } from '../../config/environment.js';

/**
 * Notificador do Telegram. Todo envio passa pelo `TelegramSender`, que cuida
 * de escape, chunking, retry e dry-run. Quando a mensagem tem `spec`, o
 * renderer estruturado assume; caso contrário, mantém o formato legado.
 */
export class TelegramNotifier implements NotifierPlugin {
  name = 'telegram';
  enabled = false;
  interactive = true;

  async init(): Promise<void> {
    this.enabled = !!(config.telegram.botToken && config.telegram.chatId);
  }

  async send(alert: FormattedAlert) {
    if (alert.spec) {
      return telegram.sendSpec(alert.spec);
    }

    const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
    const icon = severityIcon[alert.severity] ?? '⚪';
    return telegram.sendText(`${icon} <b>${alert.title}</b>\n\n${alert.body}`);
  }

  async sendInteractive(alert: FormattedAlert, actions: InteractiveAction[]) {
    if (alert.spec) {
      return telegram.sendSpec(alert.spec);
    }

    const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
    const icon = severityIcon[alert.severity] ?? '⚪';
    const buttons = actions.map(action => ({
      text: action.style === 'approve' ? `✅ ${action.label}` : action.style === 'reject' ? `❌ ${action.label}` : `📋 ${action.label}`,
      callback_data: action.id,
    }));

    return telegram.sendText(`${icon} <b>${alert.title}</b>\n\n${alert.body}`, {
      replyMarkup: { inline_keyboard: [buttons] },
    });
  }

  async handleCallback(_source: string, _payload: unknown): Promise<CallbackResult> {
    return { handled: false };
  }

  async sendRaw(text: string, replyMarkup?: Record<string, unknown>): Promise<void> {
    await telegram.sendText(text, { replyMarkup: replyMarkup as never });
  }
}
