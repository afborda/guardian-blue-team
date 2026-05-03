import type { NotifierPlugin, FormattedAlert, InteractiveAction, CallbackResult } from '../types.js';
import { config } from '../../config/environment.js';
import { logger } from '../../utils/logger.js';

export class TelegramNotifier implements NotifierPlugin {
  name = 'telegram';
  enabled = false;
  interactive = true;

  async init(): Promise<void> {
    this.enabled = !!(config.telegram.botToken && config.telegram.chatId);
  }

  async send(alert: FormattedAlert): Promise<void> {
    const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
    const icon = severityIcon[alert.severity] ?? '⚪';

    const text = `${icon} <b>${alert.title}</b>\n\n${alert.body}`;
    await this.sendMessage(text);
  }

  async sendInteractive(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void> {
    const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
    const icon = severityIcon[alert.severity] ?? '⚪';

    const text = `${icon} <b>${alert.title}</b>\n\n${alert.body}`;

    const buttons = actions.map(a => ({
      text: a.style === 'approve' ? `✅ ${a.label}` : a.style === 'reject' ? `❌ ${a.label}` : `📋 ${a.label}`,
      callback_data: a.id,
    }));

    await this.sendMessage(text, { inline_keyboard: [buttons] });
  }

  async handleCallback(_source: string, _payload: unknown): Promise<CallbackResult> {
    return { handled: false };
  }

  async sendRaw(text: string, replyMarkup?: Record<string, unknown>): Promise<void> {
    await this.sendMessage(text, replyMarkup);
  }

  private async sendMessage(text: string, replyMarkup?: Record<string, unknown>): Promise<void> {
    const body: Record<string, unknown> = {
      chat_id: config.telegram.chatId,
      text,
      parse_mode: 'HTML',
    };
    if (replyMarkup) body.reply_markup = replyMarkup;

    try {
      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (err) {
      logger.error({ err }, 'Telegram notification failed');
    }
  }
}
