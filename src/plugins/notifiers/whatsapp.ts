import type { NotifierPlugin, FormattedAlert, InteractiveAction, CallbackResult } from '../types.js';
import { logger } from '../../utils/logger.js';

export class WhatsAppNotifier implements NotifierPlugin {
  name = 'whatsapp';
  enabled = false;
  interactive = true;

  private apiUrl: string | null = null;
  private instance: string | null = null;
  private number: string | null = null;

  async init(): Promise<void> {
    this.apiUrl = process.env.WHATSAPP_API_URL || null;
    this.instance = process.env.WHATSAPP_INSTANCE || null;
    this.number = process.env.WHATSAPP_NUMBER || null;
    this.enabled = !!(this.apiUrl && this.instance && this.number);
  }

  async send(alert: FormattedAlert): Promise<void> {
    if (!this.apiUrl || !this.instance || !this.number) return;

    const text = `*${alert.title}*\n\n${alert.body.replace(/<[^>]+>/g, '')}\n\n_Severity: ${alert.severity}_`;
    await this.sendText(text);
  }

  async sendInteractive(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void> {
    if (!this.apiUrl || !this.instance || !this.number) return;

    const buttonRows = actions.slice(0, 3).map(a => ({
      buttonId: a.id,
      buttonText: { displayText: a.label },
      type: 1,
    }));

    const body = {
      number: this.number,
      options: { delay: 1200 },
      buttonMessage: {
        text: `*${alert.title}*\n\n${alert.body.replace(/<[^>]+>/g, '')}`,
        buttons: buttonRows,
        footerText: `Guardian | ${alert.severity}`,
      },
    };

    try {
      await fetch(`${this.apiUrl}/message/sendButtons/${this.instance}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (err) {
      logger.error({ err }, 'WhatsApp interactive notification failed');
    }
  }

  async handleCallback(_source: string, _payload: unknown): Promise<CallbackResult> {
    return { handled: false };
  }

  private async sendText(text: string): Promise<void> {
    try {
      await fetch(`${this.apiUrl}/message/sendText/${this.instance}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ number: this.number, options: { delay: 1200 }, textMessage: { text } }),
      });
    } catch (err) {
      logger.error({ err }, 'WhatsApp notification failed');
    }
  }
}
