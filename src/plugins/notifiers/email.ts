import type { NotifierPlugin, FormattedAlert, CallbackResult } from '../types.js';
import { logger } from '../../utils/logger.js';

export class EmailNotifier implements NotifierPlugin {
  name = 'email';
  enabled = false;
  interactive = false;

  private from: string | null = null;
  private to: string | null = null;
  private resendApiKey: string | null = null;

  async init(): Promise<void> {
    this.resendApiKey = process.env.RESEND_API_KEY || null;
    this.from = process.env.EMAIL_FROM || 'Guardian <guardian@localhost>';
    this.to = process.env.EMAIL_TO || null;

    this.enabled = !!(this.to && this.resendApiKey);
  }

  async send(alert: FormattedAlert): Promise<void> {
    if (!this.to) return;

    const subject = `[Guardian ${alert.severity.toUpperCase()}] ${alert.title}`;
    const body = alert.body.replace(/<[^>]+>/g, '');

    if (this.resendApiKey) {
      await this.sendViaResend(subject, body);
    }
  }

  async handleCallback(_source: string, _payload: unknown): Promise<CallbackResult> {
    return { handled: false };
  }

  private async sendViaResend(subject: string, text: string): Promise<void> {
    try {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.resendApiKey}`,
        },
        body: JSON.stringify({
          from: this.from,
          to: this.to,
          subject,
          text,
        }),
      });
    } catch (err) {
      logger.error({ err }, 'Email notification failed');
    }
  }
}
