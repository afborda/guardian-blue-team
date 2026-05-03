import type { NotifierPlugin, FormattedAlert, CallbackResult } from '../types.js';
import { logger } from '../../utils/logger.js';
import { createHmac } from 'crypto';

export class WebhookNotifier implements NotifierPlugin {
  name = 'webhook';
  enabled = false;
  interactive = false;

  private url: string | null = null;
  private secret: string | null = null;

  async init(): Promise<void> {
    this.url = process.env.WEBHOOK_URL || null;
    this.secret = process.env.WEBHOOK_SECRET || null;
    this.enabled = !!this.url;
  }

  async send(alert: FormattedAlert): Promise<void> {
    if (!this.url) return;

    const payload = JSON.stringify({
      event: 'alert',
      timestamp: new Date().toISOString(),
      alert: {
        title: alert.title,
        body: alert.body.replace(/<[^>]+>/g, ''),
        severity: alert.severity,
        metadata: alert.metadata,
      },
    });

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };

    if (this.secret) {
      const signature = createHmac('sha256', this.secret).update(payload).digest('hex');
      headers['X-Guardian-Signature'] = `sha256=${signature}`;
    }

    try {
      await fetch(this.url, { method: 'POST', headers, body: payload });
    } catch (err) {
      logger.error({ err }, 'Webhook notification failed');
    }
  }

  async handleCallback(_source: string, _payload: unknown): Promise<CallbackResult> {
    return { handled: false };
  }
}
