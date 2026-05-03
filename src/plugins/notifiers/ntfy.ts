import type { NotifierPlugin, FormattedAlert, CallbackResult } from '../types.js';
import { logger } from '../../utils/logger.js';

export class NtfyNotifier implements NotifierPlugin {
  name = 'ntfy';
  enabled = false;
  interactive = false;

  private server: string = 'https://ntfy.sh';
  private topic: string | null = null;

  async init(): Promise<void> {
    this.server = process.env.NTFY_SERVER || 'https://ntfy.sh';
    this.topic = process.env.NTFY_TOPIC || null;
    this.enabled = !!this.topic;
  }

  async send(alert: FormattedAlert): Promise<void> {
    if (!this.topic) return;

    const priorityMap: Record<string, string> = { critical: '5', high: '4', medium: '3', low: '2' };

    try {
      await fetch(`${this.server}/${this.topic}`, {
        method: 'POST',
        headers: {
          'Title': alert.title,
          'Priority': priorityMap[alert.severity] ?? '3',
          'Tags': `guardian,${alert.severity}`,
        },
        body: alert.body.replace(/<[^>]+>/g, ''),
      });
    } catch (err) {
      logger.error({ err }, 'ntfy notification failed');
    }
  }

  async handleCallback(_source: string, _payload: unknown): Promise<CallbackResult> {
    return { handled: false };
  }
}
