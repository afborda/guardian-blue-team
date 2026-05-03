import type { NotifierPlugin, FormattedAlert, InteractiveAction, CallbackResult } from '../types.js';
import { logger } from '../../utils/logger.js';

export class SlackNotifier implements NotifierPlugin {
  name = 'slack';
  enabled = false;
  interactive = true;

  private webhookUrl: string | null = null;

  async init(): Promise<void> {
    this.webhookUrl = process.env.SLACK_WEBHOOK_URL || null;
    this.enabled = !!this.webhookUrl;
  }

  async send(alert: FormattedAlert): Promise<void> {
    if (!this.webhookUrl) return;

    const severityEmoji: Record<string, string> = { critical: ':red_circle:', high: ':large_orange_circle:', medium: ':large_yellow_circle:', low: ':large_blue_circle:' };

    const blocks = [
      { type: 'header', text: { type: 'plain_text', text: alert.title } },
      { type: 'section', text: { type: 'mrkdwn', text: `${severityEmoji[alert.severity] ?? ''} *${alert.severity.toUpperCase()}*\n${alert.body.replace(/<[^>]+>/g, '')}` } },
    ];

    await this.post({ blocks });
  }

  async sendInteractive(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void> {
    if (!this.webhookUrl) return;

    const blocks = [
      { type: 'header', text: { type: 'plain_text', text: alert.title } },
      { type: 'section', text: { type: 'mrkdwn', text: alert.body.replace(/<[^>]+>/g, '') } },
      {
        type: 'actions',
        elements: actions.map(a => ({
          type: 'button',
          text: { type: 'plain_text', text: a.label },
          action_id: a.id,
          style: a.style === 'approve' ? 'primary' : a.style === 'reject' ? 'danger' : undefined,
        })),
      },
    ];

    await this.post({ blocks });
  }

  async handleCallback(_source: string, _payload: unknown): Promise<CallbackResult> {
    return { handled: false };
  }

  private async post(body: Record<string, unknown>): Promise<void> {
    try {
      await fetch(this.webhookUrl!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch (err) {
      logger.error({ err }, 'Slack notification failed');
    }
  }
}
