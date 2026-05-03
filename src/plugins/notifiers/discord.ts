import type { NotifierPlugin, FormattedAlert, InteractiveAction, CallbackResult } from '../types.js';
import { logger } from '../../utils/logger.js';

export class DiscordNotifier implements NotifierPlugin {
  name = 'discord';
  enabled = false;
  interactive = true;

  private webhookUrl: string | null = null;

  async init(): Promise<void> {
    this.webhookUrl = process.env.DISCORD_WEBHOOK_URL || null;
    this.enabled = !!this.webhookUrl;
  }

  async send(alert: FormattedAlert): Promise<void> {
    if (!this.webhookUrl) return;

    const colorMap: Record<string, number> = { critical: 0xff0000, high: 0xff8800, medium: 0xffcc00, low: 0x3498db };

    const embed = {
      title: alert.title,
      description: alert.body.replace(/<[^>]+>/g, ''),
      color: colorMap[alert.severity] ?? 0x95a5a6,
      timestamp: new Date().toISOString(),
      footer: { text: `Guardian | ${alert.severity}` },
    };

    await this.post({ embeds: [embed] });
  }

  async sendInteractive(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void> {
    if (!this.webhookUrl) return;

    const colorMap: Record<string, number> = { critical: 0xff0000, high: 0xff8800, medium: 0xffcc00, low: 0x3498db };

    const embed = {
      title: alert.title,
      description: alert.body.replace(/<[^>]+>/g, ''),
      color: colorMap[alert.severity] ?? 0x95a5a6,
      timestamp: new Date().toISOString(),
      fields: actions.map(a => ({ name: a.label, value: `ID: ${a.id}`, inline: true })),
    };

    await this.post({ embeds: [embed] });
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
      logger.error({ err }, 'Discord notification failed');
    }
  }
}
