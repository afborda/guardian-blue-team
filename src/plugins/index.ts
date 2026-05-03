import { registerNotifier } from './loader.js';
import { TelegramNotifier } from './notifiers/telegram.js';
import { DiscordNotifier } from './notifiers/discord.js';
import { SlackNotifier } from './notifiers/slack.js';
import { WhatsAppNotifier } from './notifiers/whatsapp.js';
import { EmailNotifier } from './notifiers/email.js';
import { NtfyNotifier } from './notifiers/ntfy.js';
import { WebhookNotifier } from './notifiers/webhook.js';

export function registerBuiltinPlugins(): void {
  registerNotifier('telegram', () => new TelegramNotifier());
  registerNotifier('discord', () => new DiscordNotifier());
  registerNotifier('slack', () => new SlackNotifier());
  registerNotifier('whatsapp', () => new WhatsAppNotifier());
  registerNotifier('email', () => new EmailNotifier());
  registerNotifier('ntfy', () => new NtfyNotifier());
  registerNotifier('webhook', () => new WebhookNotifier());
}

export { PluginManager, registerNotifier } from './loader.js';
export { NotifierManager } from './notifier-manager.js';
export type { NotifierPlugin, FormattedAlert, InteractiveAction, CallbackResult } from './types.js';
