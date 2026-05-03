import { PluginManager } from './loader.js';
import type { FormattedAlert, InteractiveAction, CallbackResult } from './types.js';
import { logger } from '../utils/logger.js';

export class NotifierManager {
  static async notify(alert: FormattedAlert): Promise<void> {
    const notifiers = PluginManager.getNotifiers();
    const results = await Promise.allSettled(
      notifiers.map(n => n.send(alert))
    );

    for (let i = 0; i < results.length; i++) {
      if (results[i].status === 'rejected') {
        const reason = (results[i] as PromiseRejectedResult).reason;
        logger.error({ err: reason, notifier: notifiers[i].name }, 'Notifier send failed');
      }
    }
  }

  static async notifyInteractive(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void> {
    const notifier = PluginManager.getInteractiveNotifier();
    if (!notifier || !notifier.sendInteractive) {
      logger.warn('No interactive notifier available, falling back to plain notify');
      await this.notify(alert);
      return;
    }

    try {
      await notifier.sendInteractive(alert, actions);
    } catch (err) {
      logger.error({ err, notifier: notifier.name }, 'Interactive notify failed');
      await this.notify(alert);
    }
  }

  static async handleCallback(source: string, payload: unknown): Promise<CallbackResult> {
    const notifier = PluginManager.getNotifierByName(source);
    if (!notifier || !notifier.handleCallback) {
      return { handled: false };
    }

    return notifier.handleCallback(source, payload);
  }
}
