import { PluginManager } from './loader.js';
import type { FormattedAlert, InteractiveAction, CallbackResult } from './types.js';
import type { MessageSpec, SendResult } from '../telegram/messaging/types.js';
import { renderPlain } from '../telegram/messaging/render.js';
import { logger } from '../utils/logger.js';

function specToAlert(spec: MessageSpec): FormattedAlert {
  return {
    title: spec.title,
    body: renderPlain(spec),
    severity: spec.severity,
    metadata: { kind: spec.kind },
    spec,
  };
}

export class NotifierManager {
  static async notify(alert: FormattedAlert): Promise<SendResult | undefined> {
    const notifiers = PluginManager.getNotifiers();
    let telegramResult: SendResult | undefined;

    const results = await Promise.allSettled(
      notifiers.map(async notifier => {
        const result = await notifier.send(alert);
        if (notifier.name === 'telegram' && result) telegramResult = result;
        return result;
      }),
    );

    for (let i = 0; i < results.length; i++) {
      if (results[i].status === 'rejected') {
        const reason = (results[i] as PromiseRejectedResult).reason;
        logger.error({ err: reason, notifier: notifiers[i]?.name }, 'Notifier send failed');
      }
    }

    return telegramResult;
  }

  /** Envia um MessageSpec estruturado; devolve o resultado do Telegram quando houver. */
  static async notifySpec(spec: MessageSpec): Promise<SendResult | undefined> {
    return this.notify(specToAlert(spec));
  }

  static async notifyInteractive(alert: FormattedAlert, actions: InteractiveAction[]): Promise<SendResult | undefined> {
    const notifier = PluginManager.getInteractiveNotifier();
    if (!notifier || !notifier.sendInteractive) {
      logger.warn('No interactive notifier available, falling back to plain notify');
      return this.notify(alert);
    }

    try {
      const result = await notifier.sendInteractive(alert, actions);
      return result ?? undefined;
    } catch (err) {
      logger.error({ err, notifier: notifier.name }, 'Interactive notify failed');
      return this.notify(alert);
    }
  }

  static async notifyInteractiveSpec(spec: MessageSpec): Promise<SendResult | undefined> {
    return this.notifyInteractive(specToAlert(spec), []);
  }

  static async handleCallback(source: string, payload: unknown): Promise<CallbackResult> {
    const notifier = PluginManager.getNotifierByName(source);
    if (!notifier || !notifier.handleCallback) {
      return { handled: false };
    }

    return notifier.handleCallback(source, payload);
  }
}
