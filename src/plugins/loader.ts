import type { NotifierPlugin } from './types.js';
import { logger } from '../utils/logger.js';

type NotifierFactory = () => NotifierPlugin;

const notifierRegistry = new Map<string, NotifierFactory>();

export function registerNotifier(name: string, factory: NotifierFactory): void {
  notifierRegistry.set(name, factory);
}

export class PluginManager {
  private static notifiers: NotifierPlugin[] = [];
  private static initialized = false;

  static async loadNotifiers(enabledList: string[]): Promise<void> {
    if (this.initialized) return;

    for (const name of enabledList) {
      const factory = notifierRegistry.get(name);
      if (!factory) {
        logger.warn({ notifier: name }, 'Notifier not found in registry');
        continue;
      }

      const plugin = factory();
      if (plugin.init) {
        try {
          await plugin.init();
        } catch (err) {
          logger.error({ err, notifier: name }, 'Notifier init failed');
          continue;
        }
      }

      if (plugin.enabled) {
        this.notifiers.push(plugin);
        logger.info({ notifier: name }, 'Notifier loaded');
      }
    }

    this.initialized = true;
    logger.info({ count: this.notifiers.length }, 'Plugin system ready');
  }

  static getNotifiers(): NotifierPlugin[] {
    return this.notifiers;
  }

  static getInteractiveNotifier(): NotifierPlugin | undefined {
    return this.notifiers.find(n => n.interactive && n.sendInteractive);
  }

  static getNotifierByName(name: string): NotifierPlugin | undefined {
    return this.notifiers.find(n => n.name === name);
  }

  static reset(): void {
    this.notifiers = [];
    this.initialized = false;
  }
}
