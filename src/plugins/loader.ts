import { existsSync, readdirSync } from 'fs';
import { join, resolve } from 'path';
import { pathToFileURL } from 'url';
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

    await this.loadExternalPlugins();

    this.initialized = true;
    logger.info({ count: this.notifiers.length }, 'Plugin system ready');
  }

  private static async loadExternalPlugins(): Promise<void> {
    const pluginsDir = resolve(process.cwd(), 'plugins');
    if (!existsSync(pluginsDir)) return;

    const entries = readdirSync(pluginsDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (!entry.name.endsWith('.js') && !entry.name.endsWith('.mjs')) continue;

      const filePath = join(pluginsDir, entry.name);

      try {
        const moduleUrl = pathToFileURL(filePath).href;
        const mod = await import(moduleUrl);

        if (mod.default && typeof mod.default === 'function') {
          const plugin: NotifierPlugin = mod.default();

          if (!plugin.name || typeof plugin.send !== 'function') {
            logger.warn({ file: entry.name }, 'External plugin missing required fields (name, send)');
            continue;
          }

          if (plugin.init) await plugin.init();

          if (plugin.enabled) {
            this.notifiers.push(plugin);
            logger.info({ notifier: plugin.name, file: entry.name }, 'External notifier plugin loaded');
          }
        } else {
          logger.warn({ file: entry.name }, 'External plugin must export default function returning NotifierPlugin');
        }
      } catch (err) {
        logger.error({ err, file: entry.name }, 'Failed to load external plugin');
      }
    }
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
