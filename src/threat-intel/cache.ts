import { logger } from '../utils/logger.js';

export interface CacheEntry<T> {
  data: T;
  expiresAt: number;
}

export class ThreatIntelCache {
  private static cache = new Map<string, CacheEntry<unknown>>();
  private static readonly DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
  private static cleanupInterval: NodeJS.Timeout | null = null;

  static start(): void {
    if (this.cleanupInterval) return;
    this.cleanupInterval = setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  static stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  static get<T>(key: string): T | null {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined;
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    return entry.data;
  }

  static set<T>(key: string, data: T, ttlMs = this.DEFAULT_TTL_MS): void {
    this.cache.set(key, { data, expiresAt: Date.now() + ttlMs });
  }

  static has(key: string): boolean {
    return this.get(key) !== null;
  }

  static delete(key: string): void {
    this.cache.delete(key);
  }

  static size(): number {
    return this.cache.size;
  }

  private static cleanup(): void {
    const now = Date.now();
    let removed = 0;
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        removed++;
      }
    }
    if (removed > 0) {
      logger.debug({ removed, remaining: this.cache.size }, 'Threat intel cache cleanup');
    }
  }
}
