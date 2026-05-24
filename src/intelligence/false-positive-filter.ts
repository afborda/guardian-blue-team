import { db } from '../database/connection.js';
import { incidentMemory } from '../database/schema.js';
import { logger } from '../utils/logger.js';

interface SuppressionRule {
  category: string;
  sourceIp?: string;
  userName?: string;
  fpCount: number;
  totalCount: number;
  fpRate: number;
}

export class FalsePositiveFilter {
  private static cache = new Map<string, SuppressionRule>();
  private static lastRefresh = 0;
  private static readonly CACHE_TTL_MS = 15 * 60 * 1000;
  private static readonly SUPPRESSION_THRESHOLD = 0.7;
  // Lowered from 3 to 2: with auto-resolved entries no longer polluting
  // incident_memory, every FP record is human-confirmed signal — two of
  // them is already a strong "stop alerting on this" vote.
  private static readonly MIN_SAMPLES = 2;

  static async shouldSuppress(category: string, sourceIp?: string, userName?: string): Promise<{ suppress: boolean; confidence: number; reason?: string }> {
    await this.refreshCacheIfNeeded();

    const keyExact = this.buildKey(category, sourceIp, userName);
    const keyIp = sourceIp ? this.buildKey(category, sourceIp) : null;
    const keyCat = this.buildKey(category);

    const ruleExact = this.cache.get(keyExact);
    if (ruleExact && ruleExact.fpCount >= this.MIN_SAMPLES && ruleExact.fpRate >= this.SUPPRESSION_THRESHOLD) {
      return { suppress: true, confidence: ruleExact.fpRate, reason: `${ruleExact.fpCount}/${ruleExact.totalCount} similar incidents were false positives` };
    }

    if (keyIp) {
      const ruleIp = this.cache.get(keyIp);
      if (ruleIp && ruleIp.fpCount >= this.MIN_SAMPLES && ruleIp.fpRate >= this.SUPPRESSION_THRESHOLD) {
        return { suppress: true, confidence: ruleIp.fpRate, reason: `IP ${sourceIp} triggered ${ruleIp.fpCount} false positives in category ${category}` };
      }
    }

    const ruleCat = this.cache.get(keyCat);
    if (ruleCat && ruleCat.fpCount >= 5 && ruleCat.fpRate >= 0.85) {
      return { suppress: true, confidence: ruleCat.fpRate, reason: `Category ${category} has ${Math.round(ruleCat.fpRate * 100)}% false positive rate` };
    }

    return { suppress: false, confidence: 0 };
  }

  static async getSuppressionScore(category: string, sourceIp?: string): Promise<number> {
    const result = await this.shouldSuppress(category, sourceIp);
    return result.suppress ? result.confidence : 0;
  }

  static async refreshCacheIfNeeded(): Promise<void> {
    if (Date.now() - this.lastRefresh < this.CACHE_TTL_MS) return;
    await this.refreshCache();
  }

  static async refreshCache(): Promise<void> {
    try {
      const allMemory = await db.select({
        category: incidentMemory.category,
        sourceIps: incidentMemory.sourceIps,
        falsePositive: incidentMemory.falsePositive,
      }).from(incidentMemory);

      const newCache = new Map<string, SuppressionRule>();

      for (const mem of allMemory) {
        const ips = (mem.sourceIps ?? []) as string[];

        this.incrementRule(newCache, mem.category, undefined, undefined, mem.falsePositive);

        for (const ip of ips) {
          this.incrementRule(newCache, mem.category, ip, undefined, mem.falsePositive);
        }
      }

      this.cache = newCache;
      this.lastRefresh = Date.now();
      logger.debug({ rules: newCache.size }, 'False positive filter cache refreshed');
    } catch (err) {
      logger.error({ err }, 'Failed to refresh false positive filter cache');
    }
  }

  static invalidateCache(): void {
    this.lastRefresh = 0;
  }

  private static incrementRule(cache: Map<string, SuppressionRule>, category: string, sourceIp?: string, userName?: string, isFp?: boolean): void {
    const key = this.buildKey(category, sourceIp, userName);
    const existing = cache.get(key) ?? { category, sourceIp, userName, fpCount: 0, totalCount: 0, fpRate: 0 };

    existing.totalCount++;
    if (isFp) existing.fpCount++;
    existing.fpRate = existing.totalCount > 0 ? existing.fpCount / existing.totalCount : 0;

    cache.set(key, existing);
  }

  private static buildKey(category: string, sourceIp?: string, userName?: string): string {
    const parts = [category];
    if (sourceIp) parts.push(`ip:${sourceIp}`);
    if (userName) parts.push(`user:${userName}`);
    return parts.join('|');
  }
}
