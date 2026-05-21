import { db } from '../database/connection.js';
import { securityEvents, ipThreatScores } from '../database/schema.js';
import { desc, sql, count } from 'drizzle-orm';
import { extractIPFeatures } from '../intelligence/ip-features.js';
import { IpClassifier } from '../intelligence/ip-classifier.js';
import { ThreatIntelManager } from '../threat-intel/manager.js';
import { logger } from '../utils/logger.js';
import { config } from '../config/environment.js';

export class IpThreatScorerWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 30 * 60 * 1000;
  private static readonly TOP_N = 150;
  // Only hit AbuseIPDB when ML score >= this threshold
  private static readonly INTEL_GATE = 0.5;
  // TTL for scored IPs
  private static readonly TTL_MS = 24 * 60 * 60 * 1000;

  static start(): void {
    if (this.intervalId) return;
    IpClassifier.init().catch(() => {});

    logger.info('IP threat scorer worker started (every 30min)');

    // Run immediately on first start, then every 30 min
    this.runCycle().catch(err => logger.error({ err }, 'IP threat scorer: initial run error'));
    this.intervalId = setInterval(() => {
      this.runCycle().catch(err => logger.error({ err }, 'IP threat scorer: cycle error'));
    }, this.INTERVAL_MS);
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('IP threat scorer worker stopped');
  }

  static async runCycle(): Promise<void> {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

    // Top active IPs in the last 24h (skip info-level noise)
    const topIps = await db.select({
      ip: securityEvents.sourceIp,
      cnt: count(),
    })
      .from(securityEvents)
      .where(
        sql`${securityEvents.sourceIp} IS NOT NULL AND ${securityEvents.sourceIp} != ''
            AND ${securityEvents.severity} != 'info'
            AND ${securityEvents.timestamp} >= ${since24h}`,
      )
      .groupBy(securityEvents.sourceIp)
      .orderBy(desc(count()))
      .limit(this.TOP_N);

    if (topIps.length === 0) return;

    let scored = 0;
    let intelLookups = 0;
    const expiresAt = new Date(Date.now() + this.TTL_MS);

    for (const row of topIps) {
      if (!row.ip) continue;
      try {
        const features = await extractIPFeatures(row.ip);
        const result = await IpClassifier.classify(features);

        let country: string | null = null;
        let isp: string | null = null;
        let abuseScore: number | null = null;
        let vtMalicious: number | null = null;

        // Gate AbuseIPDB lookups to high-scoring IPs to preserve quota
        if (result.score >= this.INTEL_GATE && config.threatIntel.abuseIpDbKey) {
          try {
            const intel = await ThreatIntelManager.lookupIP(row.ip);
            if (intel) {
              country = intel.country || null;
              isp = intel.isp || null;
              abuseScore = intel.score;
              vtMalicious = intel.virusTotal?.malicious ?? null;
              if (!intel.cached) intelLookups++;
            }
          } catch {
            // rate limit or network error — skip intel, keep ML score
          }
        }

        const featureSnapshot = Object.fromEntries(
          Object.entries(features).map(([k, v]) => [k, Number(v)])
        ) as Record<string, number>;

        await db.insert(ipThreatScores).values({
          ip: row.ip,
          threatScore: result.score,
          isDangerous: result.isDangerous,
          features: featureSnapshot,
          country,
          isp,
          abuseScore,
          vtMalicious,
          source: result.source,
          scoredAt: new Date(),
          expiresAt,
        }).onConflictDoUpdate({
          target: ipThreatScores.ip,
          set: {
            threatScore: result.score,
            isDangerous: result.isDangerous,
            features: featureSnapshot,
            country,
            isp,
            abuseScore,
            vtMalicious,
            source: result.source,
            scoredAt: new Date(),
            expiresAt,
          },
        });

        scored++;
      } catch (err) {
        logger.debug({ err, ip: row.ip }, 'IP threat scorer: failed to score IP');
      }
    }

    logger.info({ scored, intelLookups, total: topIps.length }, 'IP threat scorer cycle complete');

    // Purge expired rows
    await db.delete(ipThreatScores).where(
      sql`${ipThreatScores.expiresAt} < ${new Date()}`,
    ).catch(() => {});
  }
}
