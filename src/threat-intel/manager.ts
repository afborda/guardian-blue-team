import { AbuseIPDBClient } from './abuseipdb.js';
import { VirusTotalClient } from './virustotal.js';
import { ThreatIntelCache } from './cache.js';
import { CircuitBreaker } from '../utils/circuit-breaker.js';
import { db } from '../database/connection.js';
import { threatIntelCache } from '../database/schema.js';
import { eq, and, gte } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export interface ThreatReport {
  ip: string;
  score: number;
  totalReports: number;
  country: string;
  isp: string;
  domain: string;
  usageType: string;
  lastReported: string | null;
  source: string;
  cached: boolean;
  virusTotal?: { malicious: number; suspicious: number; reputation: number };
}

const abuseBreaker = new CircuitBreaker({
  name: 'abuseipdb',
  failureThreshold: 3,
  resetTimeoutMs: 5 * 60 * 1000,
});

const vtBreaker = new CircuitBreaker({
  name: 'virustotal',
  failureThreshold: 3,
  resetTimeoutMs: 5 * 60 * 1000,
});

export class ThreatIntelManager {
  static start(): void {
    ThreatIntelCache.start();
    logger.info('Threat intel manager started');
  }

  static stop(): void {
    ThreatIntelCache.stop();
  }

  static async lookupIP(ip: string): Promise<ThreatReport | null> {
    const cacheKey = `ip:${ip}`;
    const cached = ThreatIntelCache.get<ThreatReport>(cacheKey);
    if (cached) return { ...cached, cached: true };

    // Check DB cache (survives container restarts)
    try {
      const [dbCached] = await db.select()
        .from(threatIntelCache)
        .where(and(
          eq(threatIntelCache.indicator, ip),
          eq(threatIntelCache.source, 'abuseipdb'),
          gte(threatIntelCache.expiresAt, new Date()),
        ))
        .limit(1);

      if (dbCached?.data) {
        const restored = dbCached.data as unknown as ThreatReport;
        ThreatIntelCache.set(cacheKey, restored);
        return { ...restored, cached: true };
      }
    } catch {}

    const report = await abuseBreaker.call(() => AbuseIPDBClient.checkIP(ip));
    if (!report) return null;

    const result: ThreatReport = {
      ip: report.ip,
      score: report.abuseConfidenceScore,
      totalReports: report.totalReports,
      country: report.countryCode,
      isp: report.isp,
      domain: report.domain,
      usageType: report.usageType,
      lastReported: report.lastReportedAt,
      source: 'abuseipdb',
      cached: false,
    };

    if (VirusTotalClient.isConfigured() && report.abuseConfidenceScore >= 30) {
      const vtReport = await vtBreaker.call(() => VirusTotalClient.checkIP(ip));
      if (vtReport) {
        result.virusTotal = {
          malicious: vtReport.maliciousVotes,
          suspicious: vtReport.suspiciousVotes,
          reputation: vtReport.reputation,
        };
        result.source = 'abuseipdb+virustotal';
      }
    }

    ThreatIntelCache.set(cacheKey, result);

    // Persist to DB for cross-restart cache
    try {
      await db.insert(threatIntelCache).values({
        indicator: ip,
        indicatorType: 'ip',
        source: 'abuseipdb',
        reputationScore: result.score,
        data: result as unknown as Record<string, unknown>,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      }).onConflictDoNothing();
    } catch {}

    return result;
  }

  static async enrichIP(ip: string): Promise<{ score: number; malicious: boolean } | null> {
    const report = await this.lookupIP(ip);
    if (!report) return null;

    let score = report.score;
    if (report.virusTotal && report.virusTotal.malicious > 5) {
      score = Math.min(100, score + 15);
    }

    return { score, malicious: score >= 50 };
  }

  static async batchEnrich(ips: string[]): Promise<Map<string, ThreatReport>> {
    const results = new Map<string, ThreatReport>();
    const unique = [...new Set(ips)];

    for (const ip of unique) {
      const report = await this.lookupIP(ip);
      if (report) results.set(ip, report);
      if (!report?.cached) {
        await new Promise(resolve => setTimeout(resolve, 1100));
      }
    }

    return results;
  }

  static formatReport(report: ThreatReport): string {
    const scoreBar = this.scoreBar(report.score);
    const lines = [
      `🔍 <b>Threat Intel: ${report.ip}</b>`,
      ``,
      `${scoreBar} Score: ${report.score}/100`,
      `📊 Reports: ${report.totalReports}`,
      `🌍 País: ${report.country}`,
      `🏢 ISP: ${report.isp}`,
      `🌐 Domain: ${report.domain || 'n/a'}`,
      `📌 Uso: ${report.usageType || 'unknown'}`,
    ];

    if (report.virusTotal) {
      lines.push(
        ``,
        `<b>VirusTotal:</b>`,
        `  🚨 Malicious: ${report.virusTotal.malicious}`,
        `  ⚠️ Suspicious: ${report.virusTotal.suspicious}`,
        `  📉 Reputation: ${report.virusTotal.reputation}`,
      );
    }

    if (report.lastReported) {
      lines.push(`🕐 Último report: ${report.lastReported}`);
    }

    if (report.cached) {
      lines.push(``, `<i>📦 Cache hit</i>`);
    }

    lines.push(``, `Fonte: ${report.source}`);
    return lines.join('\n');
  }

  static getCircuitStatus(): { abuseipdb: string; virustotal: string } {
    return {
      abuseipdb: abuseBreaker.getState(),
      virustotal: vtBreaker.getState(),
    };
  }

  private static scoreBar(score: number): string {
    if (score >= 80) return '🔴';
    if (score >= 50) return '🟠';
    if (score >= 25) return '🟡';
    return '🟢';
  }
}
