import { AbuseIPDBClient } from './abuseipdb.js';
import { ThreatIntelCache } from './cache.js';
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
}

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

    const report = await AbuseIPDBClient.checkIP(ip);
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

    ThreatIntelCache.set(cacheKey, result);
    return result;
  }

  static async enrichIP(ip: string): Promise<{ score: number; malicious: boolean } | null> {
    const report = await this.lookupIP(ip);
    if (!report) return null;
    return {
      score: report.score,
      malicious: report.score >= 50,
    };
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

    if (report.lastReported) {
      lines.push(`🕐 Último report: ${report.lastReported}`);
    }

    if (report.cached) {
      lines.push(``, `<i>📦 Cache hit</i>`);
    }

    lines.push(``, `Fonte: ${report.source}`);
    return lines.join('\n');
  }

  private static scoreBar(score: number): string {
    if (score >= 80) return '🔴';
    if (score >= 50) return '🟠';
    if (score >= 25) return '🟡';
    return '🟢';
  }
}
