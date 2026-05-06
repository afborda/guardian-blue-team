import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

export interface AbuseIPDBReport {
  ip: string;
  abuseConfidenceScore: number;
  totalReports: number;
  countryCode: string;
  domain: string;
  isp: string;
  usageType: string;
  isWhitelisted: boolean;
  lastReportedAt: string | null;
  categories: number[];
}

export class AbuseIPDBClient {
  private static readonly BASE_URL = 'https://api.abuseipdb.com/api/v2';

  static isConfigured(): boolean {
    return !!config.threatIntel.abuseIpDbKey;
  }

  static async checkIP(ip: string): Promise<AbuseIPDBReport | null> {
    if (!config.threatIntel.abuseIpDbKey) return null;

    const url = `${this.BASE_URL}/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const response = await fetch(url, {
      headers: {
        'Key': config.threatIntel.abuseIpDbKey,
        'Accept': 'application/json',
      },
    });

    if (response.status === 429) {
      throw new Error('AbuseIPDB rate limit exceeded');
    }

    if (!response.ok) {
      logger.warn({ status: response.status, ip }, 'AbuseIPDB API error');
      throw new Error(`AbuseIPDB HTTP ${response.status}`);
    }

    const json = await response.json() as { data: Record<string, unknown> };
    const d = json.data;

    return {
      ip: d.ipAddress as string,
      abuseConfidenceScore: d.abuseConfidenceScore as number,
      totalReports: d.totalReports as number,
      countryCode: d.countryCode as string,
      domain: d.domain as string,
      isp: d.isp as string,
      usageType: d.usageType as string,
      isWhitelisted: d.isWhitelisted as boolean,
      lastReportedAt: d.lastReportedAt as string | null,
      categories: (d.categories ?? []) as number[],
    };
  }
}
