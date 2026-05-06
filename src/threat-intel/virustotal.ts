import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

export interface VirusTotalIPReport {
  ip: string;
  maliciousVotes: number;
  harmlessVotes: number;
  suspiciousVotes: number;
  owner: string;
  country: string;
  asn: number;
  network: string;
  reputation: number;
}

export class VirusTotalClient {
  private static readonly BASE_URL = 'https://www.virustotal.com/api/v3';

  static isConfigured(): boolean {
    return !!config.threatIntel.virusTotalKey;
  }

  static async checkIP(ip: string): Promise<VirusTotalIPReport | null> {
    if (!config.threatIntel.virusTotalKey) return null;

    const url = `${this.BASE_URL}/ip_addresses/${encodeURIComponent(ip)}`;
    const response = await fetch(url, {
      headers: {
        'x-apikey': config.threatIntel.virusTotalKey,
        'Accept': 'application/json',
      },
    });

    if (response.status === 429) {
      throw new Error('VirusTotal rate limit exceeded');
    }

    if (!response.ok) {
      logger.warn({ status: response.status, ip }, 'VirusTotal API error');
      throw new Error(`VirusTotal HTTP ${response.status}`);
    }

    const json = await response.json() as { data: { attributes: Record<string, unknown> } };
    const attrs = json.data.attributes;
    const stats = (attrs.last_analysis_stats ?? {}) as Record<string, number>;

    return {
      ip,
      maliciousVotes: stats.malicious ?? 0,
      harmlessVotes: stats.harmless ?? 0,
      suspiciousVotes: stats.suspicious ?? 0,
      owner: (attrs.as_owner as string) ?? 'unknown',
      country: (attrs.country as string) ?? 'unknown',
      asn: (attrs.asn as number) ?? 0,
      network: (attrs.network as string) ?? 'unknown',
      reputation: (attrs.reputation as number) ?? 0,
    };
  }
}
