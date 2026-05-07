import type { NormalizedEvent } from './normalizer.js';
import { ThreatIntelManager } from '../threat-intel/manager.js';
import { SSHBehaviorProfiler } from '../intelligence/ssh-behavior.js';
import { FalsePositiveFilter } from '../intelligence/false-positive-filter.js';
import { CONSTANTS } from '../config/constants.js';
import { db } from '../database/connection.js';
import { blockedIps } from '../database/schema.js';
import { logger } from '../utils/logger.js';

const TRUSTED_IPS = new Set(CONSTANTS.trustedIps);

function isSkippableIp(ip: string): boolean {
  if (TRUSTED_IPS.has(ip)) return true;
  if (ip.startsWith('172.') || ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  return false;
}

let blockedIpCache = new Set<string>();
let blockedCacheExpires = 0;

async function getBlockedIps(): Promise<Set<string>> {
  if (Date.now() < blockedCacheExpires) return blockedIpCache;
  try {
    const rows = await db.select({ ip: blockedIps.ip }).from(blockedIps);
    blockedIpCache = new Set(rows.map(r => r.ip));
    blockedCacheExpires = Date.now() + 5 * 60_000;
  } catch {}
  return blockedIpCache;
}

export function addTrustedIpToEnricher(ip: string): void {
  TRUSTED_IPS.add(ip);
}

export class EventEnricher {
  static async enrich(events: NormalizedEvent[]): Promise<NormalizedEvent[]> {
    const blocked = await getBlockedIps();
    const ipsToEnrich = new Set<string>();

    for (const event of events) {
      if (event.sourceIp && (event.severity === 'high' || event.severity === 'critical')) {
        if (!isSkippableIp(event.sourceIp) && !blocked.has(event.sourceIp)) {
          ipsToEnrich.add(event.sourceIp);
        }
      }
    }

    if (ipsToEnrich.size === 0) return events;

    const enrichments = new Map<string, { score: number; malicious: boolean }>();

    for (const ip of ipsToEnrich) {
      const result = await ThreatIntelManager.enrichIP(ip);
      if (result) {
        enrichments.set(ip, result);
      }
    }

    const enrichedEvents: NormalizedEvent[] = [];

    for (const event of events) {
      let enriched = event;

      // False positive suppression based on learned patterns
      if (event.severity !== 'info') {
        const fpCheck = await FalsePositiveFilter.shouldSuppress(
          event.eventType,
          event.sourceIp ?? undefined,
          event.userName ?? undefined,
        );
        if (fpCheck.suppress) {
          enriched = {
            ...enriched,
            severity: 'info',
            metadata: {
              ...enriched.metadata,
              suppressed: true,
              suppressionReason: fpCheck.reason,
              suppressionConfidence: fpCheck.confidence,
              originalSeverity: event.severity,
            },
          };
          logger.debug({ eventType: event.eventType, ip: event.sourceIp, reason: fpCheck.reason }, 'Event suppressed by FP filter');
          enrichedEvents.push(enriched);
          continue;
        }
      }

      // Threat intel enrichment
      if (event.sourceIp) {
        const intel = enrichments.get(event.sourceIp);
        if (intel) {
          enriched = {
            ...enriched,
            metadata: {
              ...enriched.metadata,
              threatIntel: { score: intel.score, malicious: intel.malicious },
            },
            severity: this.adjustSeverity(enriched.severity, intel),
          };
        }
      }

      // ML behavioral scoring for SSH logins
      if (event.eventType === 'ssh_login_success' || event.eventType === 'ssh_key_login') {
        const behaviorScore = await this.scoreBehavior(enriched);
        if (behaviorScore) {
          enriched = {
            ...enriched,
            metadata: {
              ...enriched.metadata,
              behaviorScore,
            },
          };
          if (behaviorScore.score >= 0.7 && this.severityRank(enriched.severity) < this.severityRank('high')) {
            enriched = { ...enriched, severity: 'high' };
          }
        }
      }

      enrichedEvents.push(enriched);
    }

    return enrichedEvents;
  }

  private static async scoreBehavior(event: NormalizedEvent) {
    if (!event.userName || !event.sourceIp || !event.serverId) return null;

    try {
      const hour = event.timestamp.getHours();
      const meta = event.metadata as Record<string, unknown> | null;
      const fingerprint = typeof meta?.fingerprint === 'string' ? meta.fingerprint : undefined;

      return await SSHBehaviorProfiler.scoreLogin(
        event.serverId,
        event.userName,
        event.sourceIp,
        hour,
        fingerprint,
      );
    } catch {
      return null;
    }
  }

  private static severityRank(severity: string): number {
    const scale: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    return scale[severity] ?? 0;
  }

  private static adjustSeverity(
    current: NormalizedEvent['severity'],
    intel: { score: number; malicious: boolean }
  ): NormalizedEvent['severity'] {
    if (!intel.malicious) return current;

    const severityScale = ['info', 'low', 'medium', 'high', 'critical'] as const;
    const currentIdx = severityScale.indexOf(current);

    if (intel.score >= 90 && currentIdx < 4) {
      return severityScale[Math.min(currentIdx + 2, 4)];
    }
    if (intel.score >= 50 && currentIdx < 3) {
      return severityScale[currentIdx + 1];
    }

    return current;
  }
}
