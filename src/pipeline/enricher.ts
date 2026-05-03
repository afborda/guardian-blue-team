import type { NormalizedEvent } from './normalizer.js';
import { ThreatIntelManager } from '../threat-intel/manager.js';

export class EventEnricher {
  static async enrich(events: NormalizedEvent[]): Promise<NormalizedEvent[]> {
    const ipsToEnrich = new Set<string>();

    for (const event of events) {
      if (event.sourceIp && event.severity !== 'info') {
        ipsToEnrich.add(event.sourceIp);
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

    return events.map(event => {
      if (!event.sourceIp) return event;

      const intel = enrichments.get(event.sourceIp);
      if (!intel) return event;

      return {
        ...event,
        metadata: {
          ...event.metadata,
          threatIntel: {
            score: intel.score,
            malicious: intel.malicious,
          },
        },
        severity: this.adjustSeverity(event.severity, intel),
      };
    });
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
