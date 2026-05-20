/**
 * Falco event → Guardian NormalizedEvent mapping.
 *
 * Falco emits structured JSON over HTTP, with fields like {rule, priority,
 * output, output_fields, time}. The pipeline downstream (correlator → ingestor
 * → playbook trigger) speaks NormalizedEvent. This module bridges the two.
 *
 * The KEY translation is rule → eventType: when Falco fires "Mining
 * cryptocurrency", we map it to `crypto_mining` so the existing
 * crypto-mining-response playbook (registry.ts:34) takes over — kill, block,
 * notify. No new playbook code needed.
 *
 * Unknown rules fall through to a generic `falco_<slug>` eventType so they
 * still get persisted (and can be inspected in the dashboard) without firing
 * any auto-response.
 */

import type { NormalizedEvent } from '../pipeline/normalizer.js';

export interface FalcoEvent {
  rule: string;
  priority: string;
  output: string;
  output_fields?: Record<string, unknown>;
  time?: string;
  hostname?: string;
  tags?: string[];
}

// Subset of Falco's CRS rules we explicitly know how to react to. Everything
// else falls through to the generic mapper below.
const RULE_MAP: Record<string, { eventType: string; severityFloor?: NormalizedEvent['severity'] }> = {
  'Mining cryptocurrency': { eventType: 'crypto_mining', severityFloor: 'critical' },
  'Outbound Connection to C2 Servers': { eventType: 'lateral_movement', severityFloor: 'critical' },
  'Write below /etc': { eventType: 'critical_file_tampering', severityFloor: 'high' },
  'Run shell untrusted': { eventType: 'suspicious_process', severityFloor: 'high' },
  'Container privilege escalation': { eventType: 'container_escape_attempt', severityFloor: 'critical' },
};

export class FalcoMapper {
  static toNormalizedEvent(event: FalcoEvent, serverId: number): NormalizedEvent {
    const fields = event.output_fields ?? {};
    const known = RULE_MAP[event.rule];
    const eventType = known?.eventType ?? `falco_${slugify(event.rule)}`;

    // Severity = max(rule's severity floor, mapped from priority). Floor wins
    // for known-bad rules so a misconfigured Falco emitting "Notice" priority
    // for a miner still escalates.
    const fromPriority = priorityToSeverity(event.priority);
    const severity = known?.severityFloor && severityRank(known.severityFloor) > severityRank(fromPriority)
      ? known.severityFloor
      : fromPriority;

    return {
      serverId,
      timestamp: event.time ? new Date(event.time) : new Date(),
      source: 'falco',
      category: categoryFor(eventType),
      severity,
      eventType,
      sourceIp: pickString(fields, ['fd.rip', 'fd.cip', 'fd.sip']) ?? null,
      destinationPort: pickNumber(fields, ['fd.rport', 'fd.sport']) ?? null,
      userName: pickString(fields, ['user.name', 'user']) ?? null,
      processName: pickString(fields, ['proc.name', 'process']) ?? null,
      rawLog: event.output,
      metadata: {
        rule: event.rule,
        priority: event.priority,
        output_fields: fields,
        ...(event.tags ? { falcoTags: event.tags } : {}),
        ...(event.hostname ? { falcoHostname: event.hostname } : {}),
      },
    };
  }
}

function priorityToSeverity(p: string): NormalizedEvent['severity'] {
  switch ((p ?? '').toLowerCase()) {
    case 'emergency':
    case 'alert':
    case 'critical':
      return 'critical';
    case 'error':
      return 'high';
    case 'warning':
      return 'medium';
    case 'notice':
    case 'informational':
    case 'info':
      return 'low';
    case 'debug':
      return 'info';
    default:
      // Unknown priority shouldn't silently default to low — fail upward.
      return 'medium';
  }
}

const SEVERITY_ORDER: Record<NormalizedEvent['severity'], number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};
function severityRank(s: NormalizedEvent['severity']): number {
  return SEVERITY_ORDER[s];
}

function categoryFor(eventType: string): string {
  if (eventType.startsWith('container_') || eventType === 'crypto_mining') return 'container';
  if (eventType === 'lateral_movement') return 'network';
  if (eventType === 'critical_file_tampering') return 'integrity';
  if (eventType === 'suspicious_process') return 'system';
  return 'runtime';
}

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
}

function pickString(obj: Record<string, unknown>, keys: string[]): string | null {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return null;
}

function pickNumber(obj: Record<string, unknown>, keys: string[]): number | null {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'number') return v;
    if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
  }
  return null;
}
