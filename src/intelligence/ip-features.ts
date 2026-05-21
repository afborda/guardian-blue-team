/**
 * Feature extraction for IP threat classification.
 *
 * Features are derived entirely from internal data (security_events,
 * blocked_ips, rate_limited_ips, soc_incidents, threat_intel_cache) so
 * no external API calls are needed at feature-extraction time.
 *
 * The feature vector MUST match scripts/train_ip_classifier.py byte-for-byte.
 * If you add, remove, or reorder features, retrain the ONNX model.
 */

import { db } from '../database/connection.js';
import { securityEvents, rateLimitedIps, socIncidents, threatIntelCache } from '../database/schema.js';
import { eq, and, gte, sql, count } from 'drizzle-orm';

export interface IPFeatureVector {
  // Index 0: total event count (log-scaled at inference time)
  totalEvents: number;
  // Index 1: number of distinct event_type values seen
  distinctEventTypes: number;
  // Index 2: fraction of events with severity high or critical
  ratioHighCritical: number;
  // Index 3–6: presence of high-signal event types (0 or 1)
  hasBruteForce: number;
  hasLateralMovement: number;
  hasCryptoMining: number;
  hasProxyScanner: number;
  // Index 7: distinct destination ports targeted
  distinctPorts: number;
  // Index 8: distinct servers targeted (max 4 in this setup)
  distinctServers: number;
  // Index 9: events per hour over the observation window
  eventsPerHour: number;
  // Index 10: Shannon entropy of events-by-hour-of-day distribution (0–log2(24))
  hourEntropy: number;
  // Index 11: successful SSH login occurred after prior failures (lateral movement signal)
  hadSuccess: number;
  // Index 12–13: DDoS escalation path (0 or 1)
  wasRateLimited: number;
  wasEscalated: number;
  // Index 14: max incident severity the IP appears in (0=none, 1=low, 2=medium, 3=high, 4=critical)
  maxIncidentSeverity: number;
  // Index 15–17: AbuseIPDB / VirusTotal data from cache (0 if not cached)
  abuseScore: number;
  totalReports: number;
  vtMalicious: number;
  // Index 18: ISP is a datacenter/hosting provider (0 or 1)
  usageTypeDatacenter: number;
}

export const FEATURE_ORDER: ReadonlyArray<keyof IPFeatureVector> = [
  'totalEvents',
  'distinctEventTypes',
  'ratioHighCritical',
  'hasBruteForce',
  'hasLateralMovement',
  'hasCryptoMining',
  'hasProxyScanner',
  'distinctPorts',
  'distinctServers',
  'eventsPerHour',
  'hourEntropy',
  'hadSuccess',
  'wasRateLimited',
  'wasEscalated',
  'maxIncidentSeverity',
  'abuseScore',
  'totalReports',
  'vtMalicious',
  'usageTypeDatacenter',
];

const SEVERITY_RANK: Record<string, number> = {
  info: 0, low: 1, medium: 2, high: 3, critical: 4,
};

function severityToNum(s: string): number {
  return SEVERITY_RANK[s] ?? 0;
}

/**
 * Compute Shannon entropy over an array of integer counts.
 * Returns 0 if all counts are zero.
 */
function countEntropy(counts: number[]): number {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return 0;
  let h = 0;
  for (const c of counts) {
    if (c > 0) {
      const p = c / total;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

/**
 * Extract all 19 features for a given IP by querying the live database.
 * Uses a 90-day lookback for historical breadth while keeping queries fast.
 */
export async function extractIPFeatures(ip: string, lookbackDays = 90): Promise<IPFeatureVector> {
  const since = new Date(Date.now() - lookbackDays * 24 * 60 * 60 * 1000);

  // ── Event aggregation ─────────────────────────────────────────────────────
  const eventRows = await db.select({
    eventType: securityEvents.eventType,
    severity: securityEvents.severity,
    destinationPort: securityEvents.destinationPort,
    serverId: securityEvents.serverId,
    timestamp: securityEvents.timestamp,
  })
    .from(securityEvents)
    .where(and(
      eq(securityEvents.sourceIp, ip),
      gte(securityEvents.timestamp, since),
    ));

  const totalEvents = eventRows.length;
  if (totalEvents === 0) {
    return emptyFeatures();
  }

  const eventTypes = new Set(eventRows.map(r => r.eventType));
  const distinctEventTypes = eventTypes.size;

  let highCritCount = 0;
  let hasBruteForce = 0;
  let hasLateralMovement = 0;
  let hasCryptoMining = 0;
  let hasProxyScanner = 0;
  let hadSuccess = 0;
  let hadFailure = 0;

  const ports = new Set<number>();
  const servers = new Set<number>();
  const hourCounts = new Array<number>(24).fill(0);

  const timestamps: number[] = [];

  for (const r of eventRows) {
    const sev = r.severity ?? 'info';
    if (sev === 'high' || sev === 'critical') highCritCount++;

    const et = r.eventType;
    if (et === 'ssh_brute_force') hasBruteForce = 1;
    if (et === 'lateral_movement') hasLateralMovement = 1;
    if (et === 'crypto_mining') hasCryptoMining = 1;
    if (et === 'proxy_scanner_burst' || et === 'proxy_scanner_detected') hasProxyScanner = 1;
    if (et === 'ssh_login_success' || et === 'ssh_key_login') hadSuccess = 1;
    if (et === 'ssh_failed_password' || et === 'ssh_invalid_user') hadFailure = 1;

    if (r.destinationPort) ports.add(r.destinationPort);
    servers.add(r.serverId);

    const ts = new Date(r.timestamp).getTime();
    timestamps.push(ts);
    const hour = new Date(r.timestamp).getUTCHours();
    hourCounts[hour]++;
  }

  // Only count success as signal if there were prior failures (lateral movement)
  if (hadSuccess && !hadFailure) hadSuccess = 0;

  const ratioHighCritical = totalEvents > 0 ? highCritCount / totalEvents : 0;

  const tMin = Math.min(...timestamps);
  const tMax = Math.max(...timestamps);
  const hoursActive = Math.max(1, (tMax - tMin) / 3_600_000);
  const eventsPerHour = totalEvents / hoursActive;

  const hourEntropy = countEntropy(hourCounts);

  // ── DDoS escalation path ─────────────────────────────────────────────────
  const [rateLimitRow] = await db.select({ cnt: count(), escalatedCnt: sql<number>`COUNT(CASE WHEN ${rateLimitedIps.escalatedAt} IS NOT NULL THEN 1 END)` })
    .from(rateLimitedIps)
    .where(eq(rateLimitedIps.ip, ip));

  const wasRateLimited = (rateLimitRow?.cnt ?? 0) > 0 ? 1 : 0;
  const wasEscalated = (rateLimitRow?.escalatedCnt ?? 0) > 0 ? 1 : 0;

  // ── Incident severity ────────────────────────────────────────────────────
  const incidents = await db.select({ severity: socIncidents.severity })
    .from(socIncidents)
    .where(sql`${socIncidents.sourceIps}::jsonb @> ${JSON.stringify([ip])}::jsonb`);

  let maxIncidentSeverity = 0;
  for (const inc of incidents) {
    const rank = severityToNum(inc.severity);
    if (rank > maxIncidentSeverity) maxIncidentSeverity = rank;
  }

  // ── Threat intel cache ───────────────────────────────────────────────────
  const [cacheRow] = await db.select({ reputationScore: threatIntelCache.reputationScore, data: threatIntelCache.data })
    .from(threatIntelCache)
    .where(eq(threatIntelCache.indicator, ip))
    .limit(1);

  const abuseScore = cacheRow?.reputationScore ?? 0;
  const cacheData = cacheRow?.data as Record<string, unknown> | null ?? null;
  const totalReports = cacheData ? (cacheData.totalReports as number ?? 0) : 0;
  const vtMalicious = cacheData?.virusTotal
    ? ((cacheData.virusTotal as Record<string, number>).malicious ?? 0)
    : 0;

  const isp = (cacheData?.isp as string ?? '').toLowerCase();
  const usageType = (cacheData?.usageType as string ?? '').toLowerCase();
  const usageTypeDatacenter = (
    isp.includes('data center') || isp.includes('hosting') || isp.includes('transit') ||
    usageType.includes('data center') || usageType.includes('hosting')
  ) ? 1 : 0;

  return {
    totalEvents,
    distinctEventTypes,
    ratioHighCritical,
    hasBruteForce,
    hasLateralMovement,
    hasCryptoMining,
    hasProxyScanner,
    distinctPorts: ports.size,
    distinctServers: servers.size,
    eventsPerHour,
    hourEntropy,
    hadSuccess,
    wasRateLimited,
    wasEscalated,
    maxIncidentSeverity,
    abuseScore,
    totalReports,
    vtMalicious,
    usageTypeDatacenter,
  };
}

function emptyFeatures(): IPFeatureVector {
  return {
    totalEvents: 0, distinctEventTypes: 0, ratioHighCritical: 0,
    hasBruteForce: 0, hasLateralMovement: 0, hasCryptoMining: 0, hasProxyScanner: 0,
    distinctPorts: 0, distinctServers: 0, eventsPerHour: 0, hourEntropy: 0,
    hadSuccess: 0, wasRateLimited: 0, wasEscalated: 0, maxIncidentSeverity: 0,
    abuseScore: 0, totalReports: 0, vtMalicious: 0, usageTypeDatacenter: 0,
  };
}

/**
 * Serialize a feature vector to Float32Array in canonical order.
 * ONNX inference expects a positional vector — this is the contract
 * between the extractor and the model.
 */
export function featuresToVector(f: IPFeatureVector): Float32Array {
  const vec = new Float32Array(FEATURE_ORDER.length);
  for (let i = 0; i < FEATURE_ORDER.length; i++) {
    vec[i] = f[FEATURE_ORDER[i]];
  }
  return vec;
}
