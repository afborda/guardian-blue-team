import {
  pgTable,
  serial,
  text,
  timestamp,
  integer,
  varchar,
  jsonb,
  index,
  boolean,
  real,
  bigint,
  uniqueIndex,
  numeric,
  date,
  primaryKey,
} from 'drizzle-orm/pg-core';

// ─── Guardian SOC Tables (owned and managed by Guardian) ────────────────────

export const socServers = pgTable('soc_servers', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  host: varchar('host', { length: 255 }).notNull(),
  sshPort: integer('ssh_port').default(22).notNull(),
  sshUser: varchar('ssh_user', { length: 100 }).default('ubuntu').notNull(),
  sshKeyPath: varchar('ssh_key_path', { length: 500 }),
  tags: jsonb('tags').$type<string[]>().default([]),
  enabled: boolean('enabled').default(true).notNull(),
  lastSeenAt: timestamp('last_seen_at'),
  falcoInstalledAt: timestamp('falco_installed_at'),
  // Tier 0 hardening (PR1). See connection.ts DDL for semantics.
  installMode: varchar('install_mode', { length: 20 }),
  sshFingerprint: varchar('ssh_fingerprint', { length: 128 }),
  guardianShellVersion: varchar('guardian_shell_version', { length: 20 }),
  upgradedAt: timestamp('upgraded_at'),
  lastHeartbeatAt: timestamp('last_heartbeat_at'),
  osFamily: varchar('os_family', { length: 30 }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

export const securityEvents = pgTable('security_events', {
  id: serial('id').primaryKey(),
  serverId: integer('server_id').notNull(),
  timestamp: timestamp('timestamp').notNull(),
  source: varchar('source', { length: 50 }).notNull(),
  category: varchar('category', { length: 50 }).notNull(),
  severity: varchar('severity', { length: 20 }).default('info').notNull(),
  eventType: varchar('event_type', { length: 100 }).notNull(),
  sourceIp: varchar('source_ip', { length: 45 }),
  destinationPort: integer('destination_port'),
  userName: varchar('user_name', { length: 255 }),
  processName: varchar('process_name', { length: 255 }),
  rawLog: text('raw_log'),
  metadata: jsonb('metadata'),
  enrichment: jsonb('enrichment'),
  incidentId: integer('incident_id'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  serverIdx: index('security_events_server_idx').on(table.serverId),
  timestampIdx: index('security_events_timestamp_idx').on(table.timestamp),
  eventTypeIdx: index('security_events_event_type_idx').on(table.eventType),
  sourceIpIdx: index('security_events_source_ip_idx').on(table.sourceIp),
  severityIdx: index('security_events_severity_idx').on(table.severity),
}));

export const socIncidents = pgTable('soc_incidents', {
  id: serial('id').primaryKey(),
  title: varchar('title', { length: 500 }).notNull(),
  severity: varchar('severity', { length: 20 }).notNull(),
  status: varchar('status', { length: 30 }).default('open').notNull(),
  category: varchar('category', { length: 100 }),
  sourceIps: jsonb('source_ips').$type<string[]>().default([]),
  affectedServers: jsonb('affected_servers').$type<number[]>().default([]),
  eventCount: integer('event_count').default(0).notNull(),
  firstSeenAt: timestamp('first_seen_at').notNull(),
  lastSeenAt: timestamp('last_seen_at').notNull(),
  resolvedAt: timestamp('resolved_at'),
  aiSummary: text('ai_summary'),
  playbookId: varchar('playbook_id', { length: 100 }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  statusIdx: index('soc_incidents_status_idx').on(table.status),
  severityIdx: index('soc_incidents_severity_idx').on(table.severity),
}));

export const playbookExecutions = pgTable('playbook_executions', {
  id: serial('id').primaryKey(),
  playbookName: varchar('playbook_name', { length: 100 }).notNull(),
  incidentId: integer('incident_id'),
  serverId: integer('server_id'),
  triggerType: varchar('trigger_type', { length: 50 }),
  status: varchar('status', { length: 30 }).default('running').notNull(),
  stepsCompleted: jsonb('steps_completed').$type<string[]>().default([]),
  stepsFailed: jsonb('steps_failed').$type<string[]>().default([]),
  startedAt: timestamp('started_at').defaultNow().notNull(),
  completedAt: timestamp('completed_at'),
  triggeredBy: varchar('triggered_by', { length: 255 }),
});

export const threatIntelCache = pgTable('threat_intel_cache', {
  id: serial('id').primaryKey(),
  indicator: varchar('indicator', { length: 500 }).notNull(),
  indicatorType: varchar('indicator_type', { length: 50 }).notNull(),
  source: varchar('source', { length: 100 }).notNull(),
  reputationScore: integer('reputation_score'),
  data: jsonb('data'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  indicatorSourceIdx: index('threat_intel_indicator_source_idx').on(table.indicator, table.source),
  expiresIdx: index('threat_intel_expires_idx').on(table.expiresAt),
}));

export const vulnerabilities = pgTable('vulnerabilities', {
  id: serial('id').primaryKey(),
  serverId: integer('server_id').notNull(),
  category: varchar('category', { length: 50 }),
  severity: varchar('severity', { length: 20 }),
  title: varchar('title', { length: 500 }),
  description: text('description'),
  cveId: varchar('cve_id', { length: 20 }),
  remediation: text('remediation'),
  status: varchar('status', { length: 30 }).default('open').notNull(),
  detectedAt: timestamp('detected_at').defaultNow().notNull(),
  fixedAt: timestamp('fixed_at'),
});

export const cveAlerts = pgTable('cve_alerts', {
  id: serial('id').primaryKey(),
  cveId: varchar('cve_id', { length: 30 }).notNull(),
  serverId: integer('server_id').notNull(),
  packageName: varchar('package_name', { length: 200 }).notNull(),
  installedVersion: varchar('installed_version', { length: 100 }).notNull(),
  fixedVersion: varchar('fixed_version', { length: 100 }),
  ecosystem: varchar('ecosystem', { length: 50 }).notNull(),
  cvssScore: integer('cvss_score'),
  summary: text('summary'),
  status: varchar('status', { length: 30 }).default('pending').notNull(),
  notifiedAt: timestamp('notified_at'),
  resolvedAt: timestamp('resolved_at'),
  resolvedBy: varchar('resolved_by', { length: 100 }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  cveServerIdx: index('cve_alerts_cve_server_idx').on(table.cveId, table.serverId),
  statusIdx: index('cve_alerts_status_idx').on(table.status),
}));

// EPSS (Exploit Prediction Scoring System) — daily snapshot per CVE
// Source: https://api.first.org/data/v1/epss
export const cveEpss = pgTable('cve_epss', {
  cveId: varchar('cve_id', { length: 20 }).primaryKey(),
  epssScore: numeric('epss_score', { precision: 6, scale: 5, mode: 'number' }).notNull(),
  percentile: numeric('percentile', { precision: 6, scale: 5, mode: 'number' }).notNull(),
  fetchedAt: timestamp('fetched_at').defaultNow().notNull(),
}, (table) => ({
  scoreIdx: index('cve_epss_score_idx').on(table.epssScore),
}));

// 30-day rolling history for EPSS trend detection
export const cveEpssHistory = pgTable('cve_epss_history', {
  id: bigint('id', { mode: 'number' }).primaryKey().generatedAlwaysAsIdentity(),
  cveId: varchar('cve_id', { length: 20 }).notNull(),
  epssScore: numeric('epss_score', { precision: 6, scale: 5, mode: 'number' }).notNull(),
  percentile: numeric('percentile', { precision: 6, scale: 5, mode: 'number' }).notNull(),
  snapshotDate: date('snapshot_date').notNull(),
}, (table) => ({
  cveDateIdx: index('cve_epss_history_cve_date_idx').on(table.cveId, table.snapshotDate),
  dateIdx: index('cve_epss_history_date_idx').on(table.snapshotDate),
  cveDateUq: uniqueIndex('cve_epss_history_cve_date_uq').on(table.cveId, table.snapshotDate),
}));

// CISA KEV (Known Exploited Vulnerabilities) — confirmed exploited in the wild
// Source: https://github.com/cisagov/kev-data (GitHub mirror; cisa.gov direct feed is Akamai-blocked from datacenter IPs)
export const cveKev = pgTable('cve_kev', {
  cveId: varchar('cve_id', { length: 20 }).primaryKey(),
  vendorProject: varchar('vendor_project', { length: 200 }),
  product: varchar('product', { length: 200 }),
  vulnerabilityName: varchar('vulnerability_name', { length: 500 }),
  dateAdded: date('date_added').notNull(),
  shortDescription: text('short_description'),
  requiredAction: text('required_action'),
  dueDate: date('due_date'),
  ransomwareUse: boolean('ransomware_use').default(false),
  notes: text('notes'),
  cwes: text('cwes'),
  fetchedAt: timestamp('fetched_at').defaultNow().notNull(),
}, (table) => ({
  dateAddedIdx: index('cve_kev_date_added_idx').on(table.dateAdded),
}));

export const blockedIps = pgTable('blocked_ips', {
  id: serial('id').primaryKey(),
  ip: varchar('ip', { length: 45 }).notNull(),
  serverId: integer('server_id').notNull(),
  reason: varchar('reason', { length: 255 }).notNull(),
  playbookExecutionId: integer('playbook_execution_id'),
  incidentId: integer('incident_id'),
  blockedAt: timestamp('blocked_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at'),
  unblockedAt: timestamp('unblocked_at'),
  active: boolean('active').default(true).notNull(),
  verified: boolean('verified').default(false),
  method: varchar('method', { length: 20 }),
  lastVerifiedAt: timestamp('last_verified_at'),
  consecutiveVerifyFailures: integer('consecutive_verify_failures').notNull().default(0),
}, (table) => ({
  activeIdx: index('blocked_ips_active_idx').on(table.active),
  expiresIdx: index('blocked_ips_expires_idx').on(table.expiresAt),
  ipServerIdx: index('blocked_ips_ip_server_idx').on(table.ip, table.serverId),
}));

// ─── Block Propagation Queue ────────────────────────────────────────────────
// Persistent queue ensuring every blocked IP reaches every monitored server,
// even when servers are temporarily offline. Drained by BlockPropagationWorker.
export const blockPropagationQueue = pgTable('block_propagation_queue', {
  id: serial('id').primaryKey(),
  ip: varchar('ip', { length: 45 }).notNull(),
  targetServerId: integer('target_server_id').notNull(),
  sourceServerId: integer('source_server_id'),
  incidentId: integer('incident_id'),
  reason: varchar('reason', { length: 255 }),
  attempts: integer('attempts').notNull().default(0),
  maxAttempts: integer('max_attempts').notNull().default(5),
  status: varchar('status', { length: 20 }).notNull().default('pending'),
  lastError: varchar('last_error', { length: 500 }),
  nextRetryAt: timestamp('next_retry_at').defaultNow().notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  lastTriedAt: timestamp('last_tried_at'),
  completedAt: timestamp('completed_at'),
}, (table) => ({
  statusRetryIdx: index('block_prop_status_retry_idx').on(table.status, table.nextRetryAt),
  ipTargetIdx: index('block_prop_ip_target_idx').on(table.ip, table.targetServerId),
}));

// ─── Rate Limiting (DDoS Graduated Response) ────────────────────────────────────

export const rateLimitedIps = pgTable('rate_limited_ips', {
  id: serial('id').primaryKey(),
  ip: varchar('ip', { length: 45 }).notNull(),
  serverId: integer('server_id').notNull(),
  limitPerSec: integer('limit_per_sec').notNull().default(10),
  burst: integer('burst').notNull().default(20),
  reason: varchar('reason', { length: 255 }),
  incidentId: integer('incident_id'),
  appliedAt: timestamp('applied_at').defaultNow().notNull(),
  escalatedAt: timestamp('escalated_at'),
  removedAt: timestamp('removed_at'),
  active: boolean('active').default(true).notNull(),
}, (table) => ({
  activeIdx: index('rate_limited_ips_active_idx').on(table.active),
}));

// ─── Threat Hunt Findings ───────────────────────────────────────────────────────

export const threatHuntFindings = pgTable('threat_hunt_findings', {
  id: serial('id').primaryKey(),
  runAt: timestamp('run_at').defaultNow().notNull(),
  eventsAnalyzed: integer('events_analyzed').notNull().default(0),
  finding: text('finding').notNull(),
  severity: varchar('severity', { length: 20 }).default('medium'),
  aiProvider: varchar('ai_provider', { length: 30 }),
  notified: boolean('notified').default(false),
});

// ─── Infrastructure Monitoring Tables ──────────────────────────────────────────

export const serverMetrics = pgTable('server_metrics', {
  id: serial('id').primaryKey(),
  serverId: integer('server_id').notNull(),
  collectedAt: timestamp('collected_at').notNull(),
  load1: real('load_1'),
  load5: real('load_5'),
  load15: real('load_15'),
  cpuCount: integer('cpu_count'),
  memTotalBytes: bigint('mem_total_bytes', { mode: 'number' }),
  memUsedBytes: bigint('mem_used_bytes', { mode: 'number' }),
  memAvailableBytes: bigint('mem_available_bytes', { mode: 'number' }),
  swapTotalBytes: bigint('swap_total_bytes', { mode: 'number' }),
  swapUsedBytes: bigint('swap_used_bytes', { mode: 'number' }),
  disks: jsonb('disks').$type<Array<{ mountpoint: string; usedPercent: number; availableBytes: number }>>().default([]),
  uptimeSeconds: integer('uptime_seconds'),
  diskIo: jsonb('disk_io').$type<Array<{ device: string; readBps: number; writeBps: number }>>(),
  networkIo: jsonb('network_io').$type<Array<{ iface: string; rxBps: number; txBps: number }>>(),
  failedUnits: jsonb('failed_units').$type<string[]>().default([]),
  kernelErrors: integer('kernel_errors').default(0),
  journalErrors: integer('journal_errors').default(0),
}, (table) => ({
  serverCollectedIdx: index('server_metrics_server_collected_idx').on(table.serverId, table.collectedAt),
}));

export const serverScores = pgTable('server_scores', {
  id: serial('id').primaryKey(),
  serverId: integer('server_id').notNull(),
  periodStart: timestamp('period_start').notNull(),
  periodEnd: timestamp('period_end').notNull(),
  periodType: varchar('period_type', { length: 10 }).default('hourly').notNull(),
  healthScore: integer('health_score').notNull(),
  securityScore: integer('security_score').notNull(),
  qualityScore: integer('quality_score').notNull(),
  wasteScore: integer('waste_score').notNull(),
  vulnerabilityScore: integer('vulnerability_score').notNull(),
  availabilityScore: integer('availability_score').notNull(),
  overallScore: integer('overall_score').notNull(),
  scoreDetails: jsonb('score_details').$type<Record<string, unknown>>().default({}),
}, (table) => ({
  serverPeriodIdx: uniqueIndex('server_scores_server_period_idx').on(table.serverId, table.periodStart, table.periodType),
}));

// ─── ML Behavioral Baselines ──────────────────────────────────────────────────

export const behaviorProfiles = pgTable('behavior_profiles', {
  id: serial('id').primaryKey(),
  serverId: integer('server_id').notNull(),
  profileType: varchar('profile_type', { length: 30 }).notNull(),
  subjectId: varchar('subject_id', { length: 255 }).notNull(),
  profile: jsonb('profile').$type<Record<string, unknown>>().notNull(),
  sampleCount: integer('sample_count').default(0).notNull(),
  lastUpdatedAt: timestamp('last_updated_at').defaultNow().notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  subjectIdx: uniqueIndex('behavior_profiles_subject_idx').on(table.serverId, table.profileType, table.subjectId),
}));

// ─── Container Runtime Security ────────────────────────────────────────────

export const containerSnapshots = pgTable('container_snapshots', {
  id: serial('id').primaryKey(),
  serverId: integer('server_id').notNull(),
  containerName: varchar('container_name', { length: 200 }).notNull(),
  imageName: varchar('image_name', { length: 300 }),
  processes: jsonb('processes').$type<Array<{ pid: number; user: string; cpu: number; mem: number; command: string; args: string }>>(),
  network: jsonb('network').$type<Array<{ remoteIp: string; remotePort: number; localPort: number; state: string }>>(),
  filesystemChanges: jsonb('filesystem_changes').$type<string[]>(),
  securityConfig: jsonb('security_config').$type<{ readOnly: boolean; noNewPrivs: boolean; capDrop: string[]; memoryLimit: number; cpuQuota: number }>(),
  cveCount: integer('cve_count').default(0),
  status: varchar('status', { length: 20 }).default('running'),
  collectedAt: timestamp('collected_at').defaultNow().notNull(),
}, (table) => ({
  serverIdx: index('container_snapshots_server_idx').on(table.serverId, table.collectedAt),
  nameIdx: index('container_snapshots_name_idx').on(table.serverId, table.containerName),
}));

export const incidentMemory = pgTable('incident_memory', {
  id: serial('id').primaryKey(),
  incidentId: integer('incident_id'),
  category: varchar('category', { length: 100 }).notNull(),
  title: varchar('title', { length: 500 }).notNull(),
  sourceIps: jsonb('source_ips').$type<string[]>().default([]),
  resolution: varchar('resolution', { length: 500 }),
  outcome: varchar('outcome', { length: 30 }),
  falsePositive: boolean('false_positive').default(false).notNull(),
  rootCause: text('root_cause'),
  timeToContainMinutes: integer('time_to_contain_minutes'),
  tags: jsonb('tags').$type<string[]>().default([]),
  embedding: jsonb('embedding').$type<number[]>(),
  // Tracks which embedding model produced `embedding`. Required so that
  // switching between two models of identical dimension (e.g. bge-m3 1024d
  // ↔ mxbai-embed-large 1024d) can still trigger re-embedding — comparing
  // dimension alone would silently mix two distinct vector spaces.
  embeddingModel: varchar('embedding_model', { length: 100 }),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  categoryIdx: index('incident_memory_category_idx').on(table.category),
  createdIdx: index('incident_memory_created_idx').on(table.createdAt),
}));

export const trustedEntities = pgTable('trusted_entities', {
  id: serial('id').primaryKey(),
  entityType: varchar('entity_type', { length: 20 }).notNull(), // 'ip' | 'fingerprint'
  value: varchar('value', { length: 500 }).notNull(),
  addedBy: varchar('added_by', { length: 100 }),
  addedAt: timestamp('added_at').defaultNow().notNull(),
  note: varchar('note', { length: 500 }),
}, (table) => ({
  typeValueIdx: uniqueIndex('trusted_entities_type_value_idx').on(table.entityType, table.value),
}));

export const ipThreatScores = pgTable('ip_threat_scores', {
  id: serial('id').primaryKey(),
  ip: varchar('ip', { length: 45 }).notNull().unique(),
  threatScore: real('threat_score').notNull(),
  isDangerous: boolean('is_dangerous').default(false).notNull(),
  features: jsonb('features').$type<Record<string, number>>(),
  country: varchar('country', { length: 10 }),
  isp: text('isp'),
  abuseScore: integer('abuse_score'),
  vtMalicious: integer('vt_malicious'),
  source: varchar('source', { length: 20 }).default('heuristic').notNull(),
  scoredAt: timestamp('scored_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at').notNull(),
}, (table) => ({
  ipIdx: index('ip_threat_scores_ip_idx').on(table.ip),
  dangerousIdx: index('ip_threat_scores_dangerous_idx').on(table.isDangerous, table.scoredAt),
}));

export const auditLogs = pgTable('audit_logs', {
  id: serial('id').primaryKey(),
  category: varchar('category', { length: 30 }).notNull(), // operational | access | block
  eventType: varchar('event_type', { length: 100 }).notNull(),
  serverId: integer('server_id'),
  timestamp: timestamp('timestamp').defaultNow().notNull(),
  actor: varchar('actor', { length: 255 }),       // system | telegram | auto-enforce | user
  resource: varchar('resource', { length: 500 }), // IP, file path, username
  action: varchar('action', { length: 100 }),
  result: varchar('result', { length: 30 }),       // success | failure | skipped
  details: jsonb('details').$type<Record<string, unknown>>(),
  relatedIncidentId: integer('related_incident_id'),
  relatedPlaybookId: integer('related_playbook_id'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
}, (table) => ({
  serverIdx: index('audit_logs_server_idx').on(table.serverId, table.createdAt),
  categoryIdx: index('audit_logs_category_idx').on(table.category, table.eventType),
  timestampIdx: index('audit_logs_timestamp_idx').on(table.timestamp),
}));

// Persistent baseline for DiscoveryWorker. Stored per server-name (not id) so
// renaming a soc_servers row doesn't lose the baseline. Baseline survives
// container restarts — without this, every restart caused the next 24h cycle
// to fire a "Re-Discovery: changes detected" false positive against an empty
// in-memory Map.
export const discoveryBaselines = pgTable('discovery_baselines', {
  serverName: varchar('server_name', { length: 255 }).primaryKey(),
  services: jsonb('services').$type<string[]>().default([]).notNull(),
  ports: jsonb('ports').$type<number[]>().default([]).notNull(),
  architecture: varchar('architecture', { length: 100 }).default('').notNull(),
  knownContainers: jsonb('known_containers').$type<string[]>().default([]).notNull(),
  capturedAt: timestamp('captured_at').defaultNow().notNull(),
});

// Tier 0 hardening (PR1). Per-collector cursor state — fixes the "cursor not
// persisted" bug where every collector restarted from `now() - interval` on
// every loop, causing event loss during downtime and double-collection on
// restart. last_cursor is opaque text (collector-defined format documented
// in cursor_meta).
export const collectorState = pgTable('collector_state', {
  serverId: integer('server_id').notNull(),
  collectorName: varchar('collector_name', { length: 50 }).notNull(),
  lastCursor: text('last_cursor'),
  cursorMeta: jsonb('cursor_meta').$type<Record<string, unknown>>().default({}),
  lastRunAt: timestamp('last_run_at'),
  lastError: text('last_error'),
  consecutiveFailures: integer('consecutive_failures').default(0).notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.serverId, table.collectorName] }),
}));
