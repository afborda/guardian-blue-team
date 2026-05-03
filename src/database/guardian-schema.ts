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

export const blockedIps = pgTable('blocked_ips', {
  id: serial('id').primaryKey(),
  ip: varchar('ip', { length: 45 }).notNull(),
  serverId: integer('server_id').notNull(),
  reason: varchar('reason', { length: 255 }).notNull(),
  playbookExecutionId: integer('playbook_execution_id'),
  incidentId: integer('incident_id'),
  blockedAt: timestamp('blocked_at').defaultNow().notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  unblockedAt: timestamp('unblocked_at'),
  active: boolean('active').default(true).notNull(),
}, (table) => ({
  activeIdx: index('blocked_ips_active_idx').on(table.active),
  expiresIdx: index('blocked_ips_expires_idx').on(table.expiresAt),
  ipServerIdx: index('blocked_ips_ip_server_idx').on(table.ip, table.serverId),
}));

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
