import {
  pgTable,
  serial,
  text,
  timestamp,
  integer,
  varchar,
  jsonb,
  real,
  index,
  boolean,
} from 'drizzle-orm/pg-core';

// ─── Tables Guardian READS (owned by AutomaBotHub API) ──────────────────────

export const instances = pgTable('instances', {
  id: serial('id').primaryKey(),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  subdomain: varchar('subdomain', { length: 255 }),
  userId: varchar('user_id', { length: 255 }),
  planId: integer('plan_id'),
  status: varchar('status', { length: 50 }),
  suspendedAt: timestamp('suspended_at'),
  suspensionReason: text('suspension_reason'),
  updatedAt: timestamp('updated_at'),
});

export const users = pgTable('users', {
  id: varchar('id', { length: 255 }).primaryKey(),
  name: varchar('name', { length: 255 }),
  email: varchar('email', { length: 255 }),
});

export const plans = pgTable('plans', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 100 }).notNull(),
  displayName: varchar('display_name', { length: 255 }),
  maxCpuMillicores: integer('max_cpu_millicores'),
  maxMemoryMb: integer('max_memory_mb'),
  storageGb: integer('storage_gb'),
});

export const instanceMetrics = pgTable('instance_metrics', {
  id: serial('id').primaryKey(),
  instanceId: varchar('instance_id', { length: 255 }).notNull(),
  timestamp: timestamp('timestamp').notNull(),
  cpuPercent: real('cpu_percent'),
  memoryMB: real('memory_mb'),
  networkOutMB: real('network_out_mb'),
  diskWriteMB: real('disk_write_mb'),
  activeConnections: integer('active_connections'),
  processCount: integer('process_count'),
  storageMB: real('storage_mb'),
  http4xxRate: real('http_4xx_rate'),
  totalHttp4xxRequests: integer('total_http_4xx_requests'),
  topFailedEndpoints: jsonb('top_failed_endpoints').$type<string[]>(),
});

// ─── Tables Guardian WRITES (owned by Guardian) ─────────────────────────────

export const instanceBehaviorProfiles = pgTable('instance_behavior_profiles', {
  id: serial('id').primaryKey(),
  instanceId: varchar('instance_id', { length: 255 }).notNull().unique(),
  p95CpuPercent: real('p95_cpu_percent').default(0).notNull(),
  p95MemoryMB: real('p95_memory_mb').default(0).notNull(),
  p95NetworkOutMB: real('p95_network_out_mb').default(0).notNull(),
  avgCpuPercent: real('avg_cpu_percent').default(0).notNull(),
  avgNetworkOutMB: real('avg_network_out_mb').default(0).notNull(),
  hourlyCpuAvg: jsonb('hourly_cpu_avg').$type<number[]>().default([]),
  totalSamplesUsed: integer('total_samples_used').default(0).notNull(),
  falsePositiveCount: integer('false_positive_count').default(0).notNull(),
  lastCalculatedAt: timestamp('last_calculated_at').defaultNow().notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

export const guardianDecisions = pgTable('guardian_decisions', {
  id: serial('id').primaryKey(),
  instanceId: varchar('instance_id', { length: 255 }).notNull(),
  userId: varchar('user_id', { length: 255 }).notNull(),
  aiAnalysisType: varchar('ai_analysis_type', { length: 100 }),
  aiConfidence: real('ai_confidence'),
  aiReasoning: text('ai_reasoning'),
  proposedAction: varchar('proposed_action', { length: 50 }),
  actionPlanText: text('action_plan_text'),
  status: varchar('status', { length: 30 }).default('pending_approval').notNull(),
  telegramMessageId: integer('telegram_message_id'),
  respondedAt: timestamp('responded_at'),
  executedAt: timestamp('executed_at'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, (table) => ({
  instanceIdx: index('guardian_decisions_instance_idx').on(table.instanceId),
  statusIdx: index('guardian_decisions_status_idx').on(table.status),
  expiresAtIdx: index('guardian_decisions_expires_at_idx').on(table.expiresAt),
}));

export const abuseIncidents = pgTable('abuse_incidents', {
  id: serial('id').primaryKey(),
  userId: varchar('user_id', { length: 255 }).notNull(),
  instanceId: varchar('instance_id', { length: 255 }).notNull(),
  type: varchar('type', { length: 100 }).notNull(),
  severity: varchar('severity', { length: 20 }).notNull(),
  reasoning: text('reasoning'),
  autoSuspended: boolean('auto_suspended').default(false),
  metadata: jsonb('metadata'),
  resolvedAt: timestamp('resolved_at'),
  createdAt: timestamp('created_at').defaultNow().notNull(),
});

// ─── SOC Agent Tables ──────────────────────────────────────────────────────

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
