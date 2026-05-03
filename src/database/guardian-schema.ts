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
