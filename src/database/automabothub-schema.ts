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

// ─── AutomaBotHub Tables (Guardian reads, AutomaBotHub API owns) ────────────
// These tables exist in the AutomaBotHub database.
// Guardian only reads instances/metrics and writes guardian_decisions/abuse_incidents.

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
