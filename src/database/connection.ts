import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

let _db: NodePgDatabase | null = null;
let _closeHandler: (() => Promise<void>) | null = null;

async function initPostgres(): Promise<void> {
  const pool = new Pool({
    connectionString: config.database.url!,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  pool.on('error', (err) => {
    logger.error({ err }, 'Database pool error');
  });

  await createPostgresTables(pool);

  _db = drizzle(pool);
  _closeHandler = async () => { await pool.end(); };

  logger.info('PostgreSQL database initialized');
}

async function createPostgresTables(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS soc_servers (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        host VARCHAR(255) NOT NULL,
        ssh_port INTEGER NOT NULL DEFAULT 22,
        ssh_user VARCHAR(100) NOT NULL DEFAULT 'ubuntu',
        ssh_key_path VARCHAR(500),
        tags JSONB DEFAULT '[]',
        enabled BOOLEAN NOT NULL DEFAULT true,
        last_seen_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS security_events (
        id SERIAL PRIMARY KEY,
        server_id INTEGER NOT NULL,
        timestamp TIMESTAMP NOT NULL,
        source VARCHAR(50) NOT NULL,
        category VARCHAR(50) NOT NULL,
        severity VARCHAR(20) NOT NULL DEFAULT 'info',
        event_type VARCHAR(100) NOT NULL,
        source_ip VARCHAR(45),
        destination_port INTEGER,
        user_name VARCHAR(255),
        process_name VARCHAR(255),
        raw_log TEXT,
        metadata JSONB,
        enrichment JSONB,
        incident_id INTEGER,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS security_events_server_idx ON security_events(server_id);
      CREATE INDEX IF NOT EXISTS security_events_timestamp_idx ON security_events(timestamp);
      CREATE INDEX IF NOT EXISTS security_events_event_type_idx ON security_events(event_type);
      CREATE INDEX IF NOT EXISTS security_events_source_ip_idx ON security_events(source_ip);
      CREATE INDEX IF NOT EXISTS security_events_severity_idx ON security_events(severity);

      CREATE TABLE IF NOT EXISTS soc_incidents (
        id SERIAL PRIMARY KEY,
        title VARCHAR(500) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'open',
        category VARCHAR(100),
        source_ips JSONB DEFAULT '[]',
        affected_servers JSONB DEFAULT '[]',
        event_count INTEGER NOT NULL DEFAULT 0,
        first_seen_at TIMESTAMP NOT NULL,
        last_seen_at TIMESTAMP NOT NULL,
        resolved_at TIMESTAMP,
        ai_summary TEXT,
        playbook_id VARCHAR(100),
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS soc_incidents_status_idx ON soc_incidents(status);
      CREATE INDEX IF NOT EXISTS soc_incidents_severity_idx ON soc_incidents(severity);

      CREATE TABLE IF NOT EXISTS playbook_executions (
        id SERIAL PRIMARY KEY,
        playbook_name VARCHAR(100) NOT NULL,
        incident_id INTEGER,
        server_id INTEGER,
        trigger_type VARCHAR(50),
        status VARCHAR(30) NOT NULL DEFAULT 'running',
        steps_completed JSONB DEFAULT '[]',
        steps_failed JSONB DEFAULT '[]',
        started_at TIMESTAMP NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMP,
        triggered_by VARCHAR(255)
      );

      CREATE TABLE IF NOT EXISTS threat_intel_cache (
        id SERIAL PRIMARY KEY,
        indicator VARCHAR(500) NOT NULL,
        indicator_type VARCHAR(50) NOT NULL,
        source VARCHAR(100) NOT NULL,
        reputation_score INTEGER,
        data JSONB,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS threat_intel_indicator_source_idx ON threat_intel_cache(indicator, source);
      CREATE INDEX IF NOT EXISTS threat_intel_expires_idx ON threat_intel_cache(expires_at);

      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id SERIAL PRIMARY KEY,
        server_id INTEGER NOT NULL,
        category VARCHAR(50),
        severity VARCHAR(20),
        title VARCHAR(500),
        description TEXT,
        cve_id VARCHAR(20),
        remediation TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'open',
        detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
        fixed_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cve_alerts (
        id SERIAL PRIMARY KEY,
        cve_id VARCHAR(30) NOT NULL,
        server_id INTEGER NOT NULL,
        package_name VARCHAR(200) NOT NULL,
        installed_version VARCHAR(100) NOT NULL,
        fixed_version VARCHAR(100),
        ecosystem VARCHAR(50) NOT NULL,
        cvss_score INTEGER,
        summary TEXT,
        status VARCHAR(30) NOT NULL DEFAULT 'pending',
        notified_at TIMESTAMP,
        resolved_at TIMESTAMP,
        resolved_by VARCHAR(100),
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS cve_alerts_cve_server_idx ON cve_alerts(cve_id, server_id);
      CREATE INDEX IF NOT EXISTS cve_alerts_status_idx ON cve_alerts(status);

      CREATE TABLE IF NOT EXISTS blocked_ips (
        id SERIAL PRIMARY KEY,
        ip VARCHAR(45) NOT NULL,
        server_id INTEGER NOT NULL,
        reason VARCHAR(255) NOT NULL,
        playbook_execution_id INTEGER,
        incident_id INTEGER,
        blocked_at TIMESTAMP NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        unblocked_at TIMESTAMP,
        active BOOLEAN NOT NULL DEFAULT true
      );
      CREATE INDEX IF NOT EXISTS blocked_ips_active_idx ON blocked_ips(active);
      CREATE INDEX IF NOT EXISTS blocked_ips_expires_idx ON blocked_ips(expires_at);
      CREATE INDEX IF NOT EXISTS blocked_ips_ip_server_idx ON blocked_ips(ip, server_id);

      CREATE TABLE IF NOT EXISTS server_metrics (
        id SERIAL PRIMARY KEY,
        server_id INTEGER NOT NULL,
        collected_at TIMESTAMP NOT NULL,
        load_1 REAL,
        load_5 REAL,
        load_15 REAL,
        cpu_count INTEGER,
        mem_total_bytes BIGINT,
        mem_used_bytes BIGINT,
        mem_available_bytes BIGINT,
        swap_total_bytes BIGINT,
        swap_used_bytes BIGINT,
        disks JSONB DEFAULT '[]',
        uptime_seconds INTEGER,
        disk_io JSONB,
        network_io JSONB,
        failed_units JSONB DEFAULT '[]',
        kernel_errors INTEGER DEFAULT 0,
        journal_errors INTEGER DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS server_metrics_server_collected_idx ON server_metrics(server_id, collected_at);

      CREATE TABLE IF NOT EXISTS server_scores (
        id SERIAL PRIMARY KEY,
        server_id INTEGER NOT NULL,
        period_start TIMESTAMP NOT NULL,
        period_end TIMESTAMP NOT NULL,
        period_type VARCHAR(10) NOT NULL DEFAULT 'hourly',
        health_score INTEGER NOT NULL,
        security_score INTEGER NOT NULL,
        quality_score INTEGER NOT NULL,
        waste_score INTEGER NOT NULL,
        vulnerability_score INTEGER NOT NULL,
        availability_score INTEGER NOT NULL,
        overall_score INTEGER NOT NULL,
        score_details JSONB DEFAULT '{}'
      );
      CREATE UNIQUE INDEX IF NOT EXISTS server_scores_server_period_idx ON server_scores(server_id, period_start, period_type);
    `);
  } finally {
    client.release();
  }
}

async function initSqlite(): Promise<void> {
  const { default: Database } = await import('better-sqlite3');
  const { drizzle: sqliteDrizzle } = await import('drizzle-orm/better-sqlite3');
  const { mkdirSync } = await import('fs');
  const { dirname } = await import('path');

  const defaultPath = process.env.NODE_ENV === 'production' ? '/data/guardian.db' : './data/guardian.db';
  const dbPath = config.database.url?.replace('sqlite:', '') || defaultPath;
  mkdirSync(dirname(dbPath), { recursive: true });

  const sqlite = new Database(dbPath);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');

  createSqliteTables(sqlite);

  // Cast to NodePgDatabase — Drizzle's query builder API is identical at runtime
  _db = sqliteDrizzle(sqlite) as unknown as NodePgDatabase;
  _closeHandler = async () => { sqlite.close(); };

  logger.info({ path: dbPath }, 'SQLite database initialized');
}

function createSqliteTables(sqlite: { exec: (sql: string) => void }): void {
  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS soc_servers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name VARCHAR(100) NOT NULL UNIQUE,
      host VARCHAR(255) NOT NULL,
      ssh_port INTEGER NOT NULL DEFAULT 22,
      ssh_user VARCHAR(100) NOT NULL DEFAULT 'ubuntu',
      ssh_key_path VARCHAR(500),
      tags TEXT DEFAULT '[]',
      enabled INTEGER NOT NULL DEFAULT 1,
      last_seen_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS security_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      timestamp TEXT NOT NULL,
      source VARCHAR(50) NOT NULL,
      category VARCHAR(50) NOT NULL,
      severity VARCHAR(20) NOT NULL DEFAULT 'info',
      event_type VARCHAR(100) NOT NULL,
      source_ip VARCHAR(45),
      destination_port INTEGER,
      user_name VARCHAR(255),
      process_name VARCHAR(255),
      raw_log TEXT,
      metadata TEXT,
      enrichment TEXT,
      incident_id INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS security_events_server_idx ON security_events(server_id);
    CREATE INDEX IF NOT EXISTS security_events_timestamp_idx ON security_events(timestamp);
    CREATE INDEX IF NOT EXISTS security_events_event_type_idx ON security_events(event_type);
    CREATE INDEX IF NOT EXISTS security_events_source_ip_idx ON security_events(source_ip);
    CREATE INDEX IF NOT EXISTS security_events_severity_idx ON security_events(severity);

    CREATE TABLE IF NOT EXISTS soc_incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title VARCHAR(500) NOT NULL,
      severity VARCHAR(20) NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'open',
      category VARCHAR(100),
      source_ips TEXT DEFAULT '[]',
      affected_servers TEXT DEFAULT '[]',
      event_count INTEGER NOT NULL DEFAULT 0,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      resolved_at TEXT,
      ai_summary TEXT,
      playbook_id VARCHAR(100),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS soc_incidents_status_idx ON soc_incidents(status);
    CREATE INDEX IF NOT EXISTS soc_incidents_severity_idx ON soc_incidents(severity);

    CREATE TABLE IF NOT EXISTS playbook_executions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      playbook_name VARCHAR(100) NOT NULL,
      incident_id INTEGER,
      server_id INTEGER,
      trigger_type VARCHAR(50),
      status VARCHAR(30) NOT NULL DEFAULT 'running',
      steps_completed TEXT DEFAULT '[]',
      steps_failed TEXT DEFAULT '[]',
      started_at TEXT NOT NULL DEFAULT (datetime('now')),
      completed_at TEXT,
      triggered_by VARCHAR(255)
    );

    CREATE TABLE IF NOT EXISTS threat_intel_cache (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      indicator VARCHAR(500) NOT NULL,
      indicator_type VARCHAR(50) NOT NULL,
      source VARCHAR(100) NOT NULL,
      reputation_score INTEGER,
      data TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS threat_intel_indicator_source_idx ON threat_intel_cache(indicator, source);
    CREATE INDEX IF NOT EXISTS threat_intel_expires_idx ON threat_intel_cache(expires_at);

    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      category VARCHAR(50),
      severity VARCHAR(20),
      title VARCHAR(500),
      description TEXT,
      cve_id VARCHAR(20),
      remediation TEXT,
      status VARCHAR(30) NOT NULL DEFAULT 'open',
      detected_at TEXT NOT NULL DEFAULT (datetime('now')),
      fixed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS cve_alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cve_id VARCHAR(30) NOT NULL,
      server_id INTEGER NOT NULL,
      package_name VARCHAR(200) NOT NULL,
      installed_version VARCHAR(100) NOT NULL,
      fixed_version VARCHAR(100),
      ecosystem VARCHAR(50) NOT NULL,
      cvss_score INTEGER,
      summary TEXT,
      status VARCHAR(30) NOT NULL DEFAULT 'pending',
      notified_at TEXT,
      resolved_at TEXT,
      resolved_by VARCHAR(100),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS cve_alerts_cve_server_idx ON cve_alerts(cve_id, server_id);
    CREATE INDEX IF NOT EXISTS cve_alerts_status_idx ON cve_alerts(status);

    CREATE TABLE IF NOT EXISTS blocked_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip VARCHAR(45) NOT NULL,
      server_id INTEGER NOT NULL,
      reason VARCHAR(255) NOT NULL,
      playbook_execution_id INTEGER,
      incident_id INTEGER,
      blocked_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      unblocked_at TEXT,
      active INTEGER NOT NULL DEFAULT 1
    );
    CREATE INDEX IF NOT EXISTS blocked_ips_active_idx ON blocked_ips(active);
    CREATE INDEX IF NOT EXISTS blocked_ips_expires_idx ON blocked_ips(expires_at);
    CREATE INDEX IF NOT EXISTS blocked_ips_ip_server_idx ON blocked_ips(ip, server_id);

    CREATE TABLE IF NOT EXISTS server_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      collected_at TEXT NOT NULL,
      load_1 REAL,
      load_5 REAL,
      load_15 REAL,
      cpu_count INTEGER,
      mem_total_bytes INTEGER,
      mem_used_bytes INTEGER,
      mem_available_bytes INTEGER,
      swap_total_bytes INTEGER,
      swap_used_bytes INTEGER,
      disks TEXT DEFAULT '[]',
      uptime_seconds INTEGER,
      disk_io TEXT,
      network_io TEXT,
      failed_units TEXT DEFAULT '[]',
      kernel_errors INTEGER DEFAULT 0,
      journal_errors INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS server_metrics_server_collected_idx ON server_metrics(server_id, collected_at);

    CREATE TABLE IF NOT EXISTS server_scores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      server_id INTEGER NOT NULL,
      period_start TEXT NOT NULL,
      period_end TEXT NOT NULL,
      period_type VARCHAR(10) NOT NULL DEFAULT 'hourly',
      health_score INTEGER NOT NULL,
      security_score INTEGER NOT NULL,
      quality_score INTEGER NOT NULL,
      waste_score INTEGER NOT NULL,
      vulnerability_score INTEGER NOT NULL,
      availability_score INTEGER NOT NULL,
      overall_score INTEGER NOT NULL,
      score_details TEXT DEFAULT '{}'
    );
    CREATE UNIQUE INDEX IF NOT EXISTS server_scores_server_period_idx ON server_scores(server_id, period_start, period_type);
  `);
}

export async function initDatabase(): Promise<void> {
  if (config.database.isSqlite) {
    await initSqlite();
  } else {
    await initPostgres();
  }
}

export const db = new Proxy({} as NodePgDatabase, {
  get(_target, prop) {
    if (!_db) throw new Error('Database not initialized. Call initDatabase() first.');
    return (_db as unknown as Record<string | symbol, unknown>)[prop];
  },
});

// SQLite stores booleans as INTEGER (1/0), PostgreSQL as BOOLEAN (true/false)
export const dbTrue: any = config.database.isSqlite ? 1 : true;
export const dbFalse: any = config.database.isSqlite ? 0 : false;

// SQLite stores timestamps as TEXT (ISO), PostgreSQL as TIMESTAMP (Date)
export function dbNow(): any {
  return config.database.isSqlite ? new Date().toISOString() : new Date();
}

export function dbDate(d: Date): any {
  return config.database.isSqlite ? d.toISOString() : d;
}

export async function testConnection(): Promise<boolean> {
  try {
    if (config.database.isSqlite) {
      return !!_db;
    }
    const pool = new Pool({ connectionString: config.database.url!, max: 1, connectionTimeoutMillis: 5000 });
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();
    await pool.end();
    return true;
  } catch (error) {
    logger.error({ err: error }, 'Database connection failed');
    return false;
  }
}

export async function closeConnection(): Promise<void> {
  if (_closeHandler) await _closeHandler();
}
