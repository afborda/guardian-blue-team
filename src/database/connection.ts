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

  _db = drizzle(pool);
  _closeHandler = async () => { await pool.end(); };
}

async function initSqlite(): Promise<void> {
  const { default: Database } = await import('better-sqlite3');
  const { drizzle: sqliteDrizzle } = await import('drizzle-orm/better-sqlite3');
  const { mkdirSync } = await import('fs');
  const { dirname } = await import('path');

  const dbPath = config.database.url?.replace('sqlite:', '') || './data/guardian.db';
  mkdirSync(dirname(dbPath), { recursive: true });

  const sqlite = new Database(dbPath);
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');

  // Cast to NodePgDatabase — Drizzle's query builder API is identical at runtime
  _db = sqliteDrizzle(sqlite) as unknown as NodePgDatabase;
  _closeHandler = async () => { sqlite.close(); };

  logger.info({ path: dbPath }, 'SQLite database initialized');
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
