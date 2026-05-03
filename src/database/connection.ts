import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

// Guardian's own database (SOC tables)
const guardianPool = new Pool({
  connectionString: config.database.url,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

guardianPool.on('error', (err) => {
  logger.error({ err }, 'Guardian database pool error');
});

export const db = drizzle(guardianPool);

// AutomaBotHub database (may be same or different)
const automabothubPool = new Pool({
  connectionString: config.database.automabothubUrl,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

automabothubPool.on('error', (err) => {
  logger.error({ err }, 'AutomaBotHub database pool error');
});

export const automabothubDb = drizzle(automabothubPool);

export async function testConnection(): Promise<boolean> {
  try {
    const client = await guardianPool.connect();
    await client.query('SELECT 1');
    client.release();

    if (config.automabothub.enabled) {
      const ahClient = await automabothubPool.connect();
      await ahClient.query('SELECT 1');
      ahClient.release();
    }

    return true;
  } catch (error) {
    logger.error({ err: error }, 'Database connection failed');
    return false;
  }
}

export async function closeConnection(): Promise<void> {
  await guardianPool.end();
  await automabothubPool.end();
}
