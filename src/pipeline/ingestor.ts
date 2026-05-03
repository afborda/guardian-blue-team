import { db, dbDate } from '../database/connection.js';
import { securityEvents } from '../database/schema.js';
import type { NormalizedEvent } from './normalizer.js';
import type { CorrelationResult } from './correlator.js';
import { logger } from '../utils/logger.js';

export class EventIngestor {
  static async persist(results: CorrelationResult[]): Promise<number> {
    if (results.length === 0) return 0;

    const values = results.map(r => ({
      serverId: r.event.serverId,
      timestamp: dbDate(r.event.timestamp),
      source: r.event.source,
      category: r.event.category,
      severity: r.event.severity,
      eventType: r.event.eventType,
      sourceIp: r.event.sourceIp,
      destinationPort: r.event.destinationPort,
      userName: r.event.userName,
      processName: r.event.processName,
      rawLog: r.event.rawLog,
      metadata: r.event.metadata,
      incidentId: r.incidentId,
    }));

    const BATCH_SIZE = 100;
    let total = 0;

    for (let i = 0; i < values.length; i += BATCH_SIZE) {
      const batch = values.slice(i, i + BATCH_SIZE);
      await db.insert(securityEvents).values(batch);
      total += batch.length;
    }

    logger.debug({ count: total }, 'Events persisted');
    return total;
  }

  static async persistSingle(event: NormalizedEvent, incidentId?: number): Promise<void> {
    await db.insert(securityEvents).values({
      serverId: event.serverId,
      timestamp: dbDate(event.timestamp),
      source: event.source,
      category: event.category,
      severity: event.severity,
      eventType: event.eventType,
      sourceIp: event.sourceIp,
      destinationPort: event.destinationPort,
      userName: event.userName,
      processName: event.processName,
      rawLog: event.rawLog,
      metadata: event.metadata,
      incidentId: incidentId ?? null,
    });
  }
}
