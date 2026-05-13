import { db } from '../database/connection.js';
import { auditLogs } from '../database/schema.js';
import { logger } from './logger.js';

type AuditResult = 'success' | 'failure' | 'skipped';

export class AuditLogger {
  static async operational(
    serverId: number | null,
    eventType: string,
    result: AuditResult,
    details?: Record<string, unknown>,
  ): Promise<void> {
    await AuditLogger.insert({
      category: 'operational',
      eventType,
      serverId: serverId ?? undefined,
      actor: 'system',
      action: eventType,
      result,
      details,
    });
  }

  static async access(
    serverId: number,
    eventType: string,
    actor: string,
    resource: string,
    result: AuditResult,
    details?: Record<string, unknown>,
  ): Promise<void> {
    await AuditLogger.insert({
      category: 'access',
      eventType,
      serverId,
      actor,
      resource,
      action: eventType,
      result,
      details,
    });
  }

  static async block(
    ip: string,
    serverId: number,
    actor: string,
    incidentId: number | undefined,
    details?: Record<string, unknown>,
  ): Promise<void> {
    await AuditLogger.insert({
      category: 'block',
      eventType: 'ip_blocked',
      serverId,
      actor,
      resource: ip,
      action: 'block',
      result: 'success',
      relatedIncidentId: incidentId,
      details,
    });
  }

  private static async insert(fields: {
    category: string;
    eventType: string;
    serverId?: number;
    actor?: string;
    resource?: string;
    action?: string;
    result?: string;
    details?: Record<string, unknown>;
    relatedIncidentId?: number;
    relatedPlaybookId?: number;
  }): Promise<void> {
    try {
      await db.insert(auditLogs).values({
        category: fields.category,
        eventType: fields.eventType,
        serverId: fields.serverId ?? null,
        timestamp: new Date(),
        actor: fields.actor ?? null,
        resource: fields.resource ?? null,
        action: fields.action ?? null,
        result: fields.result ?? null,
        details: fields.details ?? null,
        relatedIncidentId: fields.relatedIncidentId ?? null,
        relatedPlaybookId: fields.relatedPlaybookId ?? null,
      });
    } catch (err) {
      logger.error({ err, eventType: fields.eventType }, 'AuditLogger insert failed');
    }
  }
}
