import type { NormalizedEvent } from './normalizer.js';
import { db, dbNow, dbDate } from '../database/connection.js';
import { socIncidents } from '../database/schema.js';
import { eq, and, gte, or } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';

export interface CorrelationResult {
  event: NormalizedEvent;
  incidentId: number | null;
  isNewIncident: boolean;
  incidentCategory?: string;
}

const CORRELATION_WINDOW_MS = CONSTANTS.correlation.windowMs;
const PORT_SCAN_CORRELATION_WINDOW_MS = CONSTANTS.correlation.portScanWindowMs;
const BRUTE_FORCE_THRESHOLD = CONSTANTS.correlation.bruteForceThreshold;
const PORT_SCAN_THRESHOLD = CONSTANTS.correlation.portScanThreshold;

export class EventCorrelator {
  private static recentEvents: NormalizedEvent[] = [];
  private static readonly MAX_BUFFER = 5000;

  static async correlate(events: NormalizedEvent[]): Promise<CorrelationResult[]> {
    this.recentEvents.push(...events);
    if (this.recentEvents.length > this.MAX_BUFFER) {
      this.recentEvents = this.recentEvents.slice(-this.MAX_BUFFER);
    }

    const results: CorrelationResult[] = [];

    for (const event of events) {
      const incident = await this.findOrCreateIncident(event);
      results.push({
        event,
        incidentId: incident?.id ?? null,
        isNewIncident: incident?.isNew ?? false,
        incidentCategory: incident?.category,
      });
    }

    return results;
  }

  private static async findOrCreateIncident(event: NormalizedEvent): Promise<{ id: number; isNew: boolean; category: string } | null> {
    if (event.severity === 'info') return null;

    if (event.eventType === 'ssh_failed_password' || event.eventType === 'ssh_invalid_user') {
      const r = await this.correlateBruteForce(event);
      return r ? { ...r, category: 'brute_force' } : null;
    }

    if (event.eventType === 'firewall_block') {
      const r = await this.correlatePortScan(event);
      return r ? { ...r, category: 'port_scan' } : null;
    }

    if (event.eventType === 'unauthorized_login' || event.eventType === 'password_login' || event.eventType === 'lateral_movement') {
      const r = await this.correlateUnauthorizedAccess(event);
      return r ? { ...r, category: 'unauthorized_access' } : null;
    }

    if (event.eventType === 'syn_flood' || event.eventType === 'connection_rate_spike' || event.eventType === 'bandwidth_spike') {
      const r = await this.correlateDDoS(event);
      return r ? { ...r, category: 'ddos' } : null;
    }

    return null;
  }

  private static async correlateBruteForce(event: NormalizedEvent): Promise<{ id: number; isNew: boolean } | null> {
    if (!event.sourceIp) return null;

    const cutoff = new Date(Date.now() - CORRELATION_WINDOW_MS);
    const relatedCount = this.recentEvents.filter(e =>
      e.sourceIp === event.sourceIp &&
      (e.eventType === 'ssh_failed_password' || e.eventType === 'ssh_invalid_user') &&
      e.timestamp >= cutoff
    ).length;

    if (relatedCount < BRUTE_FORCE_THRESHOLD) return null;

    const existing = await db.select().from(socIncidents)
      .where(and(
        eq(socIncidents.category, 'brute_force'),
        eq(socIncidents.status, 'open'),
        gte(socIncidents.lastSeenAt, dbDate(cutoff)),
      ))
      .then(rows => rows.find(r => {
        const ips = (r.sourceIps ?? []) as string[];
        return ips.includes(event.sourceIp!);
      }));

    if (existing) {
      await db.update(socIncidents)
        .set({
          lastSeenAt: dbNow(),
          eventCount: existing.eventCount + 1,
        })
        .where(eq(socIncidents.id, existing.id));
      return { id: existing.id, isNew: false };
    }

    const [newIncident] = await db.insert(socIncidents).values({
      title: `SSH Brute Force from ${event.sourceIp}`,
      severity: 'high',
      category: 'brute_force',
      sourceIps: [event.sourceIp],
      affectedServers: [event.serverId],
      eventCount: relatedCount,
      firstSeenAt: dbDate(cutoff),
      lastSeenAt: dbNow(),
    }).returning();

    logger.warn({ ip: event.sourceIp, count: relatedCount, incidentId: newIncident.id }, 'New brute force incident detected');
    return { id: newIncident.id, isNew: true };
  }

  private static async correlatePortScan(event: NormalizedEvent): Promise<{ id: number; isNew: boolean } | null> {
    if (!event.sourceIp) return null;

    const cutoff = new Date(Date.now() - PORT_SCAN_CORRELATION_WINDOW_MS);
    const relatedPorts = new Set(
      this.recentEvents
        .filter(e =>
          e.sourceIp === event.sourceIp &&
          e.eventType === 'firewall_block' &&
          e.timestamp >= cutoff
        )
        .map(e => e.destinationPort)
        .filter(Boolean)
    );

    if (relatedPorts.size < PORT_SCAN_THRESHOLD) return null;

    // Search for existing incidents (open OR recently resolved) for this IP
    const existing = await db.select().from(socIncidents)
      .where(and(
        eq(socIncidents.category, 'port_scan'),
        or(
          eq(socIncidents.status, 'open'),
          and(eq(socIncidents.status, 'resolved'), gte(socIncidents.lastSeenAt, dbDate(cutoff))),
        ),
        gte(socIncidents.lastSeenAt, dbDate(cutoff)),
      ))
      .then(rows => rows.find(r => {
        const ips = (r.sourceIps ?? []) as string[];
        return ips.includes(event.sourceIp!);
      }));

    if (existing) {
      // Reopen if it was resolved — same attacker is back
      const wasResolved = existing.status === 'resolved';
      await db.update(socIncidents)
        .set({
          status: 'open',
          lastSeenAt: dbNow(),
          eventCount: existing.eventCount + 1,
          resolvedAt: null,
        })
        .where(eq(socIncidents.id, existing.id));

      if (wasResolved) {
        logger.info({ ip: event.sourceIp, incidentId: existing.id }, 'Reopened resolved port scan incident (repeat offender)');
      }
      return { id: existing.id, isNew: wasResolved };
    }

    const [newIncident] = await db.insert(socIncidents).values({
      title: `Port Scan from ${event.sourceIp} (${relatedPorts.size} ports)`,
      severity: 'medium',
      category: 'port_scan',
      sourceIps: [event.sourceIp],
      affectedServers: [event.serverId],
      eventCount: relatedPorts.size,
      firstSeenAt: dbDate(cutoff),
      lastSeenAt: dbNow(),
    }).returning();

    logger.warn({ ip: event.sourceIp, ports: relatedPorts.size, incidentId: newIncident.id }, 'New port scan incident detected');
    return { id: newIncident.id, isNew: true };
  }

  private static async correlateUnauthorizedAccess(event: NormalizedEvent): Promise<{ id: number; isNew: boolean } | null> {
    if (!event.sourceIp) return null;

    const cutoff = new Date(Date.now() - CORRELATION_WINDOW_MS);

    const existing = await db.select().from(socIncidents)
      .where(and(
        eq(socIncidents.category, 'unauthorized_access'),
        eq(socIncidents.status, 'open'),
        gte(socIncidents.lastSeenAt, dbDate(cutoff)),
      ))
      .then(rows => rows.find(r => {
        const ips = (r.sourceIps ?? []) as string[];
        return ips.includes(event.sourceIp!);
      }));

    if (existing) {
      await db.update(socIncidents)
        .set({
          lastSeenAt: dbNow(),
          eventCount: existing.eventCount + 1,
        })
        .where(eq(socIncidents.id, existing.id));
      return { id: existing.id, isNew: false };
    }

    const severityMap: Record<string, string> = {
      unauthorized_login: 'critical',
      lateral_movement: 'critical',
      password_login: 'high',
    };

    const [newIncident] = await db.insert(socIncidents).values({
      title: `Unauthorized Access: ${event.eventType} from ${event.sourceIp}`,
      severity: severityMap[event.eventType] ?? 'high',
      category: 'unauthorized_access',
      sourceIps: [event.sourceIp],
      affectedServers: [event.serverId],
      eventCount: 1,
      firstSeenAt: dbNow(),
      lastSeenAt: dbNow(),
    }).returning();

    logger.warn({ ip: event.sourceIp, type: event.eventType, incidentId: newIncident.id }, 'Unauthorized access incident created');
    return { id: newIncident.id, isNew: true };
  }

  private static async correlateDDoS(event: NormalizedEvent): Promise<{ id: number; isNew: boolean } | null> {
    const cutoff = new Date(Date.now() - CORRELATION_WINDOW_MS);

    // Find existing open DDoS incident for this server
    const existing = await db.select().from(socIncidents)
      .where(and(
        eq(socIncidents.category, 'ddos'),
        eq(socIncidents.status, 'open'),
        gte(socIncidents.lastSeenAt, dbDate(cutoff)),
      ))
      .then(rows => rows.find(r => {
        const servers = (r.affectedServers ?? []) as number[];
        return servers.includes(event.serverId);
      }));

    if (existing) {
      const sourceIps = (existing.sourceIps ?? []) as string[];
      if (event.sourceIp && !sourceIps.includes(event.sourceIp)) {
        sourceIps.push(event.sourceIp);
      }
      await db.update(socIncidents)
        .set({
          lastSeenAt: dbNow(),
          eventCount: existing.eventCount + 1,
          sourceIps,
        })
        .where(eq(socIncidents.id, existing.id));
      return { id: existing.id, isNew: false };
    }

    const [newIncident] = await db.insert(socIncidents).values({
      title: `DDoS Attack: ${event.eventType} on server ${event.serverId}${event.sourceIp ? ` from ${event.sourceIp}` : ''}`,
      severity: 'critical',
      category: 'ddos',
      sourceIps: event.sourceIp ? [event.sourceIp] : [],
      affectedServers: [event.serverId],
      eventCount: 1,
      firstSeenAt: dbNow(),
      lastSeenAt: dbNow(),
    }).returning();

    logger.warn({ ip: event.sourceIp, type: event.eventType, incidentId: newIncident.id }, 'New DDoS incident detected');
    return { id: newIncident.id, isNew: true };
  }

  static clearBuffer(): void {
    this.recentEvents = [];
  }
}
