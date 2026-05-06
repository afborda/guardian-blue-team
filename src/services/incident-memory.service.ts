import { db } from '../database/connection.js';
import { incidentMemory, socIncidents } from '../database/schema.js';
import { eq, desc } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export interface IncidentCase {
  id: number;
  category: string;
  title: string;
  sourceIps: string[];
  resolution: string | null;
  outcome: string | null;
  falsePositive: boolean;
  rootCause: string | null;
  timeToContainMinutes: number | null;
  tags: string[];
}

export class IncidentMemoryService {
  static async store(incidentId: number, resolution: string, outcome: 'resolved' | 'false_positive' | 'mitigated', rootCause?: string): Promise<void> {
    const [incident] = await db.select().from(socIncidents).where(eq(socIncidents.id, incidentId));
    if (!incident) return;

    const existingMemory = await db.select().from(incidentMemory).where(eq(incidentMemory.incidentId, incidentId));
    if (existingMemory.length > 0) {
      await db.update(incidentMemory)
        .set({ resolution, outcome, rootCause: rootCause ?? null, falsePositive: outcome === 'false_positive' })
        .where(eq(incidentMemory.incidentId, incidentId));
      return;
    }

    const timeToContain = incident.resolvedAt
      ? Math.round((incident.resolvedAt.getTime() - incident.firstSeenAt.getTime()) / 60_000)
      : null;

    await db.insert(incidentMemory).values({
      incidentId,
      category: incident.category ?? 'unknown',
      title: incident.title,
      sourceIps: (incident.sourceIps ?? []) as string[],
      resolution,
      outcome,
      falsePositive: outcome === 'false_positive',
      rootCause: rootCause ?? null,
      timeToContainMinutes: timeToContain,
      tags: this.extractTags(incident),
    });

    logger.info({ incidentId, category: incident.category, outcome }, 'Incident stored in memory');
  }

  static async findSimilar(category: string, sourceIps: string[], limit = 5): Promise<IncidentCase[]> {
    const cases = await db.select()
      .from(incidentMemory)
      .where(eq(incidentMemory.category, category))
      .orderBy(desc(incidentMemory.createdAt))
      .limit(limit * 2);

    if (cases.length === 0) return [];

    const scored = cases.map(c => {
      let relevance = 1;
      const caseIps = (c.sourceIps ?? []) as string[];
      const overlap = sourceIps.filter(ip => caseIps.includes(ip)).length;
      if (overlap > 0) relevance += overlap * 2;
      return { case: c, relevance };
    });

    scored.sort((a, b) => b.relevance - a.relevance);

    return scored.slice(0, limit).map(s => ({
      id: s.case.id,
      category: s.case.category,
      title: s.case.title,
      sourceIps: (s.case.sourceIps ?? []) as string[],
      resolution: s.case.resolution,
      outcome: s.case.outcome,
      falsePositive: s.case.falsePositive,
      rootCause: s.case.rootCause,
      timeToContainMinutes: s.case.timeToContainMinutes,
      tags: (s.case.tags ?? []) as string[],
    }));
  }

  static async getStats(): Promise<{ total: number; byCategory: Record<string, number>; falsePositiveRate: number }> {
    const all = await db.select({
      category: incidentMemory.category,
      falsePositive: incidentMemory.falsePositive,
    }).from(incidentMemory);

    const byCategory: Record<string, number> = {};
    let fpCount = 0;

    for (const row of all) {
      byCategory[row.category] = (byCategory[row.category] ?? 0) + 1;
      if (row.falsePositive) fpCount++;
    }

    return {
      total: all.length,
      byCategory,
      falsePositiveRate: all.length > 0 ? Math.round((fpCount / all.length) * 100) : 0,
    };
  }

  static async buildContextForAI(category: string, sourceIps: string[]): Promise<string> {
    const similar = await this.findSimilar(category, sourceIps, 3);
    if (similar.length === 0) return '';

    const lines = similar.map(c => {
      const resolution = c.resolution ?? 'sem resolução registrada';
      const outcome = c.outcome ?? 'desconhecido';
      const ttc = c.timeToContainMinutes ? `${c.timeToContainMinutes}min` : 'N/A';
      const fp = c.falsePositive ? ' [FALSO POSITIVO]' : '';
      return `- "${c.title}": ${resolution} (resultado: ${outcome}, tempo: ${ttc})${fp}`;
    });

    return `\nHISTORICAL CONTEXT (${similar.length} similar past incidents):\n${lines.join('\n')}\n`;
  }

  private static extractTags(incident: typeof socIncidents.$inferSelect): string[] {
    const tags: string[] = [];
    if (incident.category) tags.push(incident.category);
    if (incident.severity) tags.push(incident.severity);
    const ips = (incident.sourceIps ?? []) as string[];
    if (ips.length > 5) tags.push('distributed');
    if (incident.eventCount > 100) tags.push('high_volume');
    return tags;
  }
}
