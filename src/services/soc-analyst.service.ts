import { db } from '../database/connection.js';
import { securityEvents, socIncidents } from '../database/schema.js';
import { desc, eq, gte, sql } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { AIProvider } from './ai-provider.js';
import { IncidentMemoryService } from './incident-memory.service.js';

export class SOCAnalystService {
  static isAvailable(): boolean {
    return AIProvider.isAvailable();
  }

  static async analyzeIncident(incidentId: number): Promise<string | null> {
    if (!this.isAvailable()) return null;

    const [incident] = await db.select().from(socIncidents).where(eq(socIncidents.id, incidentId));
    if (!incident) return null;

    const events = await db.select()
      .from(securityEvents)
      .where(eq(securityEvents.incidentId, incidentId))
      .orderBy(desc(securityEvents.timestamp))
      .limit(50);

    const prompt = this.buildIncidentPrompt(incident, events);
    const ragContext = await IncidentMemoryService.buildContextForAI(
      incident.category ?? 'unknown',
      (incident.sourceIps ?? []) as string[],
    );
    const augmentedPrompt = ragContext ? `${prompt}\n${ragContext}` : prompt;
    const response = await AIProvider.chat(augmentedPrompt, 'You are a SOC analyst. Analyze security incidents concisely in Portuguese (BR). Use historical context when available to inform your recommendations.');
    if (response) {
      logger.info({ provider: response.provider, latency: response.durationMs }, 'SOC incident analysis completed');
    }
    return response?.text ?? null;
  }

  static async generateWeeklySummary(): Promise<string | null> {
    if (!this.isAvailable()) return null;

    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const stats = await db.select({
      eventType: securityEvents.eventType,
      count: sql<number>`count(*)`,
      severity: securityEvents.severity,
    })
      .from(securityEvents)
      .where(gte(securityEvents.timestamp, weekAgo))
      .groupBy(securityEvents.eventType, securityEvents.severity);

    const incidents = await db.select()
      .from(socIncidents)
      .where(gte(socIncidents.createdAt, weekAgo));

    const prompt = this.buildWeeklySummaryPrompt(stats, incidents);
    const response = await AIProvider.chat(prompt, 'You are a SOC analyst generating weekly security reports in Portuguese (BR).');
    return response?.text ?? null;
  }

  static async naturalLanguageQuery(question: string): Promise<string | null> {
    if (!this.isAvailable()) return null;

    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const recentEvents = await db.select({
      eventType: securityEvents.eventType,
      count: sql<number>`count(*)`,
      severity: securityEvents.severity,
    })
      .from(securityEvents)
      .where(gte(securityEvents.timestamp, weekAgo))
      .groupBy(securityEvents.eventType, securityEvents.severity);

    const openIncidents = await db.select()
      .from(socIncidents)
      .where(eq(socIncidents.status, 'open'));

    const prompt = this.buildNLQueryPrompt(question, recentEvents, openIncidents);
    const memoryStats = await IncidentMemoryService.getStats();
    const memoryContext = memoryStats.total > 0
      ? `\nINCIDENT MEMORY (${memoryStats.total} cases stored, ${memoryStats.falsePositiveRate}% false positive rate):\nCategories: ${Object.entries(memoryStats.byCategory).map(([k, v]) => `${k}:${v}`).join(', ')}\n`
      : '';
    const augmentedPrompt = memoryContext ? `${prompt}\n${memoryContext}` : prompt;
    const response = await AIProvider.chat(augmentedPrompt, 'You are a SOC analyst assistant. Answer security questions based on available data in Portuguese (BR).');
    if (response) {
      return `${response.text}\n\n<i>🤖 ${response.provider}/${this.getModelShort(response.provider)} (${(response.durationMs / 1000).toFixed(1)}s)</i>`;
    }
    return null;
  }

  private static getModelShort(provider: string): string {
    const status = AIProvider.getStatus();
    const entry = status.find(s => s.name === provider);
    const model = entry?.model ?? 'unknown';
    return model.split('/').pop()?.split(':')[0] ?? model;
  }

  private static buildIncidentPrompt(incident: typeof socIncidents.$inferSelect, events: Array<typeof securityEvents.$inferSelect>): string {
    const eventSummary = events.slice(0, 20).map(e =>
      `[${e.timestamp.toISOString()}] ${e.eventType} from ${e.sourceIp ?? 'unknown'} → port ${e.destinationPort ?? 'n/a'}`
    ).join('\n');

    return `You are a SOC analyst. Analyze this security incident and provide a concise summary.

INCIDENT:
- Title: ${incident.title}
- Severity: ${incident.severity}
- Category: ${incident.category}
- Event count: ${incident.eventCount}
- Source IPs: ${JSON.stringify(incident.sourceIps)}
- First seen: ${incident.firstSeenAt.toISOString()}
- Last seen: ${incident.lastSeenAt.toISOString()}

ASSOCIATED EVENTS (latest ${events.length}):
${eventSummary}

Provide:
1. A 2-3 sentence executive summary
2. Threat assessment (is this a real attack or noise?)
3. Recommended action (block, monitor, investigate further)

Respond in Portuguese (BR). Keep it concise and actionable.`;
  }

  private static buildWeeklySummaryPrompt(
    stats: Array<{ eventType: string; count: number; severity: string }>,
    incidents: Array<typeof socIncidents.$inferSelect>
  ): string {
    const statsSummary = stats.map(s => `${s.eventType} (${s.severity}): ${s.count}`).join('\n');
    const incidentSummary = incidents.map(i =>
      `- [${i.severity}] ${i.title} — ${i.eventCount} events (${i.status})`
    ).join('\n');

    return `You are a SOC analyst generating a weekly security report. Summarize the security posture.

EVENT STATISTICS (last 7 days):
${statsSummary || 'No events'}

INCIDENTS (last 7 days):
${incidentSummary || 'No incidents'}

Provide:
1. Security posture assessment (1-2 sentences)
2. Key concerns or trends
3. Top recommendation

Respond in Portuguese (BR). Keep it brief, like a daily standup update.`;
  }

  private static buildNLQueryPrompt(
    question: string,
    stats: Array<{ eventType: string; count: number; severity: string }>,
    openIncidents: Array<typeof socIncidents.$inferSelect>
  ): string {
    const statsSummary = stats.map(s => `${s.eventType} (${s.severity}): ${s.count}`).join('\n');
    const incidentSummary = openIncidents.map(i =>
      `- [${i.severity}] ${i.title} — ${i.eventCount} events`
    ).join('\n');

    return `You are a SOC analyst assistant. Answer the user's security question based on available data.

USER QUESTION: ${question}

AVAILABLE DATA (last 7 days):
Event stats:
${statsSummary || 'No events recorded'}

Open incidents:
${incidentSummary || 'No open incidents'}

Answer in Portuguese (BR). Be concise and data-driven. If you don't have enough data to answer accurately, say so.`;
  }

}
