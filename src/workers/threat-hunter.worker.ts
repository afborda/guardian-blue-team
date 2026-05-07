import { db } from '../database/connection.js';
import { securityEvents, threatHuntFindings } from '../database/schema.js';
import { gte, desc } from 'drizzle-orm';
import { AIProvider } from '../services/ai-provider.js';
import { IncidentMemoryService } from '../services/incident-memory.service.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { logger } from '../utils/logger.js';

export class ThreatHunterWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 4 * 60 * 60 * 1000; // 4 hours

  static start(): void {
    if (this.intervalId) return;

    // First run after 5 minutes (let other workers warm up)
    setTimeout(() => {
      this.hunt().catch(err => logger.error({ err }, 'Threat hunter error'));
    }, 5 * 60 * 1000);

    this.intervalId = setInterval(() => {
      this.hunt().catch(err => logger.error({ err }, 'Threat hunter error'));
    }, this.INTERVAL_MS);

    logger.info('Threat hunter worker started (every 4h)');
  }

  static async hunt(): Promise<void> {
    if (!AIProvider.isAvailable()) {
      logger.debug('AI unavailable — skipping threat hunt');
      return;
    }

    const cutoff = new Date(Date.now() - 6 * 60 * 60 * 1000); // last 6 hours

    const events = await db.select({
      eventType: securityEvents.eventType,
      severity: securityEvents.severity,
      sourceIp: securityEvents.sourceIp,
      category: securityEvents.category,
      serverId: securityEvents.serverId,
      timestamp: securityEvents.timestamp,
    })
      .from(securityEvents)
      .where(gte(securityEvents.timestamp, cutoff))
      .orderBy(desc(securityEvents.timestamp))
      .limit(500);

    if (events.length < 5) {
      logger.debug({ events: events.length }, 'Too few events for threat hunt');
      return;
    }

    const summary = this.summarizeEvents(events);
    const ragContext = await IncidentMemoryService.buildContextForAI('threat_hunt', []);

    const prompt = `Você é um analista SOC sênior realizando threat hunting proativo.

RESUMO DOS ÚLTIMOS 6H DE EVENTOS (${events.length} total):
${summary}

${ragContext}

Analise os dados e identifique:
1. Padrões coordenados entre IPs ou servidores
2. Ataques persistentes (APT slow-roll)
3. Reconhecimento ou scanning ativo
4. Movimento lateral
5. Atividade fora do padrão que merece investigação

Responda em JSON:
{
  "findings": [
    { "description": "texto", "severity": "critical|high|medium|low", "ips": ["1.2.3.4"], "recommendation": "texto" }
  ],
  "overallRisk": "low|medium|high|critical",
  "summary": "resumo executivo em 1-2 frases"
}

Se não encontrar nada preocupante, retorne findings como array vazio.`;

    const response = await AIProvider.chat(prompt, 'Responda apenas com JSON válido. Foco em achados acionáveis.');
    if (!response) return;

    try {
      const jsonMatch = response.text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return;

      const result = JSON.parse(jsonMatch[0]) as {
        findings: Array<{ description: string; severity: string; ips?: string[]; recommendation?: string }>;
        overallRisk: string;
        summary: string;
      };

      if (!result.findings || result.findings.length === 0) {
        logger.debug('Threat hunt: no findings');
        return;
      }

      // Store each finding
      for (const finding of result.findings) {
        await db.insert(threatHuntFindings).values({
          eventsAnalyzed: events.length,
          finding: `${finding.description}\nRecommendation: ${finding.recommendation ?? 'N/A'}`,
          severity: finding.severity,
          aiProvider: response.provider,
          notified: true,
        });
      }

      // Notify via Telegram if high/critical findings exist
      const critical = result.findings.filter(f => f.severity === 'critical' || f.severity === 'high');
      if (critical.length > 0) {
        const findingLines = critical
          .map(f => `  [${f.severity.toUpperCase()}] ${f.description}`)
          .join('\n');

        await NotifierManager.notify({
          title: 'Threat Hunt — Findings',
          body: `AI proativa identificou ${critical.length} achado(s) relevante(s):\n${findingLines}\n\nResumo: ${result.summary}`,
          severity: result.overallRisk === 'critical' ? 'critical' : 'high',
          metadata: { type: 'threat_hunt', provider: response.provider },
        });
      }

      logger.info({ findings: result.findings.length, risk: result.overallRisk, provider: response.provider }, 'Threat hunt complete');
    } catch (err) {
      logger.warn({ err }, 'Failed to parse threat hunt AI response');
    }
  }

  private static summarizeEvents(events: Array<{ eventType: string; severity: string; sourceIp: string | null; category: string; serverId: number }>): string {
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const topIps: Record<string, number> = {};
    const byServer: Record<number, number> = {};

    for (const e of events) {
      byType[e.eventType] = (byType[e.eventType] ?? 0) + 1;
      bySeverity[e.severity] = (bySeverity[e.severity] ?? 0) + 1;
      if (e.sourceIp) topIps[e.sourceIp] = (topIps[e.sourceIp] ?? 0) + 1;
      byServer[e.serverId] = (byServer[e.serverId] ?? 0) + 1;
    }

    const sortedIps = Object.entries(topIps).sort((a, b) => b[1] - a[1]).slice(0, 10);

    return [
      `Por tipo: ${Object.entries(byType).map(([k, v]) => `${k}(${v})`).join(', ')}`,
      `Por severidade: ${Object.entries(bySeverity).map(([k, v]) => `${k}(${v})`).join(', ')}`,
      `Top IPs: ${sortedIps.map(([ip, n]) => `${ip}(${n})`).join(', ')}`,
      `Por servidor: ${Object.entries(byServer).map(([k, v]) => `server#${k}(${v})`).join(', ')}`,
    ].join('\n');
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Threat hunter worker stopped');
  }
}
