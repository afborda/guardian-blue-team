import { db, dbDate } from '../database/connection.js';
import { serverMetrics, securityEvents, socIncidents } from '../database/schema.js';
import { eq, gte, and, desc } from 'drizzle-orm';
import { AIProvider } from '../services/ai-provider.js';
import { logger } from '../utils/logger.js';

export interface RootCauseResult {
  serverId: number;
  dimension: string;
  previousScore: number;
  currentScore: number;
  explanation: string;
  suggestedAction: string;
  usedAI: boolean;
}

export class RootCauseAnalyzer {
  static async analyze(
    serverId: number,
    dimension: string,
    previousScore: number,
    currentScore: number,
  ): Promise<RootCauseResult> {
    const since = new Date(Date.now() - 2 * 60 * 60 * 1000);

    const [recentMetrics, recentEvents, openIncidents] = await Promise.all([
      db.select().from(serverMetrics).where(
        and(eq(serverMetrics.serverId, serverId), gte(serverMetrics.collectedAt, dbDate(since)))
      ).orderBy(desc(serverMetrics.collectedAt)).limit(5),
      db.select().from(securityEvents).where(
        and(eq(securityEvents.serverId, serverId), gte(securityEvents.timestamp, dbDate(since)))
      ).orderBy(desc(securityEvents.timestamp)).limit(20),
      db.select().from(socIncidents).where(eq(socIncidents.status, 'open')).limit(10),
    ]);

    const aiResult = await this.tryAIAnalysis(serverId, dimension, previousScore, currentScore, recentMetrics, recentEvents, openIncidents);

    if (aiResult) return aiResult;

    return this.ruleBasedAnalysis(serverId, dimension, previousScore, currentScore, recentMetrics);
  }

  private static async tryAIAnalysis(
    serverId: number,
    dimension: string,
    previousScore: number,
    currentScore: number,
    metrics: any[],
    events: any[],
    incidents: any[],
  ): Promise<RootCauseResult | null> {
    if (!AIProvider.isAvailable()) return null;

    const prompt = `O score de ${dimension} do servidor (id: ${serverId}) caiu de ${previousScore} para ${currentScore} na última hora.

Métricas recentes (últimas 2h):
${JSON.stringify(metrics.map(m => ({
  load1: m.load1, memUsedPct: m.memTotalBytes ? Math.round((m.memUsedBytes / m.memTotalBytes) * 100) : 0,
  kernelErrors: m.kernelErrors, journalErrors: m.journalErrors, failedUnits: m.failedUnits,
})), null, 2)}

Eventos recentes: ${events.map(e => `${e.eventType} (${e.severity})`).join(', ') || 'nenhum'}

Incidentes abertos: ${incidents.length}

Responda em JSON: { "explanation": "causa em 2-3 frases", "suggestedAction": "ação corretiva em 1 frase" }`;

    const response = await AIProvider.chat(prompt, 'Você é um analista de infraestrutura. Responda sempre em JSON válido.');

    if (!response) return null;

    try {
      const jsonMatch = response.text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return null;
      const parsed = JSON.parse(jsonMatch[0]);

      return {
        serverId,
        dimension,
        previousScore,
        currentScore,
        explanation: parsed.explanation || 'Análise inconclusiva',
        suggestedAction: parsed.suggestedAction || 'Investigar manualmente',
        usedAI: true,
      };
    } catch {
      logger.debug('Failed to parse AI root cause response');
      return null;
    }
  }

  private static ruleBasedAnalysis(
    serverId: number,
    dimension: string,
    previousScore: number,
    currentScore: number,
    metrics: any[],
  ): RootCauseResult {
    const reasons: string[] = [];
    const actions: string[] = [];

    if (metrics.length > 0) {
      const latest = metrics[0];

      if (dimension === 'health' || dimension === 'Health') {
        const loadRatio = (latest.load1 ?? 0) / Math.max(latest.cpuCount ?? 1, 1);
        const memPct = latest.memTotalBytes ? Math.round((latest.memUsedBytes / latest.memTotalBytes) * 100) : 0;

        if (loadRatio > 1.0) reasons.push(`load ratio elevado (${loadRatio.toFixed(1)})`);
        if (memPct > 85) reasons.push(`memória em ${memPct}%`);
        if (loadRatio > 1.5) actions.push('Identificar processos com alto consumo de CPU');
        if (memPct > 90) actions.push('Liberar memória ou adicionar RAM');
      }

      if (dimension === 'quality' || dimension === 'Quality') {
        const failed = (latest.failedUnits ?? []).length;
        if (failed > 0) reasons.push(`${failed} serviço(s) falhado(s)`);
        if (latest.kernelErrors > 5) reasons.push(`${latest.kernelErrors} erros de kernel`);
        actions.push('Verificar status dos serviços com systemctl');
      }
    }

    return {
      serverId,
      dimension,
      previousScore,
      currentScore,
      explanation: reasons.length > 0 ? `Score caiu porque: ${reasons.join(', ')}` : `Score ${dimension} caiu de ${previousScore} para ${currentScore} sem causa identificável nos dados recentes`,
      suggestedAction: actions.length > 0 ? actions[0] : 'Investigar logs do servidor manualmente',
      usedAI: false,
    };
  }
}
