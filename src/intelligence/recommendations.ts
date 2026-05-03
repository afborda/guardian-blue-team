import { db } from '../database/connection.js';
import { serverScores, serverMetrics } from '../database/schema.js';
import { eq, desc } from 'drizzle-orm';
import { AIProvider } from '../services/ai-provider.js';
import { logger } from '../utils/logger.js';

export interface Recommendation {
  serverId: number;
  serverName: string;
  priority: 'high' | 'medium' | 'low';
  action: string;
  reason: string;
  category: 'performance' | 'security' | 'maintenance' | 'cost' | 'reliability';
}

export class RecommendationEngine {
  static async generate(servers: Array<{ id: number; name: string }>): Promise<Recommendation[]> {
    const recommendations: Recommendation[] = [];
    const serverSummaries: any[] = [];

    for (const server of servers) {
      const [latestScore] = await db.select().from(serverScores)
        .where(eq(serverScores.serverId, server.id))
        .orderBy(desc(serverScores.periodStart))
        .limit(1);

      const [latestMetric] = await db.select().from(serverMetrics)
        .where(eq(serverMetrics.serverId, server.id))
        .orderBy(desc(serverMetrics.collectedAt))
        .limit(1);

      serverSummaries.push({ id: server.id, name: server.name, score: latestScore, metric: latestMetric });

      const ruleRecs = this.ruleBasedRecommendations(server, latestScore, latestMetric);
      recommendations.push(...ruleRecs);
    }

    const aiRecs = await this.tryAIRecommendations(serverSummaries);
    if (aiRecs.length > 0) {
      return aiRecs;
    }

    return recommendations;
  }

  private static ruleBasedRecommendations(
    server: { id: number; name: string },
    score: any | undefined,
    metric: any | undefined,
  ): Recommendation[] {
    const recs: Recommendation[] = [];

    if (metric) {
      const disks = (metric.disks as any[]) ?? [];
      const maxDisk = Math.max(...disks.map(d => d.usedPercent ?? 0), 0);
      if (maxDisk > 85) {
        recs.push({
          serverId: server.id, serverName: server.name,
          priority: maxDisk > 95 ? 'high' : 'medium',
          action: 'Expandir disco ou limpar logs antigos',
          reason: `Disco em ${maxDisk}% de uso`,
          category: 'maintenance',
        });
      }

      const loadRatio = (metric.load1 ?? 0) / Math.max(metric.cpuCount ?? 1, 1);
      if (loadRatio < 0.05 && metric.memTotalBytes) {
        const memPct = ((metric.memUsedBytes ?? 0) / metric.memTotalBytes) * 100;
        if (memPct < 15) {
          recs.push({
            serverId: server.id, serverName: server.name,
            priority: 'low',
            action: 'Servidor ocioso — avaliar downsize ou desligamento',
            reason: `CPU idle, memória em apenas ${Math.round(memPct)}%`,
            category: 'cost',
          });
        }
      }

      const failedUnits = (metric.failedUnits as string[]) ?? [];
      if (failedUnits.length > 0) {
        recs.push({
          serverId: server.id, serverName: server.name,
          priority: 'medium',
          action: `Corrigir serviços falhados: ${failedUnits.slice(0, 3).join(', ')}`,
          reason: `${failedUnits.length} unidade(s) systemd em estado failed`,
          category: 'reliability',
        });
      }
    }

    if (score && score.vulnerabilityScore < 60) {
      recs.push({
        serverId: server.id, serverName: server.name,
        priority: 'high',
        action: 'Aplicar patches de segurança pendentes',
        reason: `Score de vulnerabilidade baixo (${score.vulnerabilityScore}/100)`,
        category: 'security',
      });
    }

    return recs;
  }

  private static async tryAIRecommendations(summaries: any[]): Promise<Recommendation[]> {
    if (!AIProvider.isAvailable() || summaries.length === 0) return [];

    const data = summaries.map(s => ({
      name: s.name,
      overall: s.score?.overallScore ?? 'sem dados',
      health: s.score?.healthScore ?? '-',
      security: s.score?.securityScore ?? '-',
      diskMax: s.metric?.disks ? Math.max(...(s.metric.disks as any[]).map((d: any) => d.usedPercent ?? 0), 0) : '-',
      failedUnits: (s.metric?.failedUnits as string[])?.length ?? 0,
    }));

    const prompt = `Dados de servidores monitorados na última semana:
${JSON.stringify(data, null, 2)}

Gere recomendações priorizadas por impacto.
Responda em JSON array: [{ "serverName": "...", "priority": "high|medium|low", "action": "...", "reason": "...", "category": "performance|security|maintenance|cost|reliability" }]
Máximo 5 recomendações mais importantes.`;

    const response = await AIProvider.chat(prompt, 'Você é um consultor de infraestrutura. Responda apenas com JSON válido.');

    if (!response) return [];

    try {
      const jsonMatch = response.text.match(/\[[\s\S]*\]/);
      if (!jsonMatch) return [];
      const parsed = JSON.parse(jsonMatch[0]) as any[];

      return parsed.map(r => {
        const server = summaries.find(s => s.name === r.serverName);
        return {
          serverId: server?.id ?? 0,
          serverName: r.serverName,
          priority: r.priority || 'medium',
          action: r.action || '',
          reason: r.reason || '',
          category: r.category || 'maintenance',
        };
      }).filter(r => r.serverId > 0);
    } catch {
      logger.debug('Failed to parse AI recommendations');
      return [];
    }
  }
}
