import { db } from '../database/connection.js';
import { securityEvents, threatHuntFindings, trustedEntities } from '../database/schema.js';
import { gte, desc, eq } from 'drizzle-orm';
import { AIProvider } from '../services/ai-provider.js';
import { IncidentMemoryService } from '../services/incident-memory.service.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { CONSTANTS } from '../config/constants.js';
import { logger } from '../utils/logger.js';

export class ThreatHunterWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 4 * 24 * 60 * 60 * 1000; // 4 days

  static start(): void {
    if (this.intervalId) return;

    // Run immediately, then every 4h
    this.hunt().catch(err => logger.error({ err }, 'Threat hunter error'));
    this.intervalId = setInterval(() => {
      this.hunt().catch(err => logger.error({ err }, 'Threat hunter error'));
    }, this.INTERVAL_MS);

    logger.info('Threat hunter worker started (every 4 days)');
  }

  static async hunt(): Promise<void> {
    if (!AIProvider.isAvailable()) {
      logger.debug('AI unavailable — skipping threat hunt');
      return;
    }

    const cutoff = new Date(Date.now() - 6 * 60 * 60 * 1000);

    const [events, trustedRows] = await Promise.all([
      db.select({
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
        .limit(500),
      db.select({ entityType: trustedEntities.entityType, value: trustedEntities.value, note: trustedEntities.note })
        .from(trustedEntities)
        .where(eq(trustedEntities.entityType, 'ip')),
    ]);

    if (events.length < 5) {
      logger.debug({ events: events.length }, 'Too few events for threat hunt');
      return;
    }

    const knownTrustedIps = new Set([
      ...CONSTANTS.trustedIps,
      ...trustedRows.map(r => r.value),
      // Guardian's own container IPs on the internal network
      '172.26.0.5', '172.26.0.4', '172.26.0.3', '172.26.0.2',
    ]);

    const { summary, stats } = this.summarizeEvents(events, knownTrustedIps);
    const ragContext = await IncidentMemoryService.buildContextForAI('threat_hunt', []);

    const trustedIpContext = trustedRows.length > 0
      ? `IPs CONFIÁVEIS REGISTRADOS (acessos destes IPs são legítimos):\n${trustedRows.map(r => `  ${r.value}${r.note ? ` — ${r.note}` : ''}`).join('\n')}`
      : '';

    const prompt = `Você é um analista SOC sênior realizando threat hunting proativo num servidor Linux de homelab/pequena empresa.

CONTEXTO DO AMBIENTE:
- Servidor único (server#1) no Hetzner FSN1 (IP: 138.201.56.177)
- Stack de containers: Guardian (SIEM), n8n, AutomaBotHub, Ninho (fintech), Jellyfin, Tozon, SynthFin, Ninho, Traefik, Postgres, Redis, Ollama
- IPs internos 172.26.0.0/16 = containers do próprio stack (Guardian, Trivy, DB, Ollama) — NUNCA são ameaça
- container_insecure_config = containers sem ReadonlyRootfs/CapDrop — é o padrão do homelab, NÃO indica comprometimento
- docker_save = Trivy scanner inspecionando imagens para CVE — é rotina, NÃO é exfiltração
- ssh_login_success de IPs confiáveis = acesso administrativo legítimo do operador
- kernel_error = eventos normais de cgroup/namespace do Docker no kernel

${trustedIpContext}

RESUMO DOS ÚLTIMOS 6H (${stats.total} total, ${stats.noise} telemetria de infra filtrada, ${stats.signal} eventos de segurança):
${summary}

${ragContext}

INSTRUÇÕES:
- Ignore completamente: container_insecure_config, container_connection, ssh_login_success/session_opened de IPs confiáveis, docker_save, kernel_error, container_config_ok
- Foque em: brute force real (falhas repetidas de IPs desconhecidos), scanning coordenado, anomalias de processo, movimentação lateral, IPs com histórico de abuso
- Só classifique como HIGH/CRITICAL se houver evidência concreta, não volumétrica
- Se o ambiente estiver normal, retorne findings vazio — isso é o resultado correto

Responda em JSON:
{
  "findings": [
    { "description": "texto objetivo e específico", "severity": "critical|high|medium|low", "ips": ["1.2.3.4"], "recommendation": "ação concreta" }
  ],
  "overallRisk": "low|medium|high|critical",
  "summary": "1-2 frases do estado real do ambiente"
}`;

    const response = await AIProvider.chat(prompt, 'Responda apenas com JSON válido. Seja conservador: prefira falso negativo a falso positivo.');
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
        logger.info({ provider: response.provider }, 'Threat hunt: ambiente normal, sem achados');
        return;
      }

      for (const finding of result.findings) {
        await db.insert(threatHuntFindings).values({
          eventsAnalyzed: events.length,
          finding: `${finding.description}\nRecommendation: ${finding.recommendation ?? 'N/A'}`,
          severity: finding.severity,
          aiProvider: response.provider,
          notified: true,
        });
      }

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

  // Event types that are routine infra telemetry — flood the AI summary with noise
  private static readonly NOISE_EVENT_TYPES = new Set([
    'container_connection',
    'container_config_ok',
    'container_process',
    'container_insecure_config',
    'ssh_login_success',
    'session_opened',
    'docker_save',
    'docker_top',
    'docker_connect',
    'docker_disconnect',
    'kernel_error',
  ]);

  private static summarizeEvents(
    events: Array<{ eventType: string; severity: string; sourceIp: string | null; category: string; serverId: number }>,
    trustedIps: Set<string>,
  ): { summary: string; stats: { total: number; signal: number; noise: number } } {
    const signal = events.filter(e =>
      !this.NOISE_EVENT_TYPES.has(e.eventType) &&
      !(e.sourceIp && trustedIps.has(e.sourceIp) && e.eventType === 'ssh_login_success')
    );

    const byType: Record<string, number> = {};
    const unknownIps: Record<string, number> = {};
    const trustedIpCounts: Record<string, number> = {};

    for (const e of signal) {
      byType[e.eventType] = (byType[e.eventType] ?? 0) + 1;
      if (e.sourceIp) {
        if (trustedIps.has(e.sourceIp)) {
          trustedIpCounts[e.sourceIp] = (trustedIpCounts[e.sourceIp] ?? 0) + 1;
        } else {
          unknownIps[e.sourceIp] = (unknownIps[e.sourceIp] ?? 0) + 1;
        }
      }
    }

    const topUnknown = Object.entries(unknownIps).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const topTrusted = Object.entries(trustedIpCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

    const lines = [
      `Eventos de segurança por tipo: ${Object.entries(byType).map(([k, v]) => `${k}(${v})`).join(', ') || 'nenhum'}`,
      topUnknown.length > 0
        ? `IPs DESCONHECIDOS ativos: ${topUnknown.map(([ip, n]) => `${ip}(${n})`).join(', ')}`
        : 'IPs desconhecidos: nenhum',
      topTrusted.length > 0
        ? `IPs confiáveis com atividade: ${topTrusted.map(([ip, n]) => `${ip}(${n})`).join(', ')}`
        : '',
    ].filter(Boolean);

    return {
      summary: lines.join('\n'),
      stats: { total: events.length, signal: signal.length, noise: events.length - signal.length },
    };
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Threat hunter worker stopped');
  }
}
