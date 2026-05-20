import { AIProvider } from './ai-provider.js';
import { IncidentMemoryService } from './incident-memory.service.js';
import { ThreatIntelManager } from '../threat-intel/manager.js';
import { logger } from '../utils/logger.js';
import type { PlaybookContext } from '../playbooks/engine.js';

export type BlockAction = 'block_permanent' | 'rate_limit' | 'monitor' | 'ignore';

export type RecommendationSource =
  | 'ti_high'              // TI score ≥75 — auto-block, AI skipped
  | 'ti_ai_consensus'      // TI 30-74 + AI block at ≥70 conf
  | 'no_ti_low_conf'       // No TI + AI <85 conf — downgraded to monitor
  | 'ai_only'              // AI decision, no TI signal needed/available
  | 'ai_unavailable'       // AI provider not configured
  | 'ai_error'             // AI call/parse failed
  | 'ai_empty';            // AI returned no content

export interface BlockRecommendation {
  action: BlockAction;
  confidence: number;
  reasoning: string;
  source: RecommendationSource;
  tiScore?: number;
}

// Thresholds for the two-key TI+AI gate (v2 hardening plan §7.1).
const TI_HIGH_THRESHOLD = 75;       // TI alone ≥ this → auto-block
const TI_CONSENSUS_THRESHOLD = 30;  // TI ≥ this AND AI confident → block
const AI_BLOCK_CONFIDENCE = 70;     // AI must be at least this confident to count for consensus
const AI_SOLO_CONFIDENCE = 85;      // Without TI signal, AI needs this to block

export class AIBlockAdvisor {
  static async getRecommendation(
    ctx: PlaybookContext,
    eventData: { eventType: string; severity: string; eventCount?: number; sourceIp?: string },
  ): Promise<BlockRecommendation> {
    const ip = ctx.sourceIp ?? eventData.sourceIp;

    // ─── Pre-gate: high-confidence TI short-circuit ─────────────────────────
    // If we already know the IP is bad from external feeds, don't waste an AI call.
    const tiReport = ip ? await this.lookupTi(ip) : null;
    const tiScore = tiReport?.score;

    if (tiScore !== undefined && tiScore >= TI_HIGH_THRESHOLD) {
      return {
        action: 'block_permanent',
        confidence: 95,
        reasoning: `TI score ${tiScore} ≥ ${TI_HIGH_THRESHOLD} (${tiReport?.source ?? 'unknown'}) — high-confidence threat`,
        source: 'ti_high',
        tiScore,
      };
    }

    if (!AIProvider.isAvailable()) {
      return {
        action: 'block_permanent',
        confidence: 0,
        reasoning: 'AI unavailable — using rule-based default',
        source: 'ai_unavailable',
        tiScore,
      };
    }

    // ─── AI consultation ────────────────────────────────────────────────────
    const aiResult = await this.consultAI(ctx, eventData);
    if (aiResult.errorSource) {
      return { ...aiResult.recommendation, source: aiResult.errorSource, tiScore };
    }

    const ai = aiResult.recommendation;

    // ─── Post-gate: consensus / downgrade ───────────────────────────────────
    // Case 1: TI in the middle band — require AI consensus to actually block.
    if (tiScore !== undefined && tiScore >= TI_CONSENSUS_THRESHOLD) {
      if (ai.action === 'block_permanent' && ai.confidence >= AI_BLOCK_CONFIDENCE) {
        return { ...ai, source: 'ti_ai_consensus', tiScore };
      }
      // TI is mildly suspicious but AI didn't agree confidently — trust AI's softer call
      return { ...ai, source: 'ai_only', tiScore };
    }

    // Case 2: No TI signal at all — require very high AI confidence to block.
    if (tiScore === undefined && ai.action === 'block_permanent' && ai.confidence < AI_SOLO_CONFIDENCE) {
      return {
        action: 'monitor',
        confidence: ai.confidence,
        reasoning: `AI suggested block at ${ai.confidence}% conf but no TI signal — downgraded to monitor (was: ${ai.reasoning})`,
        source: 'no_ti_low_conf',
      };
    }

    // Case 3: TI < 30 (clean reputation) or AI suggested non-block — accept AI's call.
    return { ...ai, source: 'ai_only', tiScore };
  }

  /**
   * For categories that bypass the advisor entirely (alwaysBlock list in event-collector),
   * still consult TI as an audit hint. Logs a warning when an "obvious" block targets an IP
   * with low reputation — these are candidates for false-positive review later.
   */
  static async logTiHint(
    ctx: PlaybookContext,
    eventData: { eventType: string; sourceIp?: string },
  ): Promise<void> {
    const ip = ctx.sourceIp ?? eventData.sourceIp;
    if (!ip) return;

    const tiReport = await this.lookupTi(ip);
    if (!tiReport) return;

    if (tiReport.score < TI_CONSENSUS_THRESHOLD) {
      logger.warn({
        ip,
        eventType: eventData.eventType,
        serverName: ctx.serverName,
        tiScore: tiReport.score,
        tiSource: tiReport.source,
      }, 'alwaysBlock fired on IP with low TI reputation — possible FP candidate');
    }
  }

  private static async lookupTi(ip: string): Promise<{ score: number; source: string } | null> {
    try {
      const report = await ThreatIntelManager.lookupIP(ip);
      if (!report) return null;
      return { score: report.score, source: report.source };
    } catch (err) {
      logger.debug({ err, ip }, 'TI lookup failed in advisor — proceeding without TI signal');
      return null;
    }
  }

  private static async consultAI(
    ctx: PlaybookContext,
    eventData: { eventType: string; severity: string; eventCount?: number; sourceIp?: string },
  ): Promise<{
    recommendation: BlockRecommendation;
    errorSource: RecommendationSource | null;
  }> {
    try {
      const ragContext = await IncidentMemoryService.buildContextForAI(
        eventData.eventType,
        ctx.sourceIp ? [ctx.sourceIp] : [],
      );

      const prompt = `Você é um SOC analyst decidindo a resposta para um incidente de segurança.

EVENTO:
- Tipo: ${eventData.eventType}
- Severidade: ${eventData.severity}
- IP Origem: ${ctx.sourceIp ?? 'desconhecido'}
- Servidor: ${ctx.serverName}
- Total de eventos: ${eventData.eventCount ?? 1}

${ragContext}

Baseado no contexto, qual a melhor ação? Considere:
- block_permanent: ameaça confirmada, banir para sempre
- rate_limit: comportamento suspeito mas pode ser legítimo, limitar tráfego
- monitor: baixa confiança, apenas monitorar
- ignore: falso positivo provável

Responda APENAS com JSON: { "action": "block_permanent"|"rate_limit"|"monitor"|"ignore", "confidence": 0-100, "reasoning": "explicação curta" }`;

      const response = await AIProvider.chat(prompt, 'Responda apenas com JSON válido, sem markdown.');
      if (!response) {
        return {
          recommendation: { action: 'block_permanent', confidence: 0, reasoning: 'AI returned empty response', source: 'ai_empty' },
          errorSource: 'ai_empty',
        };
      }

      const jsonMatch = response.text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return {
          recommendation: { action: 'block_permanent', confidence: 0, reasoning: 'AI response not parseable as JSON', source: 'ai_error' },
          errorSource: 'ai_error',
        };
      }

      const parsed = JSON.parse(jsonMatch[0]) as Partial<BlockRecommendation>;
      const validActions: BlockAction[] = ['block_permanent', 'rate_limit', 'monitor', 'ignore'];
      const action = validActions.includes(parsed.action as BlockAction)
        ? (parsed.action as BlockAction)
        : 'block_permanent';

      return {
        recommendation: {
          action,
          confidence: Math.max(0, Math.min(100, Number(parsed.confidence) || 50)),
          reasoning: String(parsed.reasoning || 'No reasoning provided'),
          source: 'ai_only', // overridden by caller based on TI gate
        },
        errorSource: null,
      };
    } catch (err) {
      logger.warn({ err }, 'AI block advisor failed — defaulting to block_permanent');
      return {
        recommendation: { action: 'block_permanent', confidence: 0, reasoning: 'AI advisor error — fallback to rule-based', source: 'ai_error' },
        errorSource: 'ai_error',
      };
    }
  }
}
