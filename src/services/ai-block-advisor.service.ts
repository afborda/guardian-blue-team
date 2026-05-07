import { AIProvider } from './ai-provider.js';
import { IncidentMemoryService } from './incident-memory.service.js';
import { logger } from '../utils/logger.js';
import type { PlaybookContext } from '../playbooks/engine.js';

export type BlockAction = 'block_permanent' | 'rate_limit' | 'monitor' | 'ignore';

export interface BlockRecommendation {
  action: BlockAction;
  confidence: number;
  reasoning: string;
}

export class AIBlockAdvisor {
  static async getRecommendation(
    ctx: PlaybookContext,
    eventData: { eventType: string; severity: string; eventCount?: number; sourceIp?: string },
  ): Promise<BlockRecommendation> {
    if (!AIProvider.isAvailable()) {
      return { action: 'block_permanent', confidence: 0, reasoning: 'AI unavailable — using rule-based default' };
    }

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
        return { action: 'block_permanent', confidence: 0, reasoning: 'AI returned empty response' };
      }

      const jsonMatch = response.text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        return { action: 'block_permanent', confidence: 0, reasoning: 'AI response not parseable as JSON' };
      }

      const parsed = JSON.parse(jsonMatch[0]) as Partial<BlockRecommendation>;
      const validActions: BlockAction[] = ['block_permanent', 'rate_limit', 'monitor', 'ignore'];
      const action = validActions.includes(parsed.action as BlockAction)
        ? (parsed.action as BlockAction)
        : 'block_permanent';

      return {
        action,
        confidence: Math.max(0, Math.min(100, Number(parsed.confidence) || 50)),
        reasoning: String(parsed.reasoning || 'No reasoning provided'),
      };
    } catch (err) {
      logger.warn({ err }, 'AI block advisor failed — defaulting to block_permanent');
      return { action: 'block_permanent', confidence: 0, reasoning: 'AI advisor error — fallback to rule-based' };
    }
  }
}
