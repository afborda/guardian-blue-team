import { db } from '../database/connection.js';
import { guardianDecisions } from '../database/schema.js';
import { eq, and, lt } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { config } from '../config/environment.js';
import aiAnalyzer, { type AIAnalysisResult } from './ai-analyzer.service.js';
import { InstanceProfileService } from './instance-profile.service.js';

const EXPIRY_MINUTES = 30;

const ACTION_LABELS: Record<string, string> = {
  suspend: '⏸️ Suspender container',
  throttle: '🐌 Limitar recursos (throttle)',
  alert: '🔔 Registrar alerta',
  freeze: '🧊 Congelar container (storage)',
  none: '✅ Nenhuma ação',
};

const TYPE_LABELS: Record<string, string> = {
  crypto_mining: 'Mineração de criptomoeda',
  torrents: 'Torrent / P2P',
  ddos: 'Ataque DDoS',
  fork_bomb: 'Fork bomb',
  resource_hijacking: 'Sequestro de recursos',
  endpoint_scanning: 'Varredura de endpoints',
  anomaly: 'Anomalia detectada',
  legitimate: 'Uso legítimo',
};

export class GuardianDecisionService {
  static async proposeAction(
    instanceId: string,
    userId: string,
    analysis: AIAnalysisResult,
    subdomain?: string,
    userEmail?: string,
  ): Promise<void> {
    const existing = await db
      .select({ id: guardianDecisions.id })
      .from(guardianDecisions)
      .where(and(
        eq(guardianDecisions.instanceId, instanceId),
        eq(guardianDecisions.status, 'pending_approval'),
      ))
      .limit(1);

    if (existing.length > 0) {
      logger.debug(`Already pending decision for ${instanceId}, skipping`);
      return;
    }

    const expiresAt = new Date(Date.now() + EXPIRY_MINUTES * 60 * 1000);
    const actionPlanText = this.buildPlanText(instanceId, analysis, subdomain, userEmail);

    const [decision] = await db
      .insert(guardianDecisions)
      .values({
        instanceId, userId,
        aiAnalysisType: analysis.type,
        aiConfidence: analysis.confidence,
        aiReasoning: analysis.reasoning,
        proposedAction: analysis.action,
        actionPlanText,
        status: 'pending_approval',
        expiresAt,
      })
      .returning({ id: guardianDecisions.id });

    if (!decision) {
      logger.error('Failed to insert guardian decision');
      return;
    }

    await this.sendApprovalMessage(decision.id, instanceId, analysis, actionPlanText, subdomain);
  }

  static async handleCallback(callbackQuery: {
    id: string;
    data?: string;
    message?: { message_id: number; chat: { id: number } };
    from?: { first_name?: string };
  }): Promise<void> {
    await this.answerCallback(callbackQuery.id);
    if (!callbackQuery.data) return;

    const match = callbackQuery.data.match(/^guardian_(approve|reject|monitor)_(\d+)$/);
    if (!match) return;

    const [, actionStr, idStr] = match;
    const decisionId = parseInt(idStr, 10);

    const [decision] = await db
      .select()
      .from(guardianDecisions)
      .where(eq(guardianDecisions.id, decisionId))
      .limit(1);

    if (!decision) return;

    if (decision.status !== 'pending_approval') {
      await this.editMessage(
        callbackQuery.message?.message_id ?? decision.telegramMessageId,
        callbackQuery.message?.chat.id,
        `ℹ️ Decisão já processada (status: <b>${decision.status}</b>)`,
      );
      return;
    }

    const respondedBy = callbackQuery.from?.first_name ?? 'Admin';
    const now = new Date();

    if (actionStr === 'approve') {
      await db.update(guardianDecisions)
        .set({ status: 'approved', respondedAt: now, updatedAt: now })
        .where(eq(guardianDecisions.id, decisionId));

      try {
        await aiAnalyzer.executeAction(
          decision.instanceId, decision.userId,
          decision.proposedAction as any,
          decision.aiAnalysisType ?? 'unknown',
          decision.aiReasoning ?? '',
        );
        await db.update(guardianDecisions)
          .set({ status: 'executed', executedAt: new Date(), updatedAt: new Date() })
          .where(eq(guardianDecisions.id, decisionId));

        await this.editMessage(
          callbackQuery.message?.message_id ?? decision.telegramMessageId,
          callbackQuery.message?.chat.id,
          `✅ <b>Executado</b> por ${respondedBy}\n🎯 ${ACTION_LABELS[decision.proposedAction ?? 'none']}\n📦 <code>${decision.instanceId}</code>`,
        );
      } catch (error) {
        logger.error({ err: error }, 'Failed to execute approved action');
        await this.editMessage(
          callbackQuery.message?.message_id ?? decision.telegramMessageId,
          callbackQuery.message?.chat.id,
          `❌ <b>Erro ao executar</b>\n<code>${(error as Error).message}</code>`,
        );
      }
    } else if (actionStr === 'reject') {
      await db.update(guardianDecisions)
        .set({ status: 'rejected', respondedAt: now, updatedAt: now })
        .where(eq(guardianDecisions.id, decisionId));

      await InstanceProfileService.markAsFalsePositive(decision.instanceId);

      await this.editMessage(
        callbackQuery.message?.message_id ?? decision.telegramMessageId,
        callbackQuery.message?.chat.id,
        `❌ <b>Ignorado</b> por ${respondedBy}\n📚 Marcado como falso positivo.\n📦 <code>${decision.instanceId}</code>`,
      );
    } else if (actionStr === 'monitor') {
      await db.update(guardianDecisions)
        .set({ status: 'monitoring', respondedAt: now, updatedAt: now })
        .where(eq(guardianDecisions.id, decisionId));

      await this.editMessage(
        callbackQuery.message?.message_id ?? decision.telegramMessageId,
        callbackQuery.message?.chat.id,
        `👁️ <b>Monitorando</b> — nenhuma ação.\n📦 <code>${decision.instanceId}</code>`,
      );
    }
  }

  static async expireOldDecisions(): Promise<void> {
    const now = new Date();
    const expired = await db
      .select()
      .from(guardianDecisions)
      .where(and(
        eq(guardianDecisions.status, 'pending_approval'),
        lt(guardianDecisions.expiresAt, now),
      ));

    for (const d of expired) {
      await db.update(guardianDecisions)
        .set({ status: 'expired', updatedAt: now })
        .where(eq(guardianDecisions.id, d.id));

      if (d.telegramMessageId) {
        await this.editMessage(d.telegramMessageId, null,
          `⏰ <b>Expirada</b> — sem resposta em ${EXPIRY_MINUTES}min.\n📦 <code>${d.instanceId}</code>`);
      }
    }

    if (expired.length > 0) logger.info(`Expired ${expired.length} pending decision(s)`);
  }

  private static buildPlanText(
    instanceId: string, analysis: AIAnalysisResult, subdomain?: string, userEmail?: string,
  ): string {
    const label = subdomain ? `${subdomain}.automabothub.com` : instanceId;
    return [
      `🔍 <b>Análise:</b> ${TYPE_LABELS[analysis.type ?? ''] ?? analysis.type}`,
      `⚡ <b>Confiança:</b> ${analysis.confidence.toFixed(0)}%`,
      `🎯 <b>Ação:</b> ${ACTION_LABELS[analysis.action]}`,
      ``,
      `📋 ${analysis.reasoning}`,
      ``,
      `🖥️ <code>${label}</code>`,
      userEmail ? `👤 ${userEmail}` : '',
    ].filter(Boolean).join('\n');
  }

  private static async sendApprovalMessage(
    decisionId: number, instanceId: string, _analysis: AIAnalysisResult,
    planText: string, subdomain?: string,
  ): Promise<void> {
    const text = `🚨 <b>GUARDIAN</b> — <code>${subdomain ?? instanceId}</code>\n\n${planText}\n\n⏰ <i>Expira em ${EXPIRY_MINUTES}min</i>`;

    try {
      const resp = await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text,
          parse_mode: 'HTML',
          reply_markup: {
            inline_keyboard: [[
              { text: '✅ Executar', callback_data: `guardian_approve_${decisionId}` },
              { text: '❌ Ignorar', callback_data: `guardian_reject_${decisionId}` },
              { text: '👁 Monitorar', callback_data: `guardian_monitor_${decisionId}` },
            ]],
          },
        }),
      });

      const result = await resp.json() as any;
      if (result.ok && result.result?.message_id) {
        await db.update(guardianDecisions)
          .set({ telegramMessageId: result.result.message_id, updatedAt: new Date() })
          .where(eq(guardianDecisions.id, decisionId));
      }
    } catch (error) {
      logger.error({ err: error }, 'Failed to send approval message');
    }
  }

  private static async editMessage(
    messageId: number | null | undefined, chatId: number | string | null | undefined, text: string,
  ): Promise<void> {
    if (!messageId) return;
    const resolvedChatId = chatId ?? config.telegram.chatId;

    try {
      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/editMessageText`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: resolvedChatId, message_id: messageId, text, parse_mode: 'HTML' }),
      });
    } catch { /* non-critical */ }
  }

  private static async answerCallback(callbackQueryId: string): Promise<void> {
    try {
      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/answerCallbackQuery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_query_id: callbackQueryId }),
      });
    } catch { /* non-critical */ }
  }
}
