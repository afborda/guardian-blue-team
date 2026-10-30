import { db } from '../database/connection.js';
import { blockedIps, socIncidents, socServers } from '../database/schema.js';
import { and, eq, inArray } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { telegram } from '../telegram/messaging/sender.js';
import type { MessageSeverity, MessageSpec } from '../telegram/messaging/types.js';
import { formatNumber } from '../telegram/messaging/style.js';
import { copyV2Enabled } from '../telegram/messaging/flags.js';
import type { CorrelationResult } from '../pipeline/correlator.js';
import {
  buildIncidentResolutionSpec,
  buildIncidentSpec,
  categoryLabel,
} from '../telegram/copy/incident.js';

interface TrackedMessage {
  chatId: string;
  messageId: number;
  spec: MessageSpec;
  sentAt: number;
}

export interface IncidentOutcome {
  label: string;
  kind?: 'blocked' | 'unblocked' | 'isolated' | 'executed' | 'failed';
  ip?: string;
}

/**
 * Garante uma mensagem por incidente novo, inclusive para categorias que não
 * têm playbook. Também mantém o vínculo incidente ↔ mensagem para editar o
 * desfecho em vez de mandar uma segunda mensagem.
 */
export class IncidentAlertService {
  private static tracked = new Map<number, TrackedMessage>();
  private static sentAt = new Map<number, number>();
  private static readonly DEDUPE_MS = 24 * 60 * 60 * 1000;

  static async onNewIncidents(results: CorrelationResult[]): Promise<void> {
    if (!copyV2Enabled('incident')) return;

    const seen = new Set<number>();
    const digest: Array<{ id: number; label: string; serverName: string; severity: MessageSeverity }> = [];

    for (const result of results) {
      if (!result.isNewIncident || !result.incidentId) continue;
      if (seen.has(result.incidentId)) continue;
      seen.add(result.incidentId);

      const lastSent = this.sentAt.get(result.incidentId) ?? 0;
      if (Date.now() - lastSent < this.DEDUPE_MS) continue;

      try {
        const individual = await this.notifyIncident(result);
        if (individual === 'digest') {
          digest.push({
            id: result.incidentId,
            label: categoryLabel(result.incidentCategory ?? result.event.category),
            serverName: await this.serverName(result.event.serverId),
            severity: this.severity(result.event.severity),
          });
        }
      } catch (err) {
        logger.warn({ err, incidentId: result.incidentId }, 'Falha ao notificar incidente');
      }
    }

    if (digest.length > 1) {
      await this.notifyDigest(digest);
    }
  }

  /** Edita a mensagem do incidente com o que o playbook fez. */
  static async attachOutcome(incidentId: number, outcome: IncidentOutcome): Promise<boolean> {
    const tracked = this.tracked.get(incidentId);
    if (!tracked) return false;

    let buttons = [...(tracked.spec.buttons ?? [])];

    if (outcome.kind === 'blocked' && outcome.ip) {
      buttons = buttons
        .filter(button => !button.id.startsWith('incident_block_'))
        .map(button => button.id.startsWith('incident_threat_')
          ? { ...button, id: `incident_unblock_${incidentId}_${outcome.ip}`, label: 'Desbloquear', style: 'danger' as const }
          : button);
    }

    if (outcome.kind === 'unblocked' && outcome.ip) {
      buttons = buttons.filter(button => !button.id.startsWith('incident_unblock_'));
      buttons = [
        { id: `incident_block_${incidentId}_${outcome.ip}`, label: 'Bloquear IP', style: 'primary' as const },
        ...buttons,
      ];
    }

    buttons = buttons.filter((button, index) => buttons.findIndex(candidate => candidate.id === button.id) === index);

    const nextSpec: MessageSpec = {
      ...tracked.spec,
      action: {
        required: false,
        title: outcome.kind === 'failed' ? 'O que aconteceu' : 'O que já foi feito',
        steps: [outcome.label],
      },
      buttons,
      footer: `${tracked.spec.footer ?? ''} · atualizado agora`.trim(),
    };

    const result = await telegram.editSpec(tracked.chatId, tracked.messageId, nextSpec);
    if (result.ok) {
      this.tracked.set(incidentId, { ...tracked, spec: nextSpec });
    }
    return result.ok;
  }

  static async markResolved(
    incidentId: number,
    outcome: 'false_positive' | 'confirmed' | 'monitoring',
    operator: string,
  ): Promise<boolean> {
    const tracked = this.tracked.get(incidentId);
    if (!tracked) return false;

    const nextSpec = buildIncidentResolutionSpec(tracked.spec, outcome, operator);
    const result = await telegram.editSpec(tracked.chatId, tracked.messageId, nextSpec);
    if (result.ok) {
      this.tracked.set(incidentId, { ...tracked, spec: nextSpec });
    }
    return result.ok;
  }

  private static async notifyIncident(result: CorrelationResult): Promise<'sent' | 'digest' | 'skipped'> {
    const incidentId = result.incidentId;
    if (!incidentId) return 'skipped';

    const [incident] = await db.select().from(socIncidents).where(eq(socIncidents.id, incidentId));
    if (!incident) return 'skipped';

    const severity = this.severity(incident.severity);
    const sourceIp = (incident.sourceIps ?? [])[0] ?? result.event.sourceIp ?? null;
    const serverId = result.event.serverId;
    const serverName = await this.serverName(serverId);

    // Informação de baixa severidade não merece mensagem individual.
    if (severity === 'low') return 'digest';
    if (severity === 'medium' && !sourceIp) return 'digest';

    const category = incident.category ?? result.incidentCategory ?? result.event.category;
    const alreadyBlocked = sourceIp && category !== 'egress' ? await this.isBlocked(sourceIp, serverId) : false;

    const spec = buildIncidentSpec({
      incidentId,
      serverName,
      category,
      severity,
      sourceIp,
      containerName: result.event.metadata?.containerName as string | undefined,
      eventCount: incident.eventCount,
      firstSeenAt: incident.firstSeenAt,
      alreadyBlocked,
    });

    const sendResult = await NotifierManager.notifySpec(spec);
    const delivered = sendResult ? sendResult.ok : true;
    if (!delivered) return 'skipped';

    this.sentAt.set(incidentId, Date.now());
    if (sendResult?.messageId && sendResult.messageId > 0 && sendResult.chatId) {
      this.tracked.set(incidentId, {
        chatId: sendResult.chatId,
        messageId: sendResult.messageId,
        spec,
        sentAt: Date.now(),
      });
    }
    return 'sent';
  }

  private static async notifyDigest(entries: Array<{ id: number; label: string; serverName: string; severity: MessageSeverity }>): Promise<void> {
    const top = entries.slice(0, 3);
    const spec: MessageSpec = {
      kind: 'incident',
      severity: 'medium',
      title: `${formatNumber(entries.length)} novos incidentes`,
      lead: 'O Guardian abriu vários incidentes no mesmo ciclo. Os principais estão abaixo.',
      facts: top.map(entry => ({
        label: `#${entry.id}`,
        value: `${entry.label} em ${entry.serverName}`,
      })),
      action: {
        required: false,
        title: 'O que fazer agora',
        steps: ['Digite /incidents para ver todos e decidir caso a caso.'],
        fallbackCommand: '/incidents',
      },
      footer: entries.length > top.length ? `Mais ${formatNumber(entries.length - top.length)} incidentes no painel.` : undefined,
    };

    await NotifierManager.notifySpec(spec);
  }

  private static async serverName(serverId: number): Promise<string> {
    const [server] = await db.select({ name: socServers.name }).from(socServers).where(eq(socServers.id, serverId));
    return server?.name ?? `servidor #${serverId}`;
  }

  private static async isBlocked(ip: string, serverId: number): Promise<boolean> {
    const rows = await db.select({ id: blockedIps.id })
      .from(blockedIps)
      .where(and(
        eq(blockedIps.serverId, serverId),
        eq(blockedIps.active, true),
        inArray(blockedIps.ip, [ip]),
      ))
      .limit(1);
    return rows.length > 0;
  }

  private static severity(value: string | null | undefined): MessageSeverity {
    if (value === 'critical' || value === 'high' || value === 'medium' || value === 'low') return value;
    return 'medium';
  }

  /** Apenas para testes. */
  static resetForTests(): void {
    this.tracked.clear();
    this.sentAt.clear();
  }
}
