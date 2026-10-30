import { NotifierManager } from '../../plugins/notifier-manager.js';
import { IncidentAlertService } from '../../services/incident-alert.service.js';
import { buildPlaybookNoticeSpec } from '../../telegram/copy/system.js';
import { playbookCopy } from '../../telegram/copy/playbook.js';
import { copyV2Enabled } from '../../telegram/messaging/flags.js';
import { logger } from '../../utils/logger.js';
import type { PlaybookContext } from '../engine.js';

export async function notify(
  ctx: PlaybookContext,
  params?: Record<string, unknown>,
): Promise<{ success: boolean; message: string }> {
  const severity = (params?.severity as string) ?? 'medium';
  const copy = playbookCopy(ctx.playbookName);
  const containerName = ctx.variables['containerName'] as string | undefined;
  const outcomeLabel = copy.nextStep ? `${copy.impact} ${copy.nextStep}` : copy.impact;

  try {
    if (!copyV2Enabled('approval')) {
      return await legacyNotify(ctx, severity, params);
    }

    // Se o incidente já tem uma mensagem, edita em vez de mandar outra.
    if (ctx.incidentId) {
      const edited = await IncidentAlertService.attachOutcome(ctx.incidentId, {
        label: outcomeLabel,
        kind: inferOutcomeKind(ctx.playbookName),
        ip: ctx.sourceIp,
      });
      if (edited) {
        return { success: true, message: `Incidente #${ctx.incidentId} atualizado` };
      }
    }

    const spec = buildPlaybookNoticeSpec({
      serverName: ctx.serverName,
      actionTitle: copy.actionTitle,
      impact: outcomeLabel,
      containerName,
      sourceIp: ctx.sourceIp,
      incidentId: ctx.incidentId,
      executed: true,
    });

    await NotifierManager.notifySpec(spec);
    return { success: true, message: `Notified (${severity})` };
  } catch (err) {
    logger.warn({ err, playbook: ctx.playbookName }, 'Falha ao notificar playbook');
    return { success: false, message: 'Notification failed' };
  }
}

function inferOutcomeKind(playbookName?: string): 'blocked' | 'isolated' | 'executed' {
  if (!playbookName) return 'executed';
  if (playbookName.startsWith('container')) return 'isolated';
  if (['ssh-brute-force', 'port-scan-response', 'lateral-movement-response', 'connection-flood-response', 'proxy-scanner-block'].includes(playbookName)) {
    return 'blocked';
  }
  return 'executed';
}

/** Caminho antigo, mantido apenas para rollback via TELEGRAM_COPY_V2=legacy. */
async function legacyNotify(
  ctx: PlaybookContext,
  severity: string,
  params?: Record<string, unknown>,
): Promise<{ success: boolean; message: string }> {
  const customMessage = params?.message as string | undefined;
  const lines: string[] = [];

  if (customMessage) {
    lines.push(customMessage, '');
  }

  lines.push('🚨 <b>Playbook Alert</b>', '');
  lines.push(`<b>Servidor:</b> ${ctx.serverName}`);
  const containerName = ctx.variables['containerName'] as string | undefined;
  if (containerName) lines.push(`<b>Container:</b> ${containerName}`);
  if (ctx.sourceIp) lines.push(`<b>IP origem:</b> <code>${ctx.sourceIp}</code>`);
  if (ctx.incidentId) lines.push(`<b>Incidente:</b> #${ctx.incidentId}`);
  lines.push(`<b>Severidade:</b> ${severity}`);

  await NotifierManager.notify({
    title: 'Playbook Alert',
    body: lines.join('\n'),
    severity: severity as 'critical' | 'high' | 'medium' | 'low',
    metadata: { server: ctx.serverName, triggeredBy: ctx.triggeredBy },
  });

  return { success: true, message: `Notified (${severity})` };
}
