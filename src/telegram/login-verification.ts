import { addTrustedIp, addTrustedFingerprint } from '../pipeline/detector.js';
import { ThreatIntelManager } from '../threat-intel/manager.js';
import { db, dbNow } from '../database/connection.js';
import { socIncidents, trustedEntities } from '../database/schema.js';
import { eq } from 'drizzle-orm';
import { secureId } from '../utils/sanitize.js';
import { logger } from '../utils/logger.js';
import { telegram } from './messaging/sender.js';
import type { MessageSpec } from './messaging/types.js';
import { buildLoginResolvedSpec, buildLoginSpec } from './copy/login.js';

interface PendingVerification {
  verificationId: string;
  incidentId: number;
  sourceIp: string;
  userName: string;
  serverName: string;
  authMethod: string;
  fingerprint: string | null;
  timestamp: Date;
  expiresAt: Date;
  spec?: MessageSpec;
  messageId?: number;
  chatId?: string;
}

interface LoginData {
  incidentId: number;
  sourceIp: string;
  userName: string;
  serverName: string;
  authMethod: string;
  fingerprint: string | null;
  timestamp: Date;
}

const pendingVerifications = new Map<string, PendingVerification>();
const processedCallbacks = new Set<string>();

export function requestLoginVerification(data: LoginData): void {
  const verificationId = secureId();
  const pending: PendingVerification = {
    verificationId,
    ...data,
    expiresAt: new Date(Date.now() + 30 * 60_000),
  };
  pendingVerifications.set(verificationId, pending);

  // Enriquecer em background e mandar uma única mensagem, com ou sem reputação.
  ThreatIntelManager.lookupIP(data.sourceIp)
    .then(report => sendVerification(pending, report))
    .catch(() => sendVerification(pending, null))
    .catch(err => logger.warn({ err, ip: data.sourceIp }, 'Falha ao enviar verificação de login'));

  setTimeout(() => {
    const current = pendingVerifications.get(verificationId);
    if (!current) return;
    pendingVerifications.delete(verificationId);

    if (current.chatId && current.messageId && current.spec) {
      void telegram.editSpec(current.chatId, current.messageId, {
        ...current.spec,
        title: 'Verificação expirada',
        severity: 'medium',
        action: {
          required: false,
          title: 'Resultado',
          steps: ['Ninguém respondeu em 30 minutos. O incidente continua aberto.'],
        },
        buttons: [],
      });
    }
  }, 30 * 60_000);
}

async function sendVerification(
  pending: PendingVerification,
  report: Awaited<ReturnType<typeof ThreatIntelManager.lookupIP>> | null,
): Promise<void> {
  const spec = buildLoginSpec({
    verificationId: pending.verificationId,
    serverName: pending.serverName,
    userName: pending.userName,
    sourceIp: pending.sourceIp,
    authMethod: pending.authMethod,
    fingerprint: pending.fingerprint,
    country: report?.country ?? null,
    isp: report?.isp ?? null,
    score: report?.score ?? null,
    totalReports: report?.totalReports ?? null,
    timestamp: pending.timestamp,
    expiresAt: pending.expiresAt,
  });

  pending.spec = spec;
  const result = await telegram.sendSpec(spec);
  if (result.ok && result.messageId && result.chatId) {
    pending.messageId = result.messageId;
    pending.chatId = result.chatId;
  } else {
    logger.warn({ ip: pending.sourceIp, error: result.error }, 'Falha ao enviar verificação de login');
  }
}

export async function handleLoginVerification(
  action: string,
  verificationId: string,
  callbackQuery: {
    id: string;
    message?: { message_id: number; chat: { id: number } };
    from?: { first_name?: string };
  },
): Promise<void> {
  // Prevent duplicate processing (Telegram can send same callback multiple times)
  const callbackKey = `${verificationId}:${action}`;
  if (processedCallbacks.has(callbackKey)) {
    await telegram.answer(callbackQuery.id, 'Já processado');
    return;
  }
  processedCallbacks.add(callbackKey);
  setTimeout(() => processedCallbacks.delete(callbackKey), 5 * 60_000);

  const pending = pendingVerifications.get(verificationId);

  const labels: Record<string, string> = { yes: 'Confirmado', no: 'Escalado', watch: 'Monitorando' };
  await telegram.answer(callbackQuery.id, labels[action] ?? 'OK');

  if (!pending) {
    await editMessage(callbackQuery.message, '⏰ Verificação expirada ou já processada.');
    return;
  }

  // Delete BEFORE processing to prevent race conditions
  pendingVerifications.delete(verificationId);
  const operator = callbackQuery.from?.first_name ?? 'operador';
  const finish = async (detail?: string) => {
    const base = pending.spec ?? buildLoginSpec({
      verificationId: pending.verificationId,
      serverName: pending.serverName,
      userName: pending.userName,
      sourceIp: pending.sourceIp,
      authMethod: pending.authMethod,
      fingerprint: pending.fingerprint,
      timestamp: pending.timestamp,
      expiresAt: pending.expiresAt,
    });
    const resolved = buildLoginResolvedSpec(base, action as 'yes' | 'no' | 'watch', operator, detail);
    if (pending.chatId && pending.messageId) {
      await telegram.editSpec(pending.chatId, pending.messageId, resolved);
    } else {
      await editMessage(callbackQuery.message, resolved.lead);
    }
  };

  if (action === 'yes') {
    addTrustedIp(pending.sourceIp);
    db.insert(trustedEntities).values({ entityType: 'ip', value: pending.sourceIp, addedBy: operator })
      .onConflictDoNothing().catch(err => logger.error({ err }, 'Failed to persist trusted IP'));

    if (pending.fingerprint) {
      const hashPart = pending.fingerprint.includes(' ')
        ? pending.fingerprint.split(' ')[1]
        : pending.fingerprint;
      addTrustedFingerprint(hashPart);
      db.insert(trustedEntities).values({ entityType: 'fingerprint', value: hashPart, addedBy: operator })
        .onConflictDoNothing().catch(err => logger.error({ err }, 'Failed to persist trusted fingerprint'));
    }
    await db.update(socIncidents)
      .set({ status: 'resolved', resolvedAt: dbNow() })
      .where(eq(socIncidents.id, pending.incidentId));

    await finish('O IP entrou na lista de confiança.');
    logger.info({ ip: pending.sourceIp, fingerprint: pending.fingerprint, operator }, 'Login confirmed as legitimate');
    return;
  }

  if (action === 'no') {
    await db.update(socIncidents)
      .set({ severity: 'critical' })
      .where(eq(socIncidents.id, pending.incidentId));

    await finish(`Incidente #${pending.incidentId} escalado para crítico.`);
    logger.warn({ ip: pending.sourceIp, incidentId: pending.incidentId, operator }, 'Login reported as unauthorized intrusion');
    return;
  }

  await finish(`Incidente #${pending.incidentId} continua aberto.`);
  logger.info({ ip: pending.sourceIp, incidentId: pending.incidentId }, 'Login set to monitor');
}

async function editMessage(
  message: { message_id: number; chat: { id: number } } | undefined,
  text: string,
): Promise<void> {
  if (!message) return;
  await telegram.editText(message.chat.id, message.message_id, text);
}
