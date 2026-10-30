import type { MessageSpec } from '../messaging/types.js';
import { formatWhen } from '../messaging/style.js';

export interface LoginCopyInput {
  verificationId: string;
  serverName: string;
  userName: string;
  sourceIp: string;
  authMethod: string;
  fingerprint?: string | null;
  country?: string | null;
  isp?: string | null;
  score?: number | null;
  totalReports?: number | null;
  timestamp: Date;
  expiresAt: Date;
}

function reputationLine(input: LoginCopyInput): string | null {
  if (input.score === null || input.score === undefined) return null;
  if (input.score >= 80) {
    return `Reputação ruim (${input.score}/100, ${input.totalReports ?? 0} denúncias). Trate como suspeito até confirmar.`;
  }
  if (input.score >= 40) {
    return `Reputação média (${input.score}/100). Vale confirmar antes de confiar.`;
  }
  return `Reputação limpa (${input.score}/100).`;
}

export function buildLoginSpec(input: LoginCopyInput): MessageSpec {
  const method = input.authMethod === 'publickey' ? 'chave pública' : 'senha';
  const place = input.country ? ` (${input.country}${input.isp ? `, ${input.isp}` : ''})` : '';

  const facts = [
    { label: 'Servidor', value: input.serverName },
    { label: 'Usuário', value: input.userName, code: true },
    { label: 'IP', value: input.sourceIp, code: true },
    { label: 'Método', value: method },
    ...(input.fingerprint ? [{ label: 'Fingerprint', value: input.fingerprint.slice(0, 60), code: true }] : []),
  ];

  const meaning = [
    reputationLine(input),
    'Se não foi você, marque “Não sou eu” para escalar o incidente imediatamente.',
  ].filter(Boolean).join(' ');

  return {
    kind: 'login',
    severity: input.score !== null && input.score !== undefined && input.score >= 80 ? 'critical' : 'high',
    title: `Login SSH em ${input.serverName}`,
    lead: `${input.userName} entrou por ${method} de ${input.sourceIp}${place}, ${formatWhen(input.timestamp)}.`,
    facts,
    meaning,
    action: {
      required: true,
      title: 'Foi você?',
      steps: [
        'Confirme se este acesso é seu.',
        'Se não for, marque “Não sou eu” para escalar agora.',
      ],
      deadline: input.expiresAt,
      ifIgnored: 'Se ninguém responder, a verificação expira e o incidente continua aberto.',
    },
    buttons: [
      { id: `login_yes_${input.verificationId}`, label: 'Sou eu', style: 'primary' },
      { id: `login_no_${input.verificationId}`, label: 'Não sou eu', style: 'danger' },
      { id: `login_watch_${input.verificationId}`, label: 'Monitorar', style: 'neutral' },
    ],
    footer: `Verificação aberta em ${formatWhen(new Date())}.`,
  };
}

export function buildLoginResolvedSpec(
  base: MessageSpec,
  action: 'yes' | 'no' | 'watch',
  operator: string,
  detail?: string,
): MessageSpec {
  const title = action === 'yes'
    ? 'Login confirmado'
    : action === 'no'
      ? 'Login reportado como invasão'
      : 'Login em monitoramento';

  const step = action === 'yes'
    ? `Confirmado por ${operator}. O IP entrou na lista de confiança.`
    : action === 'no'
      ? `Reportado como invasão por ${operator}. O incidente foi escalado para crítico.`
      : `Marcado para monitorar por ${operator}.`;

  return {
    ...base,
    severity: action === 'no' ? 'critical' : action === 'yes' ? 'low' : 'medium',
    title,
    action: {
      required: false,
      title: 'Resultado',
      steps: [step, ...(detail ? [detail] : [])].slice(0, 3),
    },
    buttons: [],
  };
}
