import type { MessageSpec } from '../messaging/types.js';
import { formatWhen } from '../messaging/style.js';

export interface ApprovalCopyInput {
  approvalId: string;
  playbookName: string;
  serverName: string;
  sourceIp?: string | null;
  containerName?: string | null;
  incidentId?: number | null;
  actionTitle: string;
  impact: string;
  steps: string[];
  expiresAt: Date;
}

export function buildApprovalSpec(input: ApprovalCopyInput): MessageSpec {
  const facts = [
    { label: 'Servidor', value: input.serverName },
    ...(input.containerName ? [{ label: 'Container', value: input.containerName, code: true }] : []),
    ...(input.sourceIp ? [{ label: 'IP', value: input.sourceIp, code: true }] : []),
    ...(input.incidentId ? [{ label: 'Incidente', value: `#${input.incidentId}`, code: true }] : []),
  ];

  return {
    kind: 'approval',
    severity: 'high',
    title: 'Preciso da sua autorização',
    lead: `O Guardian quer ${input.actionTitle.charAt(0).toLowerCase()}${input.actionTitle.slice(1)} em ${input.serverName}.`,
    facts,
    meaning: input.impact,
    action: {
      required: true,
      title: 'O que vai acontecer se você aprovar',
      steps: input.steps.slice(0, 3),
      deadline: input.expiresAt,
      ifIgnored: 'Se ninguém responder, nada será executado.',
    },
    buttons: [
      { id: `pb_approve_${input.approvalId}`, label: 'Aprovar', style: 'primary' },
      { id: `pb_reject_${input.approvalId}`, label: 'Rejeitar', style: 'danger' },
    ],
    footer: `Pedido feito ${formatWhen(new Date())}.`,
  };
}

export function buildApprovalResolvedSpec(
  base: MessageSpec,
  approved: boolean,
  operator: string,
  detail?: string,
): MessageSpec {
  const title = approved ? 'Ação aprovada' : 'Ação rejeitada';
  const outcome = approved
    ? `Aprovada por ${operator}.`
    : `Rejeitada por ${operator}. Nada foi executado.`;

  return {
    ...base,
    title,
    severity: approved ? 'medium' : 'low',
    action: {
      required: false,
      title: 'Resultado',
      steps: [outcome, ...(detail ? [detail] : [])].slice(0, 3),
    },
    buttons: [],
    footer: base.footer,
  };
}
