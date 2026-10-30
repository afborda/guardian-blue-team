import type { MessageButton, MessageSeverity, MessageSpec } from '../messaging/types.js';
import { formatNumber, formatWhen } from '../messaging/style.js';

export interface IncidentCopyInput {
  incidentId: number;
  serverName: string;
  category?: string | null;
  severity: MessageSeverity;
  sourceIp?: string | null;
  containerName?: string | null;
  eventCount?: number;
  firstSeenAt?: Date | null;
  alreadyBlocked?: boolean;
  /** Ex.: "IP bloqueado", "container isolado". */
  containment?: string | null;
}

const CATEGORY_LABELS: Record<string, string> = {
  brute_force: 'Força bruta no SSH',
  port_scan: 'Varredura de portas',
  unauthorized_access: 'Acesso não reconhecido',
  ddos: 'Tráfego de ataque (DDoS)',
  container: 'Atividade suspeita em container',
  integrity: 'Arquivo crítico alterado',
  dns: 'Consulta DNS suspeita',
  egress: 'Tráfego de saída suspeito',
  container_rce: 'Possível execução remota',
  crypto_mining: 'Mineração de cripto',
  lateral_movement: 'Movimento lateral',
  backup: 'Problema no backup',
  system: 'Problema no sistema',
};

const CATEGORY_MEANING: Record<string, string> = {
  brute_force: 'Alguém tentou adivinhar a senha do SSH. Se o IP não é seu, bloquear é seguro.',
  port_scan: 'Alguém testou portas para descobrir o que está aberto. Isso, sozinho, não significa que entrou.',
  unauthorized_access: 'Houve um login fora do padrão conhecido. Confirme se foi você ou alguém da equipe.',
  ddos: 'O volume de conexões passou do normal e pode afetar a disponibilidade do site.',
  container: 'Um processo ou container fez algo fora do padrão. Vale olhar antes de reiniciar qualquer coisa.',
  integrity: 'Um arquivo crítico mudou. Pode ser atualização legítima ou backdoor.',
  egress: 'Um container começou a falar com muitos destinos diferentes. É o padrão de um scan ou de um malware.',
  container_rce: 'O stdout do container tem sinal de execução de comando. Pode ser exploit em andamento; isolar preserva a evidência.',
  crypto_mining: 'Um processo está usando CPU para minerar cripto. Costuma indicar invasão.',
  lateral_movement: 'Alguém tentou se mover de uma máquina para outra dentro da rede.',
  backup: 'O backup diário não foi gerado como esperado.',
  system: 'O sistema operacional registrou um problema que merece conferência.',
};

export function categoryLabel(category?: string | null): string {
  if (!category) return 'Atividade suspeita';
  return CATEGORY_LABELS[category] ?? 'Atividade suspeita';
}

function plural(count: number, singular: string, pluralWord: string): string {
  return count === 1 ? singular : pluralWord;
}

function incidentButtons(input: IncidentCopyInput): MessageButton[] {
  const buttons: MessageButton[] = [];
  const isContainerThreat = input.category === 'egress' || input.category === 'container_rce';

  if (input.sourceIp && !isContainerThreat) {
    if (input.alreadyBlocked) {
      buttons.push({
        id: `incident_unblock_${input.incidentId}_${input.sourceIp}`,
        label: 'Desbloquear',
        style: 'danger',
      });
    } else {
      buttons.push({
        id: `incident_block_${input.incidentId}_${input.sourceIp}`,
        label: 'Bloquear IP',
        style: 'primary',
      });
    }
    buttons.push({
      id: `incident_threat_${input.incidentId}_${input.sourceIp}`,
      label: 'Ver reputação',
      style: 'neutral',
    });
  }

  buttons.push(
    { id: `incident_fp_${input.incidentId}`, label: 'Falso positivo', style: 'neutral' },
    { id: `incident_confirm_${input.incidentId}`, label: 'Confirmar', style: 'neutral' },
    { id: `incident_monitor_${input.incidentId}`, label: 'Monitorar', style: 'neutral' },
  );

  return buttons;
}

export function buildIncidentSpec(input: IncidentCopyInput): MessageSpec {
  const label = categoryLabel(input.category);
  const count = input.eventCount && input.eventCount > 0 ? input.eventCount : 1;
  const when = formatWhen(input.firstSeenAt ?? new Date());
  const containerPart = input.containerName ? ` no container ${input.containerName}` : '';

  const lead = input.category === 'brute_force'
    ? `O servidor ${input.serverName} registrou ${formatNumber(count)} ${plural(count, 'tentativa', 'tentativas')} de login em ${when}.`
    : input.category === 'egress'
      ? `${input.serverName} viu o container ${input.containerName ?? 'monitorado'} abrir conexões de saída para muitos destinos, ${when}.`
      : input.category === 'container_rce'
        ? `${input.serverName} viu sinal de execução de comando no container ${input.containerName ?? 'monitorado'}, ${when}.`
      : `${input.serverName} registrou ${formatNumber(count)} ${plural(count, 'evento', 'eventos')} de ${label.toLowerCase()}${containerPart}, ${when}.`;

  const facts = [
    { label: 'Servidor', value: input.serverName },
    ...(input.containerName ? [{ label: 'Container', value: input.containerName, code: true }] : []),
    ...(input.sourceIp
      ? [{
          label: input.category === 'egress' ? 'Primeiro destino' : 'IP',
          value: input.sourceIp,
          code: true,
        }]
      : []),
    { label: 'Incidente', value: `#${input.incidentId}`, code: true },
  ];

  const contained = input.alreadyBlocked || !!input.containment;
  const isContainerThreat = input.category === 'egress' || input.category === 'container_rce';

  const action = isContainerThreat && !contained
    ? {
        required: false,
        title: 'O que fazer agora',
        steps: [
          input.category === 'egress'
            ? 'O Guardian vai isolar o container. Não bloqueie o destino: ele é vítima do scan, não a origem.'
            : 'O Guardian vai isolar o container. Não reinicie: preserve a evidência.',
        ],
      }
    : contained
    ? {
        required: false,
        title: 'O que já foi feito',
        steps: [
          input.containment
            ?? (input.sourceIp
              ? `O IP ${input.sourceIp} já está bloqueado. Não precisa fazer nada.`
              : 'Já existe uma contenção ativa. Não precisa fazer nada.'),
        ],
      }
    : input.sourceIp
      ? {
          required: true,
          title: 'O que fazer agora',
          steps: [
            'Confira se reconhece esse IP.',
            'Se não reconhecer, bloqueie agora.',
          ],
          fallbackCommand: `/block ${input.sourceIp}`,
        }
      : {
          required: false,
          title: 'O que fazer agora',
          steps: ['Nada urgente. O incidente ficou registrado para análise.'],
        };

  return {
    kind: 'incident',
    severity: input.severity,
    title: label,
    lead,
    facts,
    meaning: CATEGORY_MEANING[input.category ?? ''] ?? undefined,
    action,
    buttons: incidentButtons(input),
    footer: `Incidente #${input.incidentId} · ${when}`,
    dedupeKey: `incident:${input.incidentId}`,
  };
}

/** Mensagem curta para desfecho (falso positivo/confirmado). */
export function buildIncidentResolutionSpec(
  base: MessageSpec,
  outcome: 'false_positive' | 'confirmed' | 'monitoring',
  operator: string,
): MessageSpec {
  const label = outcome === 'false_positive'
    ? 'Marcado como falso positivo'
    : outcome === 'confirmed'
      ? 'Confirmado como ameaça'
      : 'Em monitoramento';

  const keepFeedback = outcome === 'monitoring'
    ? (base.buttons ?? []).filter(button => button.id.includes('_fp_') || button.id.includes('_confirm_'))
    : [];

  return {
    ...base,
    action: {
      required: false,
      title: 'Registrado',
      steps: [`${label} por ${operator}.`],
    },
    buttons: keepFeedback,
    footer: `${base.footer ?? ''} · ${label}`.trim(),
  };
}
