import type { MessageSeverity, MessageSpec } from '../messaging/types.js';
import { formatNumber, severityWord } from '../messaging/style.js';

export interface CveCopyInput {
  alertId: number;
  cveId: string;
  packageName: string;
  installedVersion: string;
  fixedVersion?: string | null;
  ecosystem: string;
  serverName: string;
  /** 0–100, como o Guardian armazena. */
  cvssScore?: number | null;
  isKev?: boolean;
  epssScore?: number | null;
  summary?: string | null;
}

export interface CveSummaryInput {
  serverName: string;
  total: number;
  critical: number;
  high: number;
  kevCount: number;
  epssCount: number;
  top: Array<{ cveId: string; packageName: string; cvss: number; kev?: boolean; epss?: number | null }>;
}

export function cveSeverity(cvssScore?: number | null): MessageSeverity {
  const score = (cvssScore ?? 0) / 10;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

export function buildCveSpec(input: CveCopyInput): MessageSpec {
  const severity = cveSeverity(input.cvssScore);
  const hasFix = !!input.fixedVersion;
  const score = input.cvssScore ? (input.cvssScore / 10).toFixed(1).replace('.', ',') : null;

  const facts = [
    { label: 'Servidor', value: input.serverName },
    { label: 'Pacote', value: `${input.packageName} ${input.installedVersion}`, code: true },
    { label: 'CVE', value: input.cveId, code: true },
    ...(score ? [{ label: 'CVSS', value: `${score} de 10` }] : []),
    ...(input.isKev ? [{ label: 'KEV', value: 'já explorada na vida real' }] : []),
  ];

  const explanation: string[] = [];
  if (input.isKev) {
    explanation.push('Esta falha está no catálogo KEV: já foi explorada por atacantes na vida real.');
  }
  if (input.epssScore !== null && input.epssScore !== undefined && input.epssScore >= 0.5) {
    explanation.push(`A chance estimada de exploração nos próximos 30 dias é alta (${Math.round(input.epssScore * 100)}%).`);
  }
  if (explanation.length === 0) {
    explanation.push('CVSS mede a gravidade da falha; quanto maior, mais fácil de explorar e mais grave o impacto.');
  }

  const action = hasFix
    ? {
        required: severity === 'critical' || !!input.isKev,
        title: 'O que fazer agora',
        steps: [
          `Atualize para ${input.fixedVersion}.`,
          severity === 'critical' || input.isKev
            ? 'Faça isso hoje: a falha é grave e tem correção disponível.'
            : 'Se não puder agora, atualize na próxima janela de manutenção.',
        ],
        fallbackCommand: '/vulns',
      }
    : {
        required: false,
        title: 'O que fazer agora',
        steps: [
          'Ainda não há correção publicada.',
          'Reduza a exposição do serviço e acompanhe a atualização do fornecedor.',
        ],
      };

  const buttons = [
    ...(hasFix ? [{ id: `cve_update_${input.alertId}`, label: 'Atualizar agora', style: 'primary' as const }] : []),
    { id: `cve_details_${input.alertId}`, label: 'Ver detalhes', style: 'neutral' as const },
    { id: `cve_ignore_${input.alertId}`, label: 'Ignorar', style: 'neutral' as const },
  ];

  return {
    kind: 'cve',
    severity,
    title: `Falha ${severityWord(severity)} em ${input.packageName}`,
    lead: `${input.serverName} usa ${input.packageName} ${input.installedVersion}, que tem uma falha ${severityWord(severity)}.`,
    facts,
    meaning: explanation.join(' '),
    action,
    buttons,
    footer: `Alerta #${input.alertId} · ${input.cveId}`,
  };
}

export function buildCveSummarySpec(input: CveSummaryInput): MessageSpec {
  const topLines = input.top.slice(0, 5).map(item => {
    const tags = [
      item.kev ? 'KEV' : null,
      item.epss !== null && item.epss !== undefined && item.epss >= 0.5 ? `EPSS ${Math.round(item.epss * 100)}%` : null,
    ].filter(Boolean).join(', ');
    return `${item.cveId} — ${item.packageName} (CVSS ${(item.cvss / 10).toFixed(1).replace('.', ',')}${tags ? `; ${tags}` : ''})`;
  });

  return {
    kind: 'cve',
    severity: input.critical > 0 ? 'critical' : 'high',
    title: `${formatNumber(input.total)} falhas encontradas`,
    lead: `A varredura encontrou ${formatNumber(input.total)} falhas em ${input.serverName}.`,
    facts: [
      { label: 'Críticas', value: formatNumber(input.critical) },
      { label: 'Altas', value: formatNumber(input.high) },
      ...(input.kevCount > 0 ? [{ label: 'KEV', value: input.kevCount === 1 ? '1 já explorada' : `${formatNumber(input.kevCount)} já exploradas` }] : []),
      ...(input.epssCount > 0 ? [{ label: 'EPSS alta', value: formatNumber(input.epssCount) }] : []),
    ],
    meaning: topLines.length > 0
      ? `Principais: ${topLines.join(' · ')}`
      : undefined,
    action: {
      required: input.critical > 0 || input.kevCount > 0,
      title: 'O que fazer agora',
      steps: [
        input.kevCount > 0
          ? 'Comece pelas marcadas como KEV: já estão sendo exploradas.'
          : 'Comece pelas críticas.',
        'Digite /vulns para ver a lista completa.',
      ],
    },
    footer: `${formatNumber(input.total)} falhas · ${input.serverName}`,
  };
}
