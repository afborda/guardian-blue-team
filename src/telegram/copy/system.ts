import type { MessageSpec } from '../messaging/types.js';
import { cleanText, formatNumber } from '../messaging/style.js';

export interface ThreatHuntInput {
  count: number;
  findings: Array<{ severity: string; description: string }>;
  summary: string;
  provider?: string | null;
}

export function buildThreatHuntSpec(input: ThreatHuntInput): MessageSpec {
  const top = input.findings
    .filter(finding => finding.severity === 'critical' || finding.severity === 'high')
    .slice(0, 3)
    .map(finding => `• ${cleanText(finding.description, 180)}`);

  return {
    kind: 'system',
    severity: input.findings.some(finding => finding.severity === 'critical') ? 'critical' : 'high',
    title: input.count === 1 ? 'Sinal encontrado pela caça' : `${formatNumber(input.count)} sinais encontrados pela caça`,
    lead: 'A análise proativa cruzou os eventos recentes e encontrou padrões que merecem uma olhada.',
    facts: [
      { label: 'Achados', value: formatNumber(input.count) },
      ...(input.provider ? [{ label: 'Analisado por', value: input.provider }] : []),
    ],
    meaning: [top.join('\n'), cleanText(input.summary, 300)].filter(Boolean).join('\n\n') || undefined,
    action: {
      required: false,
      title: 'O que fazer agora',
      steps: ['Revise os achados. Se algum IP ou servidor não fizer sentido, investigue antes de bloquear.'],
    },
  };
}

export interface VulnReportInput {
  servers: Array<{
    serverName: string;
    totalFindings: number;
    portsOpen: number;
    portsUnexpected: number;
    packagesUpgradable: number;
    securityUpdates: number;
    dockerIssues: number;
    runtimeEolCount?: number;
  }>;
}

export function buildVulnReportSpec(input: VulnReportInput): MessageSpec {
  const total = input.servers.reduce((sum, server) => sum + server.totalFindings, 0);
  const worst = [...input.servers].sort((a, b) => b.totalFindings - a.totalFindings).slice(0, 3);
  const lines = worst.map(server =>
    `• ${server.serverName}: ${formatNumber(server.totalFindings)} achados, ${formatNumber(server.portsUnexpected)} portas inesperadas, ${formatNumber(server.securityUpdates)} atualizações de segurança`);

  return {
    kind: 'report',
    severity: total > 10 ? 'high' : 'medium',
    title: 'Relatório semanal de vulnerabilidades',
    lead: `A varredura encontrou ${formatNumber(total)} achados em ${formatNumber(input.servers.length)} servidores.`,
    facts: [
      { label: 'Achados', value: formatNumber(total) },
      { label: 'Servidores', value: formatNumber(input.servers.length) },
    ],
    meaning: lines.join('\n'),
    action: {
      required: total > 10,
      title: 'O que fazer agora',
      steps: total > 10
        ? ['Comece pelos servidores com mais achados.', 'Digite /vulns para ver o relatório completo.']
        : ['Nada urgente. Acompanhe na próxima varredura.'],
      fallbackCommand: '/vulns',
    },
  };
}

export interface PlaybookNoticeInput {
  serverName: string;
  actionTitle: string;
  impact: string;
  containerName?: string | null;
  sourceIp?: string | null;
  incidentId?: number | null;
  executed: boolean;
}

export function buildPlaybookNoticeSpec(input: PlaybookNoticeInput): MessageSpec {
  return {
    kind: 'system',
    severity: 'high',
    title: `${input.actionTitle} em ${input.serverName}`,
    lead: input.executed
      ? `O Guardian executou "${input.actionTitle}" em ${input.serverName}.`
      : `O Guardian tentou "${input.actionTitle}" em ${input.serverName}.`,
    facts: [
      { label: 'Servidor', value: input.serverName },
      ...(input.containerName ? [{ label: 'Container', value: input.containerName, code: true }] : []),
      ...(input.sourceIp ? [{ label: 'IP', value: input.sourceIp, code: true }] : []),
      ...(input.incidentId ? [{ label: 'Incidente', value: `#${input.incidentId}`, code: true }] : []),
    ],
    meaning: input.impact,
    action: {
      required: false,
      title: 'O que já foi feito',
      steps: [input.impact],
    },
  };
}

export interface DockerCveInput {
  newFindings: number;
  criticalImages: string[];
  trivyFindings: number;
  npmFindings: number;
}

export function buildDockerCveSpec(input: DockerCveInput): MessageSpec {
  const critical = input.criticalImages.length > 0;
  return {
    kind: 'cve',
    severity: critical ? 'critical' : 'high',
    title: `${formatNumber(input.newFindings)} falhas em imagens Docker`,
    lead: `A varredura local encontrou ${formatNumber(input.newFindings)} falhas novas nas imagens deste host.`,
    facts: [
      { label: 'Novas', value: formatNumber(input.newFindings) },
      { label: 'Trivy', value: formatNumber(input.trivyFindings) },
      { label: 'npm', value: formatNumber(input.npmFindings) },
      ...(critical ? [{ label: 'Imagens críticas', value: input.criticalImages.slice(0, 3).join(', ') }] : []),
    ],
    action: {
      required: critical,
      title: 'O que fazer agora',
      steps: critical
        ? ['Atualize primeiro as imagens com falha crítica.', 'Digite /vulns para ver os detalhes.']
        : ['Atualize na próxima janela de manutenção.', 'Digite /vulns para ver os detalhes.'],
      fallbackCommand: '/vulns',
    },
  };
}
