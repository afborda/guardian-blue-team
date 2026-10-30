/**
 * Prévia offline das mensagens do Guardian.
 *
 * Uso:
 *   npm run preview:telegram
 *   npm run preview:telegram -- --family incident
 *   npm run preview:telegram -- --json
 *
 * Não faz chamada de rede e não precisa de TELEGRAM_BOT_TOKEN.
 */
import { buildIncidentSpec } from '../src/telegram/copy/incident.js';
import { buildApprovalSpec } from '../src/telegram/copy/approval.js';
import { buildCveSpec, buildCveSummarySpec } from '../src/telegram/copy/cve.js';
import { buildLoginSpec } from '../src/telegram/copy/login.js';
import {
  buildBlockLostSpec,
  buildDdosEscalationSpec,
  buildPropagationFailedSpec,
} from '../src/telegram/copy/block.js';
import { buildThreatHuntSpec, buildVulnReportSpec } from '../src/telegram/copy/system.js';
import { renderPlain, renderTelegram } from '../src/telegram/messaging/render.js';
import type { MessageSpec } from '../src/telegram/messaging/types.js';
import { existsSync, readFileSync } from 'node:fs';

const now = new Date('2026-10-30T16:08:00-03:00');
const later = new Date('2026-10-30T16:38:00-03:00');

const samples: Array<{ family: string; name: string; spec: MessageSpec }> = [
  {
    family: 'incident',
    name: 'Incidente com IP ainda não bloqueado',
    spec: buildIncidentSpec({
      incidentId: 42,
      serverName: 'hetzner-prod',
      category: 'brute_force',
      severity: 'high',
      sourceIp: '203.0.113.50',
      eventCount: 20,
      firstSeenAt: now,
    }),
  },
  {
    family: 'incident',
    name: 'Incidente já contido',
    spec: buildIncidentSpec({
      incidentId: 43,
      serverName: 'hetzner-prod',
      category: 'port_scan',
      severity: 'medium',
      sourceIp: '198.51.100.7',
      eventCount: 12,
      firstSeenAt: now,
      alreadyBlocked: true,
    }),
  },
  {
    family: 'approval',
    name: 'Aprovação de atualização de container',
    spec: buildApprovalSpec({
      approvalId: 'preview',
      playbookName: 'container-auto-update',
      serverName: 'hetzner-prod',
      containerName: 'synthfin-web',
      incidentId: 7,
      actionTitle: 'Atualizar a imagem do container',
      impact: 'A imagem corrigida é baixada e o container é recriado. O serviço fica ~10 segundos fora do ar.',
      steps: ['Baixar a imagem corrigida', 'Recriar o container', 'Avisar a equipe'],
      expiresAt: later,
    }),
  },
  {
    family: 'cve',
    name: 'CVE crítica com correção',
    spec: buildCveSpec({
      alertId: 9,
      cveId: 'CVE-2025-55182',
      packageName: 'next',
      installedVersion: '15.2.3',
      fixedVersion: '15.2.6',
      ecosystem: 'npm',
      serverName: 'hetzner-prod',
      cvssScore: 100,
      isKev: true,
      epssScore: 0.9,
    }),
  },
  {
    family: 'cve',
    name: 'Resumo de CVEs',
    spec: buildCveSummarySpec({
      serverName: 'hetzner-prod',
      total: 7,
      critical: 2,
      high: 3,
      kevCount: 1,
      epssCount: 2,
      top: [
        { cveId: 'CVE-2025-55182', packageName: 'next', cvss: 100, kev: true },
        { cveId: 'CVE-2026-0001', packageName: 'openssl', cvss: 91 },
        { cveId: 'CVE-2026-0002', packageName: 'glibc', cvss: 82, epss: 0.7 },
      ],
    }),
  },
  {
    family: 'login',
    name: 'Login SSH suspeito',
    spec: buildLoginSpec({
      verificationId: 'preview',
      serverName: 'hetzner-prod',
      userName: 'root',
      sourceIp: '198.51.100.7',
      authMethod: 'publickey',
      fingerprint: 'SHA256:abc123',
      country: 'RU',
      isp: 'Example ISP',
      score: 90,
      totalReports: 10,
      timestamp: now,
      expiresAt: later,
    }),
  },
  {
    family: 'block',
    name: 'Bloqueio não confirmado',
    spec: buildBlockLostSpec('hetzner-prod', '2a01:ecc0:40:97c::2', 428, now.toISOString()),
  },
  {
    family: 'block',
    name: 'Bloqueio não propagado',
    spec: buildPropagationFailedSpec('203.0.113.50', 'ovh-2', 3, 'ssh: connection timeout'),
  },
  {
    family: 'block',
    name: 'DDoS escalado',
    spec: buildDdosEscalationSpec('203.0.113.50', 'hetzner-prod', 4),
  },
  {
    family: 'system',
    name: 'Caça ameaças',
    spec: buildThreatHuntSpec({
      count: 2,
      findings: [
        { severity: 'high', description: 'Processo next-server abrindo conexões para muitos destinos.' },
        { severity: 'medium', description: 'Login SSH fora do horário habitual.' },
      ],
      summary: 'Padrão compatível com scan de saída a partir de um container.',
      provider: 'ollama',
    }),
  },
  {
    family: 'report',
    name: 'Relatório diário (resumo + detalhes)',
    spec: {
      kind: 'report',
      severity: 'high',
      title: 'Relatório diário de segurança',
      lead: 'Nas últimas 24h: 1.234 eventos, 3 novos incidentes e 2 em aberto, em 2 servidores.',
      facts: [
        { label: 'Eventos', value: '1.234' },
        { label: 'Novos incidentes', value: '3' },
        { label: 'Em aberto', value: '2' },
        { label: 'Servidores', value: '2' },
      ],
      action: {
        required: true,
        title: 'Precisa de você',
        steps: ['Digite /incidents para revisar os 2 incidente(s) aberto(s).'],
        fallbackCommand: '/incidents',
      },
      sections: [{
        title: 'Detalhes das últimas 24h',
        lines: [
          'Últimas 24h:',
          '   • 3 novos incidentes (2 abertos)',
          'Top atacantes:',
          '   1. 203.0.113.50 — 120 eventos',
          'Scores:',
          '   🟢 hetzner-prod: 84/100',
        ],
      }],
    },
  },
  {
    family: 'report',
    name: 'Relatório de vulnerabilidades',
    spec: buildVulnReportSpec({
      servers: [
        { serverName: 'hetzner-prod', totalFindings: 7, portsOpen: 5, portsUnexpected: 1, packagesUpgradable: 12, securityUpdates: 3, dockerIssues: 1 },
        { serverName: 'ovh-2', totalFindings: 2, portsOpen: 3, portsUnexpected: 0, packagesUpgradable: 4, securityUpdates: 1, dockerIssues: 0 },
      ],
    }),
  },
];

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const familyArg = args.indexOf('--family');
  const family = familyArg >= 0 ? args[familyArg + 1] : undefined;
  const asJson = args.includes('--json');

  const selected = family ? samples.filter(sample => sample.family === family) : samples;
  if (selected.length === 0) {
    console.error(`Nenhuma família "${family}". Opções: ${[...new Set(samples.map(s => s.family))].join(', ')}`);
    process.exitCode = 1;
    return;
  }

  if (asJson) {
    const payload = selected.map(sample => ({
      family: sample.family,
      name: sample.name,
      spec: sample.spec,
      rendered: renderTelegram(sample.spec),
      plain: renderPlain(sample.spec),
    }));
    console.log(JSON.stringify(payload, null, 2));
    return;
  }

  for (const sample of selected) {
    const { text } = renderTelegram(sample.spec);
    console.log('━'.repeat(72));
    console.log(`${sample.family.toUpperCase()} · ${sample.name} · ${text.length} chars`);
    console.log('━'.repeat(72));
    console.log(text);
    console.log('');
  }

  if (args.includes('--send')) {
    loadDotEnv();
    const chatId = process.env.TELEGRAM_TEST_CHAT_ID;
    if (!chatId) {
      console.error('--send exige TELEGRAM_TEST_CHAT_ID no ambiente.');
      process.exitCode = 1;
      return;
    }
    const { telegram } = await import('../src/telegram/messaging/sender.js');
    for (const sample of selected) {
      const result = await telegram.sendSpec(sample.spec, { chatId });
      console.log(`enviado ${sample.name}: ok=${result.ok} id=${result.messageId ?? '-'} erro=${result.error ?? '-'}`);
    }
  }
}

function loadDotEnv(): void {
  if (!existsSync('.env')) return;
  for (const rawLine of readFileSync('.env', 'utf8').split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim();
    let value = line.slice(separator + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

void main();
