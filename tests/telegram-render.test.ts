import { describe, expect, it } from 'vitest';
import { buildIncidentSpec } from '../src/telegram/copy/incident.js';
import { buildApprovalSpec } from '../src/telegram/copy/approval.js';
import { buildCveSpec } from '../src/telegram/copy/cve.js';
import { buildLoginSpec } from '../src/telegram/copy/login.js';
import { renderPlain, renderTelegram } from '../src/telegram/messaging/render.js';
import type { MessageSpec } from '../src/telegram/messaging/types.js';

const incidentBase = {
  incidentId: 42,
  serverName: 'hetzner-prod',
  category: 'brute_force',
  severity: 'high' as const,
  sourceIp: '203.0.113.50',
  eventCount: 20,
  firstSeenAt: new Date('2026-10-30T16:08:00-03:00'),
};

function forbidden(text: string): string[] {
  const problems: string[] = [];
  if (/&#\d+;/.test(text)) problems.push('html entity');
  if (/Playbook Alert/i.test(text)) problems.push('playbook alert');
  if (/\[(HIGH|CRITICAL|MEDIUM|LOW)\]/.test(text)) problems.push('bracket severity');
  if (/\b(undefined|NaN|null)\b/.test(text)) problems.push('undefined/NaN/null');
  if (/\b[A-Z]{5,}\b/.test(text)) problems.push('all caps');
  return problems;
}

describe('incident copy', () => {
  it('asks for a decision when the IP is not blocked', () => {
    const spec = buildIncidentSpec(incidentBase);
    const { text, replyMarkup } = renderTelegram(spec);

    expect(text).toContain('Força bruta no SSH');
    expect(text).toContain('hetzner-prod');
    expect(text).toContain('203.0.113.50');
    expect(text).toContain('O que fazer agora');
    expect(spec.action?.required).toBe(true);

    const ids = replyMarkup?.inline_keyboard.flat().map(button => button.callback_data) ?? [];
    expect(ids).toContain('incident_block_42_203.0.113.50');
    expect(ids).toContain('incident_threat_42_203.0.113.50');
    expect(forbidden(text)).toEqual([]);
  });

  it('does not offer "block" again when the IP is already blocked', () => {
    const spec = buildIncidentSpec({ ...incidentBase, alreadyBlocked: true });
    const { text, replyMarkup } = renderTelegram(spec);
    const ids = replyMarkup?.inline_keyboard.flat().map(button => button.callback_data) ?? [];

    expect(spec.action?.required).toBe(false);
    expect(text).toContain('Não precisa fazer nada');
    expect(ids.some(id => id.startsWith('incident_block_'))).toBe(false);
    expect(ids).toContain('incident_unblock_42_203.0.113.50');
  });


  it('never offers to block the destination on an egress incident', () => {
    const spec = buildIncidentSpec({
      incidentId: 44,
      serverName: 'hetzner-prod',
      category: 'egress',
      severity: 'critical',
      sourceIp: '198.51.100.9',
      containerName: 'synthfin-web',
      eventCount: 60,
      firstSeenAt: new Date('2026-10-30T16:08:00-03:00'),
    });
    const { text, replyMarkup } = renderTelegram(spec);
    const ids = replyMarkup?.inline_keyboard.flat().map(button => button.callback_data) ?? [];

    expect(text).toMatch(/não bloqueie o destino/i);
    expect(ids.some(id => id.startsWith('incident_block_'))).toBe(false);
    expect(ids.some(id => id.startsWith('incident_unblock_'))).toBe(false);
    expect(ids.some(id => id.startsWith('incident_fp_'))).toBe(true);
  });

  it('does not blow up on HTML in server names', () => {
    const spec = buildIncidentSpec({ ...incidentBase, serverName: '<b>evil</b> & co' });
    const { text } = renderTelegram(spec);
    expect(text).not.toContain('<b>evil</b>');
    expect(text).toContain('&lt;b&gt;evil&lt;/b&gt; &amp; co');
  });
});

describe('approval copy', () => {
  it('explains impact, deadline and consequence of silence', () => {
    const spec = buildApprovalSpec({
      approvalId: 'abc',
      playbookName: 'container-auto-update',
      serverName: 'hetzner-prod',
      containerName: 'synthfin-web',
      incidentId: 7,
      actionTitle: 'Atualizar a imagem do container',
      impact: 'O serviço fica ~10 segundos fora do ar.',
      steps: ['Baixar a imagem', 'Recriar o container'],
      expiresAt: new Date('2026-10-30T18:00:00-03:00'),
    });
    const { text, replyMarkup } = renderTelegram(spec);

    expect(text).toContain('Preciso da sua autorização');
    expect(text).toContain('O serviço fica ~10 segundos fora do ar');
    expect(text).toContain('Se ninguém responder, nada será executado');
    const ids = replyMarkup?.inline_keyboard.flat().map(button => button.callback_data) ?? [];
    expect(ids).toEqual(['pb_approve_abc', 'pb_reject_abc']);
    expect(forbidden(text)).toEqual([]);
  });
});

describe('cve copy', () => {
  it('explains KEV and offers update when a fix exists', () => {
    const spec = buildCveSpec({
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
    });
    const { text, replyMarkup } = renderTelegram(spec);

    expect(text).toContain('CVE-2025-55182');
    expect(text).toContain('KEV');
    expect(text).toContain('15.2.6');
    expect(spec.action?.required).toBe(true);
    const ids = replyMarkup?.inline_keyboard.flat().map(button => button.callback_data) ?? [];
    expect(ids).toContain('cve_update_9');
    expect(forbidden(text)).toEqual([]);
  });

  it('does not offer update when there is no fix', () => {
    const spec = buildCveSpec({
      alertId: 10,
      cveId: 'CVE-2026-0001',
      packageName: 'openssl',
      installedVersion: '1.0',
      fixedVersion: null,
      ecosystem: 'Debian',
      serverName: 'srv',
      cvssScore: 75,
    });
    const { text, replyMarkup } = renderTelegram(spec);
    const ids = replyMarkup?.inline_keyboard.flat().map(button => button.callback_data) ?? [];
    expect(text).toContain('Ainda não há correção');
    expect(ids.some(id => id.startsWith('cve_update_'))).toBe(false);
  });
});

describe('login copy', () => {
  it('asks "foi você?" and explains what happens on silence', () => {
    const spec = buildLoginSpec({
      verificationId: 'v1',
      serverName: 'srv',
      userName: 'root',
      sourceIp: '198.51.100.7',
      authMethod: 'publickey',
      fingerprint: 'SHA256:abc',
      country: 'RU',
      score: 90,
      totalReports: 10,
      timestamp: new Date('2026-10-30T10:00:00-03:00'),
      expiresAt: new Date('2026-10-30T10:30:00-03:00'),
    });
    const { text, replyMarkup } = renderTelegram(spec);
    expect(text).toContain('Foi você?');
    expect(text).toContain('expira');
    const ids = replyMarkup?.inline_keyboard.flat().map(button => button.callback_data) ?? [];
    expect(ids).toContain('login_yes_v1');
    expect(ids).toContain('login_no_v1');
    expect(forbidden(text)).toEqual([]);
  });
});

describe('renderer', () => {
  it('drops callback_data above 64 bytes instead of breaking the keyboard', () => {
    const longId = `incident_block_1_${'a'.repeat(80)}`;
    const spec: MessageSpec = {
      kind: 'incident',
      severity: 'high',
      title: 'Teste',
      lead: 'Teste',
      buttons: [{ id: longId, label: 'Bloquear', style: 'primary' }],
    };
    expect(renderTelegram(spec).replyMarkup).toBeUndefined();
  });


  it('escapes report section lines', () => {
    const spec: MessageSpec = {
      kind: 'report',
      severity: 'low',
      title: 'Relatório',
      lead: 'Resumo',
      sections: [{ title: 'Detalhes', lines: ['servidor <b>evil</b>', 'ok'] }],
    };
    const { text } = renderTelegram(spec);
    expect(text).toContain('&lt;b&gt;evil&lt;/b&gt;');
    expect(text).not.toContain('<b>evil</b>');
  });

  it('plain rendering has no HTML tags', () => {
    const spec = buildIncidentSpec(incidentBase);
    const plain = renderPlain(spec);
    expect(plain).not.toMatch(/<[^>]+>/);
    expect(plain).toContain('Força bruta no SSH');
  });
});
