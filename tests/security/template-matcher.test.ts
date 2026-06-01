/**
 * template-matcher tests — regression contra os hashes do PoC validado em server-1.
 *
 * Os 4 hashes âncora foram congelados em 2026-05-31 (PoC v2, 26/26 PASS). Se algum
 * teste aqui falhar, é sinal vermelho: ou normalize() mudou (e o gerador precisa
 * rodar de novo), ou alguém mexeu no allowlist.json sem regenerar o shell.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { __resetForTests, matchTemplate } from '../../src/security/template-matcher.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../..');
const ALLOWLIST_JSON = resolve(REPO_ROOT, 'dist/security/allowlist.json');

// Hashes congelados do PoC v2 (26/26 PASS em server-1, 2026-05-31).
// Se algum desses muda, normalize() ou o template no allowed-commands.txt
// foi alterado — é um sinal vermelho que merece revisão manual.
const ANCHOR_HASHES = {
  authLogs: '3c0682b6dc926a36abbeb9ce6c952a6e25cbc8caf1e53f592ce01b8ea1a2192a',
  ufwLogs: '5cc6be2d9667d93f6577cdad6a53a72bcff6b6eac300e7e0685512bdeaff5d32',
  sudoCollector: '16044b22d56ed3c05d6fc832b23c727471e95b6823533a8836e301616ca87917',
  systemCollector: 'd42bfb226ac4341b351d69def69fc9cb97b81be06ce8882e4fabd246e9956b42',
};

describe('matchTemplate — anchor hashes', () => {
  beforeEach(() => {
    __resetForTests();
  });

  it('matches log-collector authLogs (ISO_DATETIME + LINES)', () => {
    const cmd =
      "sudo journalctl -u ssh -u sshd --since '2026-05-31 12:00:00' --no-pager -o short-iso 2>/dev/null || sudo tail -n 100 /var/log/auth.log 2>/dev/null || echo ''";
    const result = matchTemplate(cmd);
    expect(result.templateHash).toBe(ANCHOR_HASHES.authLogs);
    expect(result.normalized).toContain('%ISO_DATETIME%');
    expect(result.normalized).toContain('%LINES%');
  });

  it('matches log-collector ufwLogs (LINES -n form)', () => {
    const cmd = "sudo tail -n 200 /var/log/ufw.log 2>/dev/null || echo ''";
    const result = matchTemplate(cmd);
    expect(result.templateHash).toBe(ANCHOR_HASHES.ufwLogs);
  });

  it('matches sudo-collector (MINUTES + LINES)', () => {
    const cmd =
      "journalctl _COMM=sudo --since '15 min ago' --no-pager -o short-iso 2>/dev/null || grep -i sudo /var/log/auth.log | tail -n 100";
    const result = matchTemplate(cmd);
    expect(result.templateHash).toBe(ANCHOR_HASHES.sudoCollector);
  });

  it('matches system-collector (chained && with mixed placeholders)', () => {
    // Input REAL emitido por src/collectors/system-collector.ts:15-21 após o fix de aspas/forma -n.
    const cmd =
      'dmesg --time-format iso 2>/dev/null | tail -n 30 && echo "---SSEP---" && journalctl -p err --since \'5 min ago\' --no-pager -o short-iso 2>/dev/null | tail -n 20 && echo "---SSEP---" && systemctl list-units --failed --no-legend --no-pager 2>/dev/null';
    const result = matchTemplate(cmd);
    expect(result.templateHash).toBe(ANCHOR_HASHES.systemCollector);
  });

  it('returns the same hash regardless of LINES/MINUTES/ISO values', () => {
    const a = matchTemplate("sudo tail -n 10 /var/log/ufw.log 2>/dev/null || echo ''");
    const b = matchTemplate("sudo tail -n 9999 /var/log/ufw.log 2>/dev/null || echo ''");
    expect(a.templateHash).toBe(ANCHOR_HASHES.ufwLogs);
    expect(b.templateHash).toBe(ANCHOR_HASHES.ufwLogs);
    expect(a.templateHash).toBe(b.templateHash);
  });
});

describe('matchTemplate — non-matching commands', () => {
  beforeEach(() => {
    __resetForTests();
  });

  it('returns null templateHash for arbitrary commands', () => {
    const result = matchTemplate('rm -rf / --no-preserve-root');
    expect(result.templateHash).toBeNull();
    expect(result.normalized).toBeTypeOf('string');
  });

  it('returns null for commands that look similar but are not in allowlist', () => {
    // Tail de outro arquivo — mesmo padrão de placeholder, template diferente.
    const result = matchTemplate('sudo tail -n 100 /var/log/syslog');
    expect(result.templateHash).toBeNull();
  });

  it('returns null for empty string', () => {
    const result = matchTemplate('');
    expect(result.templateHash).toBeNull();
    expect(result.normalized).toBe('');
  });

  it('returns null for injection-shaped strings (tail with semicolon)', () => {
    // Normaliza igual ao template ufwLogs no início, mas o resto difere:
    // o template canônico não tem `; cat /etc/shadow`.
    const result = matchTemplate('sudo tail -n 100 /var/log/ufw.log; cat /etc/shadow');
    expect(result.templateHash).toBeNull();
  });

  it('always populates normalized field even when no match', () => {
    const result = matchTemplate('echo "hello world"');
    expect(result.normalized).toBe('echo "hello world"');
    expect(result.templateHash).toBeNull();
  });
});

describe('matchTemplate — graceful fallback when allowlist.json missing', () => {
  const BACKUP_PATH = `${ALLOWLIST_JSON}.test-backup`;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    __resetForTests();
    // Move allowlist.json para fora pra simular ambiente sem build.
    if (existsSync(ALLOWLIST_JSON)) {
      renameSync(ALLOWLIST_JSON, BACKUP_PATH);
    }
    // Silencia o warn esperado pra não poluir output dos testes.
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    // Restaura o JSON pros próximos testes — sem isso, suíte inteira quebra.
    if (existsSync(BACKUP_PATH)) {
      renameSync(BACKUP_PATH, ALLOWLIST_JSON);
    }
    __resetForTests();
    warnSpy.mockRestore();
  });

  it('returns null without throwing when allowlist.json is absent', () => {
    expect(() => matchTemplate('whatever command')).not.toThrow();
    const result = matchTemplate("sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo ''");
    expect(result.templateHash).toBeNull();
    expect(result.normalized).toBeTypeOf('string');
  });

  it('preserves normalized field even with missing allowlist', () => {
    const result = matchTemplate('sudo tail -n 50 /var/log/auth.log');
    expect(result.normalized).toBe('sudo tail -n %LINES% /var/log/auth.log');
  });
});

describe('matchTemplate — cache invalidation via __resetForTests', () => {
  const BACKUP_PATH = `${ALLOWLIST_JSON}.cache-test-backup`;

  afterEach(() => {
    // Garante restauração mesmo se o teste falhar no meio.
    if (existsSync(BACKUP_PATH)) {
      const original = readFileSync(BACKUP_PATH, 'utf-8');
      writeFileSync(ALLOWLIST_JSON, original, 'utf-8');
      renameSync(BACKUP_PATH, `${BACKUP_PATH}.delete-me`);
    }
    __resetForTests();
  });

  it('reloads allowlist after reset when file content changes', () => {
    __resetForTests();

    // 1. Estado inicial: allowlist tem o hash ufwLogs → match esperado.
    const original = readFileSync(ALLOWLIST_JSON, 'utf-8');
    writeFileSync(BACKUP_PATH, original, 'utf-8');

    const before = matchTemplate("sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo ''");
    expect(before.templateHash).toBe(ANCHOR_HASHES.ufwLogs);

    // 2. Reescreve allowlist com entries vazio.
    mkdirSync(dirname(ALLOWLIST_JSON), { recursive: true });
    writeFileSync(
      ALLOWLIST_JSON,
      JSON.stringify({ generatedAt: new Date().toISOString(), entries: [] }, null, 2),
      'utf-8',
    );

    // 3. Sem reset: cache ainda tem o hash → match continua.
    const cachedHit = matchTemplate("sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo ''");
    expect(cachedHit.templateHash).toBe(ANCHOR_HASHES.ufwLogs);

    // 4. Após reset: recarrega → não encontra mais.
    __resetForTests();
    const afterReset = matchTemplate(
      "sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo ''",
    );
    expect(afterReset.templateHash).toBeNull();

    // 5. Restaura allowlist original.
    writeFileSync(ALLOWLIST_JSON, original, 'utf-8');
    __resetForTests();
    const restored = matchTemplate(
      "sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo ''",
    );
    expect(restored.templateHash).toBe(ANCHOR_HASHES.ufwLogs);
  });
});
