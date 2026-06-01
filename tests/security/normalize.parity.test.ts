/**
 * Paridade byte-a-byte: TS normalize() === bash normalize() (sed-based).
 *
 * Estratégia: spawn `docker run --rm -v $repo:/work ubuntu:22.04` por teste,
 * roda extract-normalize.sh dentro do container, compara stdout com TS.
 *
 * Se Docker daemon não estiver rodando (típico em dev local macOS), o teste
 * faz skip com warn — em CI (GitHub Actions) Docker sempre está up.
 *
 * Por que não roda em macOS direto: BSD sed não suporta `\b` (word boundary).
 * Isso quebra a regex de %CONTAINER_ID%.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { normalize } from '../../src/security/normalize.js';

const REPO_ROOT = resolve(__dirname, '../..');

function isDockerAvailable(): boolean {
  try {
    execFileSync('docker', ['info'], { stdio: 'ignore', timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

function bashNormalize(cmd: string): string {
  const out = execFileSync(
    'docker',
    [
      'run', '--rm', '-i',
      '-v', `${REPO_ROOT}:/work:ro`,
      '-w', '/work',
      'ubuntu:22.04',
      'bash', 'src/security/extract-normalize.sh',
    ],
    {
      input: cmd,
      encoding: 'utf-8',
      timeout: 30_000,
    },
  );
  return out;
}

const dockerOk = isDockerAvailable();

describe.skipIf(!dockerOk)('normalize() bash↔TS parity (Docker)', () => {
  beforeAll(() => {
    // Pre-pull image once to avoid repeated 30s pulls per test
    try {
      execFileSync('docker', ['pull', 'ubuntu:22.04'], { stdio: 'ignore', timeout: 60_000 });
    } catch {
      // ignore — image may already exist
    }
  });

  // Cada caso: input bruto que um collector poderia produzir → template normalizado
  const cases: Array<[string, string]> = [
    // === ALLOWED — comandos reais dos 4 collectors âncora ===
    [
      "sudo journalctl -u ssh -u sshd --since '2026-05-31 12:00:00' --no-pager -o short-iso 2>/dev/null || sudo tail -n 100 /var/log/auth.log 2>/dev/null || echo ''",
      'log-collector authLogs (ISO + LINES)',
    ],
    [
      "sudo tail -n 200 /var/log/ufw.log 2>/dev/null || echo ''",
      'log-collector ufwLogs (LINES -n form)',
    ],
    [
      "sudo tail -200 /var/log/ufw.log 2>/dev/null || echo ''",
      'log-collector ufwLogs (LINES -N form, no -n)',
    ],
    [
      "journalctl _COMM=sudo --since '15 min ago' --no-pager -o short-iso 2>/dev/null || grep -i sudo /var/log/auth.log | tail -n 100",
      'sudo-collector (MINUTES + LINES)',
    ],
    [
      'dmesg --time-format iso 2>/dev/null | tail -n 30 && echo "---SSEP---" && journalctl -p err --since "5 min ago" --no-pager -o short-iso 2>/dev/null | tail -n 20 && echo "---SSEP---" && systemctl list-units --failed --no-legend --no-pager 2>/dev/null',
      'system-collector (chained && with mixed placeholders)',
    ],

    // === ISO_DATETIME variantes ===
    ["echo '2025-01-15 10:00:00'", 'ISO space form, single quotes'],
    ['echo "2025-01-15T10:00:00Z"', 'ISO T form with Z, double quotes'],
    ['echo "2025-01-15T10:00:00+0200"', 'ISO with +0200 offset'],
    ['echo "2025-01-15T10:00:00+02:00"', 'ISO with +02:00 colon offset'],
    ['echo 2025-01-15T10:00:00Z', 'ISO without quotes'],

    // === UNIX_TS ===
    ['docker events --since 1717174800 --until 1717261200', 'two unix timestamps'],
    ['journalctl --since 1717174800', 'unix ts since alone'],

    // === MINUTES variantes ===
    ['find / -mmin -60', 'find -mmin'],
    ["journalctl --since '15 minutes ago'", 'minutes ago single quote'],
    ['journalctl --since "15 minutes ago"', 'minutes ago double quote'],
    ['find / -mmin -1440', 'mmin upper bound'],

    // === LINES variantes (3 formas + last) ===
    ['tail -n 50 /var/log/auth.log', 'tail -n form'],
    ['tail -50 /var/log/auth.log', 'tail -N form'],
    ['tail 50', 'tail positional'],
    ['head -100 file', 'head NOT matched (only tail/--tail)'],
    ['docker logs --tail 30 container', 'docker logs --tail'],
    ['docker logs --tail -n 30 container', 'docker logs --tail -n'],
    ['last -F -n 25', 'last with -F -n'],

    // === CONTAINER_ID ===
    ['docker inspect abc123def4567', '13-char hex (just over min 12)'],
    ['docker inspect abc123def456', '12-char hex (exact min)'],
    ['docker inspect 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', '64-char hex (max)'],
    ['docker inspect abc12', '5-char hex (below min, NOT matched)'],
    ['docker inspect ABC123DEF456', 'uppercase hex (NOT matched, only [0-9a-f])'],

    // === Edge cases — não devem ser substituídos ===
    ['echo "no placeholder here"', 'plain string'],
    ['echo 12345', 'short number'],
    ['echo 2025', 'year-only'],
    ['echo 2025-01-15', 'date without time (NOT ISO)'],

    // === Combinações (múltiplos placeholders no mesmo comando) ===
    [
      "journalctl --since '2025-01-15 10:00:00' --until 1717261200 | tail -n 100 | grep abc123def456",
      'all placeholders together',
    ],

    // === Injection-shaped (devem normalizar mesmo, validação de placeholder rejeita depois) ===
    ['tail -n 100; cat /etc/shadow', 'tail with semicolon injection'],
    ['tail -n 100 || $(whoami)', 'command substitution syntax'],
    ['tail -n 100 `id`', 'backtick syntax'],

    // === Strings que parecem hex mas têm separadores ===
    ['echo abc-123-def', 'hex-like with dashes (NOT matched, dash breaks word)'],
    ['echo abc.123.def', 'hex-like with dots (NOT matched)'],
  ];

  it.each(cases)('parity for: %s [%s]', (input) => {
    const tsOutput = normalize(input);
    const bashOutput = bashNormalize(input);
    expect(tsOutput).toBe(bashOutput);
  });
});

describe('normalize() pure JS smoke (no Docker)', () => {
  it('normalizes ISO datetime with single quotes', () => {
    expect(normalize("'2025-01-15 10:00:00'")).toBe("'%ISO_DATETIME%'");
  });

  it('preserves the -n flag when normalizing tail', () => {
    expect(normalize('sudo tail -n 100 /var/log/auth.log')).toBe(
      'sudo tail -n %LINES% /var/log/auth.log',
    );
  });

  it('preserves the bare -N form when normalizing tail', () => {
    expect(normalize('sudo tail -100 /var/log/ufw.log')).toBe(
      'sudo tail -%LINES% /var/log/ufw.log',
    );
  });

  it('substitutes 12-char container hex but not 5-char', () => {
    expect(normalize('docker inspect abc123def456')).toBe('docker inspect %CONTAINER_ID%');
    expect(normalize('docker inspect abc12')).toBe('docker inspect abc12');
  });

  it('does not match uppercase hex (collectors lowercase docker IDs)', () => {
    expect(normalize('docker inspect ABCDEF123456')).toBe('docker inspect ABCDEF123456');
  });

  it('is idempotent — applying normalize twice gives same output', () => {
    const cmd = "sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo ''";
    const once = normalize(cmd);
    const twice = normalize(once);
    expect(twice).toBe(once);
  });
});
