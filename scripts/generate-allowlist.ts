/**
 * generate-allowlist.ts — gerador TS do allowlist embeddado em guardian-shell.sh.
 *
 * Substitui o bash legado `scripts/poc-v2/build-poc-shell.sh`. Lê
 * `src/security/allowed-commands.txt`, valida cada template (idempotência sob
 * normalize), computa SHA256, substitui o bloco BEGIN_ALLOWLIST/END_ALLOWLIST
 * em `src/security/guardian-shell.sh`, e emite `dist/security/allowlist.json`
 * para o template-matcher consumir em runtime.
 *
 * Uso:
 *   npx tsx scripts/generate-allowlist.ts        # build padrão
 *   npx tsx scripts/generate-allowlist.ts --check # exit 1 se arquivos drift do esperado
 *
 * O hash SHA256 é o mesmo que `shasum -a 256` produziria — `node:crypto`
 * usa o mesmo algoritmo OpenSSL canônico.
 */
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalize } from '../src/security/normalize.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');

const ALLOWLIST_TXT = resolve(REPO_ROOT, 'src/security/allowed-commands.txt');
const SHELL_PATH = resolve(REPO_ROOT, 'src/security/guardian-shell.sh');
const ALLOWLIST_JSON = resolve(REPO_ROOT, 'dist/security/allowlist.json');

const BEGIN_MARKER = '# BEGIN_ALLOWLIST';
const END_MARKER = '# END_ALLOWLIST';

interface AllowlistEntry {
  hash: string;
  template: string;
}

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function parseAllowlist(text: string): string[] {
  const templates: string[] = [];
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\r$/, '');
    if (!line.trim()) continue;
    if (line.startsWith('#')) continue;
    templates.push(line);
  }
  return templates;
}

function buildEntries(templates: string[]): AllowlistEntry[] {
  return templates.map((template, idx) => {
    // Sanity: cada template precisa ser idempotente sob normalize. Se aplicar
    // normalize() ao template e o output diferir, o template tem variável que
    // não está mascarada por placeholder — bug que o gerador detecta cedo.
    const normalized = normalize(template);
    if (normalized !== template) {
      throw new Error(
        `allowed-commands.txt:line${idx + 1} not idempotent under normalize().\n` +
          `  template:   ${template}\n` +
          `  normalized: ${normalized}\n` +
          `  fix: replace the variable substring with the appropriate %PLACEHOLDER%.`,
      );
    }
    return { hash: sha256(template), template };
  });
}

function renderHashesBlock(entries: AllowlistEntry[]): string {
  // Always use single-quote bash strings so $ in awk field refs are never expanded.
  // Single quotes inside the template are escaped via the bash idiom: ' → '\''
  const lines = entries.map((e) => {
    const escaped = e.template.replace(/'/g, "'\\''");
    return `HASHES["${e.hash}"]='${escaped}'`;
  });
  return lines.join('\n');
}

function replaceAllowlistBlock(shellSrc: string, hashesBlock: string): string {
  const beginIdx = shellSrc.indexOf(BEGIN_MARKER);
  const endIdx = shellSrc.indexOf(END_MARKER);
  if (beginIdx === -1 || endIdx === -1 || endIdx < beginIdx) {
    throw new Error(`markers ${BEGIN_MARKER}/${END_MARKER} not found in guardian-shell.sh`);
  }
  // Mantém o texto até e inclusive a linha BEGIN, substitui o conteúdo entre,
  // mantém a linha END em diante.
  const beforeEnd = shellSrc.indexOf('\n', beginIdx) + 1;
  const head = shellSrc.slice(0, beforeEnd);
  const tail = shellSrc.slice(endIdx);
  return `${head}${hashesBlock}\n${tail}`;
}

function main(): void {
  const checkMode = process.argv.includes('--check');

  const allowlistText = readFileSync(ALLOWLIST_TXT, 'utf-8');
  const templates = parseAllowlist(allowlistText);

  if (templates.length === 0) {
    throw new Error(`no templates parsed from ${ALLOWLIST_TXT}`);
  }

  const entries = buildEntries(templates);
  console.log(`[generate-allowlist] parsed ${entries.length} templates`);

  const shellSrc = readFileSync(SHELL_PATH, 'utf-8');
  const hashesBlock = renderHashesBlock(entries);
  const newShell = replaceAllowlistBlock(shellSrc, hashesBlock);

  if (checkMode) {
    if (newShell !== shellSrc) {
      console.error(
        '[generate-allowlist] DRIFT: guardian-shell.sh is stale. Run `npx tsx scripts/generate-allowlist.ts` to regenerate.',
      );
      process.exit(1);
    }
    console.log('[generate-allowlist] guardian-shell.sh in sync — OK');
  } else {
    if (newShell !== shellSrc) {
      writeFileSync(SHELL_PATH, newShell, 'utf-8');
      console.log(`[generate-allowlist] wrote ${SHELL_PATH}`);
    } else {
      console.log('[generate-allowlist] guardian-shell.sh already up to date');
    }
  }

  // Sempre emite o JSON em dist/ — runtime do template-matcher precisa.
  mkdirSync(dirname(ALLOWLIST_JSON), { recursive: true });
  const json = {
    generatedAt: new Date().toISOString(),
    entries: entries.map((e) => ({ hash: e.hash, template: e.template })),
  };
  writeFileSync(ALLOWLIST_JSON, `${JSON.stringify(json, null, 2)}\n`, 'utf-8');
  console.log(`[generate-allowlist] wrote ${ALLOWLIST_JSON}`);

  console.log('[generate-allowlist] hashes:');
  for (const e of entries) {
    console.log(`  ${e.hash}  ${e.template.slice(0, 80)}${e.template.length > 80 ? '…' : ''}`);
  }
}

main();
