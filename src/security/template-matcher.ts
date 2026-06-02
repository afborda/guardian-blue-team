/**
 * template-matcher — runtime decisor de "este comando bate em algum template do allowlist?".
 *
 * Carrega lazy `dist/security/allowlist.json` (gerado por scripts/generate-allowlist.ts),
 * normaliza o comando candidato, hasheia, retorna o hash do template ou `null`.
 *
 * Uso típico em SSHCollector:
 *   const m = matchTemplate(cmd);
 *   if (target.installMode === 'guardian' && !m.templateHash) {
 *     logger.warn(...); return { success: false, error: 'GUARDIAN_NO_TEMPLATE' };
 *   }
 *
 * Se o JSON não existe (ex: rodar `npm run dev` antes de `npm run build`), retorna
 * sempre null + emite warn uma única vez. Isso evita crash no startup mas permite
 * que o operador detecte o problema imediatamente nos logs.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { logger } from '../utils/logger.js';
import { normalize } from './normalize.js';

export interface TemplateMatch {
  /** SHA256 do template canônico se houve match, senão null. */
  templateHash: string | null;
  /** Sempre presente: o resultado de normalize(cmd). Útil pra logging em skip-warning. */
  normalized: string;
}

const __dirname = dirname(fileURLToPath(import.meta.url));

// Resolução do allowlist.json: tenta `dist/security/allowlist.json` primeiro
// (caminho do build); fallback `<repo>/dist/security/allowlist.json` rodando
// de src/. ESM + tsx tornam isso meio chato — caminho absoluto é mais robusto.
function resolveAllowlistPath(): string {
  // tsup bundle: chunk lives at dist/chunk-*.js → dist/security/allowlist.json
  const fromBundle = resolve(__dirname, 'security/allowlist.json');
  if (existsSync(fromBundle)) return fromBundle;
  // src/security/template-matcher.ts (tsx dev) → dist/security/allowlist.json
  const fromSrc = resolve(__dirname, '../../dist/security/allowlist.json');
  if (existsSync(fromSrc)) return fromSrc;
  // dist/security/template-matcher.js sibling path (unused in tsup but kept for safety)
  const fromDist = resolve(__dirname, '../security/allowlist.json');
  if (existsSync(fromDist)) return fromDist;
  return fromBundle;
}

interface AllowlistJson {
  generatedAt: string;
  entries: Array<{ hash: string; template: string }>;
}

let cachedHashes: Set<string> | null = null;
let warnedMissing = false;

/**
 * Carrega o set de hashes válidos. Chamada lazy + cacheada.
 * Retorna conjunto vazio (e loga warn uma vez) se o arquivo não existe.
 */
function loadHashes(): Set<string> {
  if (cachedHashes) return cachedHashes;

  const path = resolveAllowlistPath();
  if (!existsSync(path)) {
    if (!warnedMissing) {
      logger.warn(
        { path },
        'template-matcher: dist/security/allowlist.json missing — run `npx tsx scripts/generate-allowlist.ts`. All commands will be treated as non-templatable in guardian mode.',
      );
      warnedMissing = true;
    }
    cachedHashes = new Set();
    return cachedHashes;
  }

  try {
    const raw = readFileSync(path, 'utf-8');
    const json = JSON.parse(raw) as AllowlistJson;
    cachedHashes = new Set(json.entries.map((e) => e.hash));
    logger.debug(
      { path, count: cachedHashes.size, generatedAt: json.generatedAt },
      'template-matcher: allowlist loaded',
    );
  } catch (err) {
    logger.error({ path, err }, 'template-matcher: failed to parse allowlist.json');
    cachedHashes = new Set();
  }
  return cachedHashes;
}

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/**
 * Normaliza `cmd`, hasheia, checa contra o allowlist. Retorna `{ templateHash, normalized }`.
 * `templateHash === null` significa "não bate em nenhum template conhecido".
 */
export function matchTemplate(cmd: string): TemplateMatch {
  const normalized = normalize(cmd);
  const hash = sha256(normalized);
  const hashes = loadHashes();
  return {
    templateHash: hashes.has(hash) ? hash : null,
    normalized,
  };
}

/**
 * Reset interno. SOMENTE pra testes — nunca chamar em runtime.
 * @internal
 */
export function __resetForTests(): void {
  cachedHashes = null;
  warnedMissing = false;
}
