/**
 * normalize() — port byte-paritário do bash em `guardian-shell.sh:70-92`.
 *
 * Regra crítica de segurança: a saída desta função TEM que ser idêntica
 * (byte-a-byte) à do shell em runtime, ou nenhum comando bate hash.
 * Testes de paridade em `tests/security/normalize.parity.test.ts` validam
 * isso contra a função bash extraída por `extract-normalize.sh`.
 *
 * Ordem das substituições importa — placeholders mais específicos primeiro,
 * pra não serem engolidos pelos genéricos (ex: %ISO_DATETIME% antes de
 * %CONTAINER_ID% porque '2025-01-15' começa com hex).
 *
 * Sed → JS: backreferences `\1` viram `$1`, `(...)` viram `(?:...)` quando
 * não usadas como capture, `[0-9]` continua igual ou pode usar `\d`, `\b`
 * ASCII-only é compatível.
 */
export function normalize(cmd: string): string {
  let s = cmd;

  // %ISO_DATETIME% — '2025-01-15 10:00:00' / "2025-01-15T10:00:00Z" / "2025-01-15T10:00:00+0200"
  // bash: s/['"]?[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:?[0-9]{2}|Z)?['"]?/'%ISO_DATETIME%'/g
  s = s.replace(
    /['"]?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?['"]?/g,
    "'%ISO_DATETIME%'",
  );

  // %UNIX_TS% — bash: --since/--until [0-9]{10}
  s = s.replace(/--since \d{10}/g, '--since %UNIX_TS%');
  s = s.replace(/--until \d{10}/g, '--until %UNIX_TS%');

  // %MINUTES% — bash: -mmin -N, 'N min ago' (singular usado pelos collectors), 'N minutes ago'
  // Ordem: singular antes do plural senão "minutes" engole o "min" do plural.
  s = s.replace(/-mmin -\d+/g, '-mmin -%MINUTES%');
  s = s.replace(/['"]\d+ minutes ago['"]/g, "'%MINUTES% minutes ago'");
  s = s.replace(/['"]\d+ min ago['"]/g, "'%MINUTES% min ago'");

  // %LINES% — bash: 4 formas (ordem importa, mais específica primeiro)
  s = s.replace(/(tail|--tail) -n \d+/g, '$1 -n %LINES%');
  s = s.replace(/(tail|--tail) -\d+/g, '$1 -%LINES%');
  s = s.replace(/(tail|--tail) \d+/g, '$1 %LINES%');
  s = s.replace(/last -F -n \d+/g, 'last -F -n %LINES%');

  // %CONTAINER_ID% — hex 12-64 chars
  s = s.replace(/\b[0-9a-f]{12,64}\b/g, '%CONTAINER_ID%');

  return s;
}
