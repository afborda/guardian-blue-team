#!/usr/bin/env bash
# PoC v2 — Build script.
#
# Lê src/security/allowed-commands.txt, extrai templates não-comentados,
# calcula SHA256 de cada um, e gera src/security/guardian-shell-poc.sh com
# bloco BEGIN_ALLOWLIST/END_ALLOWLIST populado.
#
# O resultado é um wrapper guardian-shell pronto para deploy em ovh-spark
# (sem dependência do scripts/generate-allowlist.ts ainda).
#
# Uso:
#   ./scripts/poc-v2/build-poc-shell.sh
#
# Output:
#   src/security/guardian-shell-poc.sh    (executável, hashes embedded)
#   scripts/poc-v2/poc-templates.txt      (auditoria — template + hash de cada linha)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ALLOWLIST="$ROOT/src/security/allowed-commands.txt"
TEMPLATE_SHELL="$ROOT/src/security/guardian-shell.sh"
OUT_SHELL="$ROOT/src/security/guardian-shell-poc.sh"
AUDIT="$ROOT/scripts/poc-v2/poc-templates.txt"

[[ -f "$ALLOWLIST" ]] || { echo "FATAL: $ALLOWLIST not found"; exit 1; }
[[ -f "$TEMPLATE_SHELL" ]] || { echo "FATAL: $TEMPLATE_SHELL not found"; exit 1; }

echo "# PoC v2 templates — built $(date -Iseconds)" > "$AUDIT"
echo "# format: <sha256>  <template>" >> "$AUDIT"
echo "" >> "$AUDIT"

# Coleta linhas não-comentadas, não-vazias do allowlist.
HASH_LINES=""
COUNT=0
while IFS= read -r line; do
  # skip blank lines & comments
  [[ -z "$line" ]] && continue
  case "$line" in \#*) continue;; esac

  HASH=$(printf '%s' "$line" | shasum -a 256 | cut -d' ' -f1)
  # Templates contêm aspas simples (em torno de %ISO_DATETIME%, %MINUTES%) e
  # aspas duplas (em torno de "---SSEP---"). Usamos aspas duplas no array
  # bash e escapamos APENAS:  $  `  "  \   (caracteres especiais dentro de "...").
  # Templates atuais não usam $ nem ` nem \ literais → só preciso escapar ".
  ESCAPED_LINE=${line//\"/\\\"}
  HASH_LINES="${HASH_LINES}HASHES[\"${HASH}\"]=\"${ESCAPED_LINE}\""$'\n'

  printf '%s  %s\n' "$HASH" "$line" >> "$AUDIT"
  COUNT=$((COUNT + 1))
done < "$ALLOWLIST"

echo "Collected $COUNT templates."

# Substitui o bloco BEGIN_ALLOWLIST/END_ALLOWLIST no template do guardian-shell.
# macOS awk não aceita string multi-linha via -v; usamos arquivo intermediário.
HASHES_FILE=$(mktemp -t guardian-poc-hashes.XXXXXX)
printf '%s' "$HASH_LINES" > "$HASHES_FILE"

awk -v hashes_file="$HASHES_FILE" '
  /^# BEGIN_ALLOWLIST$/ {
    print
    while ((getline ln < hashes_file) > 0) print ln
    close(hashes_file)
    skip = 1
    next
  }
  /^# END_ALLOWLIST$/ {
    skip = 0
    print
    next
  }
  !skip { print }
' "$TEMPLATE_SHELL" > "$OUT_SHELL"

rm -f "$HASHES_FILE"

chmod +x "$OUT_SHELL"

echo ""
echo "✅ Built: $OUT_SHELL ($(wc -l < "$OUT_SHELL") lines)"
echo "✅ Audit: $AUDIT"
echo ""
echo "Next: copy $OUT_SHELL to ovh-spark and run validation tests."
echo "      scp $OUT_SHELL ovh-spark:/tmp/guardian-shell-poc.sh"
echo "      ssh ovh-spark bash /tmp/guardian-shell-poc.sh   # interactive shell test (must DENY)"
