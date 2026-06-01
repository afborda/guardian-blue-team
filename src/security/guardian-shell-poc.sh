#!/usr/bin/env bash
# /usr/local/bin/guardian-shell — Tier 0 v2 (hash-allowlist + per-placeholder regex)
#
# Modelo (Opção 3, decidido em 2026-05-31 após PoC v1 falhar com 80% dos collectors):
#   1. Recebe $SSH_ORIGINAL_COMMAND quando ssh roda com command="..." em authorized_keys
#   2. Normaliza: substitui valores variáveis (timestamps, contadores, IDs) por placeholders fixos
#   3. SHA256 do template normalizado → compara contra HASHES embedded
#   4. Se hash bate, valida cada placeholder com regex específico (defesa contra injeção mascarada)
#   5. Se tudo OK → executa via `bash -c` com env limpo
#   6. Caso contrário → exit 126 + log estruturado em /var/log/guardian-shell.log
#
# IMPORTANTE: a rotina de normalização (`normalize()`) deve ser BIT-IDÊNTICA à versão
# TypeScript em scripts/generate-allowlist.ts. Qualquer divergência faz hash não bater.
# Existem testes de paridade em tests/security/normalize.test.ts.

set -euo pipefail

LOGFILE=/var/log/guardian-shell.log
VERSION=2.0.0

CMD="${SSH_ORIGINAL_COMMAND:-}"
TS=$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S%z)
SRC_IP="${SSH_CLIENT%% *}"
SRC_IP="${SRC_IP:-unknown}"

# Limites duros pra placeholders numéricos (defesa contra abuso recursos no servidor)
MAX_LINES=10000
MAX_MINUTES=1440      # 24h
MAX_UNIX_TS_AGE=2678400   # 31 dias — janela aceitável de --since timestamp

log() {
  local status=$1
  local detail=${2:-}
  printf '%s v%s %s src=%s cmd=%q %s\n' \
    "$TS" "$VERSION" "$status" "$SRC_IP" "$CMD" "$detail" >> "$LOGFILE" 2>/dev/null || true
}

deny() {
  local reason=$1
  local detail=${2:-}
  log "DENIED_${reason}" "$detail"
  echo "guardian-shell: ${reason,,}" >&2
  exit 126
}

# ── Allowlist embedded ────────────────────────────────────────────────────────
# Gerada por scripts/generate-allowlist.ts a partir do AST dos collectors em
# src/collectors/*.ts. A linha BEGIN_ALLOWLIST/END_ALLOWLIST é marker pro generator
# substituir o conteúdo. NÃO edite à mão — regenera no CI.
#
# Formato: declare -A com hash → template (template só pra log de debug; a comparação é por hash).
declare -A HASHES
# BEGIN_ALLOWLIST
HASHES["3c0682b6dc926a36abbeb9ce6c952a6e25cbc8caf1e53f592ce01b8ea1a2192a"]="sudo journalctl -u ssh -u sshd --since '%ISO_DATETIME%' --no-pager -o short-iso 2>/dev/null || sudo tail -n %LINES% /var/log/auth.log 2>/dev/null || echo ''"
HASHES["5cc6be2d9667d93f6577cdad6a53a72bcff6b6eac300e7e0685512bdeaff5d32"]="sudo tail -n %LINES% /var/log/ufw.log 2>/dev/null || echo ''"
HASHES["16044b22d56ed3c05d6fc832b23c727471e95b6823533a8836e301616ca87917"]="journalctl _COMM=sudo --since '%MINUTES% min ago' --no-pager -o short-iso 2>/dev/null || grep -i sudo /var/log/auth.log | tail -n %LINES%"
HASHES["f5bd58b5caf3f4c46fed1245a7ba2ad30cc43aebf81e79c3e9451eb65a586ca1"]="dmesg --time-format iso 2>/dev/null | tail -n %LINES% && echo \"---SSEP---\" && journalctl -p err --since \"%MINUTES% min ago\" --no-pager -o short-iso 2>/dev/null | tail -n %LINES% && echo \"---SSEP---\" && systemctl list-units --failed --no-legend --no-pager 2>/dev/null"
# END_ALLOWLIST

# ── Recusa precoce ────────────────────────────────────────────────────────────
[[ -z "$CMD" ]] && deny "INTERACTIVE_SHELL"

# Bloqueia caracteres de controle (NUL, etc) que poderiam confundir parser bash
case "$CMD" in
  *$'\x00'*|*$'\x01'*|*$'\x02'*|*$'\x03'*|*$'\x04'*|*$'\x05'*|*$'\x06'*|*$'\x07'*) deny "CONTROL_CHARS";;
esac

# ── Normalização ──────────────────────────────────────────────────────────────
# Cada substituição corresponde a um placeholder. Ordem importa (placeholders mais
# específicos primeiro, pra não serem engolidos pelos genéricos).
#
# Mantenha sincronizado com scripts/generate-allowlist.ts:normalize().
normalize() {
  local s=$1
  # %ISO_DATETIME% — '2025-01-15 10:00:00' / "2025-01-15T10:00:00Z" / "2025-01-15T10:00:00+0200"
  s=$(printf '%s' "$s" | sed -E "s/['\"]?[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:?[0-9]{2}|Z)?['\"]?/'%ISO_DATETIME%'/g")
  # %UNIX_TS% — --since 1717174800 (10 dígitos, segundos desde epoch)
  s=$(printf '%s' "$s" | sed -E "s/--since [0-9]{10}/--since %UNIX_TS%/g")
  s=$(printf '%s' "$s" | sed -E "s/--until [0-9]{10}/--until %UNIX_TS%/g")
  # Capture do --until $(date +%s) — vira %UNIX_TS% após substituição em runtime;
  # mas como template estático nós escrevemos literal "$(date +%s)" no allowlist e
  # NÃO permitimos forma direta. Vide allowed-commands.txt para o canônico.
  # %MINUTES% — find -mmin -60 / "60 minutes ago"
  s=$(printf '%s' "$s" | sed -E "s/-mmin -[0-9]+/-mmin -%MINUTES%/g")
  s=$(printf '%s' "$s" | sed -E "s/['\"][0-9]+ minutes ago['\"]/'%MINUTES% minutes ago'/g")
  # %LINES% — tail -100 / tail -n 200 / docker logs --tail 50.
  # Importante preservar a forma do flag (-n vs nu): cada forma é hash diferente.
  s=$(printf '%s' "$s" | sed -E "s/(tail|--tail) -n [0-9]+/\1 -n %LINES%/g")
  s=$(printf '%s' "$s" | sed -E "s/(tail|--tail) -[0-9]+/\1 -%LINES%/g")
  s=$(printf '%s' "$s" | sed -E "s/(tail|--tail) [0-9]+/\1 %LINES%/g")
  s=$(printf '%s' "$s" | sed -E "s/last -F -n [0-9]+/last -F -n %LINES%/g")
  # %CONTAINER_ID% — hex de 12-64 chars (docker IDs full ou short)
  s=$(printf '%s' "$s" | sed -E "s/\b[0-9a-f]{12,64}\b/%CONTAINER_ID%/g")
  printf '%s' "$s"
}

TEMPLATE=$(normalize "$CMD")
TEMPLATE_HASH=$(printf '%s' "$TEMPLATE" | sha256sum | cut -d' ' -f1)

# ── Verifica hash ─────────────────────────────────────────────────────────────
if [[ -z "${HASHES[$TEMPLATE_HASH]:-}" ]]; then
  deny "HASH_MISMATCH" "template=${TEMPLATE} hash=${TEMPLATE_HASH}"
fi

# ── Per-placeholder validation ────────────────────────────────────────────────
# Garante que valores reais extraídos do CMD são do tipo declarado pelo template.
# Defesa contra ataques onde o atacante consegue gerar mesmo hash com lixo no lugar
# de placeholder (improvável com SHA256, mas barato adicionar).
validate_placeholders() {
  local cmd=$1

  # %ISO_DATETIME% — formato ISO8601
  local iso_re='^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:?[0-9]{2}|Z)?$'
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    [[ "$v" =~ $iso_re ]] || return 1
  done < <(printf '%s' "$cmd" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:?[0-9]{2}|Z)?" || true)

  # %UNIX_TS% — exatamente 10 dígitos, dentro da janela aceitável
  local now_ts
  now_ts=$(date +%s)
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    [[ "$v" =~ ^[0-9]{10}$ ]] || return 1
    local age=$((now_ts - v))
    (( age >= 0 && age <= MAX_UNIX_TS_AGE )) || return 1
  done < <(printf '%s' "$cmd" | grep -oE "(--since|--until) [0-9]{10}" | grep -oE "[0-9]{10}" || true)

  # %MINUTES% — só dígitos, dentro de cap
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    [[ "$v" =~ ^[0-9]+$ ]] || return 1
    (( v <= MAX_MINUTES )) || return 1
  done < <(printf '%s' "$cmd" | grep -oE "(-mmin -|['\"])[0-9]+( minutes ago)?" | grep -oE "[0-9]+" || true)

  # %LINES% — só dígitos, dentro de cap
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    [[ "$v" =~ ^[0-9]+$ ]] || return 1
    (( v <= MAX_LINES )) || return 1
  done < <(printf '%s' "$cmd" | grep -oE "(tail|--tail) (-n |-)?[0-9]+|last -F -n [0-9]+" | grep -oE "[0-9]+$" || true)

  # %CONTAINER_ID% — só hex
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    [[ "$v" =~ ^[0-9a-f]{12,64}$ ]] || return 1
  done < <(printf '%s' "$cmd" | grep -oE "\b[0-9a-f]{12,64}\b" || true)

  return 0
}

if ! validate_placeholders "$CMD"; then
  deny "PLACEHOLDER_INVALID" "template=${TEMPLATE}"
fi

# ── Tudo OK — executa com env limpo ───────────────────────────────────────────
# `env -i` zera environment (LD_PRELOAD, BASH_ENV, IFS, etc); reseta PATH/LANG.
# Comando vai pra `bash -c` porque alguns templates usam `||` (OR-fallback) e
# pipes — o normalizador hasheou o template completo INCLUINDO esses operadores.
log "ALLOWED" "template=${TEMPLATE}"
exec env -i \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  LANG=C.UTF-8 \
  HOME="${HOME:-/home/guardian}" \
  bash -c "$CMD"
