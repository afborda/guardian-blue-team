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
HASHES["3c0682b6dc926a36abbeb9ce6c952a6e25cbc8caf1e53f592ce01b8ea1a2192a"]='sudo journalctl -u ssh -u sshd --since '\''%ISO_DATETIME%'\'' --no-pager -o short-iso 2>/dev/null || sudo tail -n %LINES% /var/log/auth.log 2>/dev/null || echo '\'''\'''
HASHES["5cc6be2d9667d93f6577cdad6a53a72bcff6b6eac300e7e0685512bdeaff5d32"]='sudo tail -n %LINES% /var/log/ufw.log 2>/dev/null || echo '\'''\'''
HASHES["16044b22d56ed3c05d6fc832b23c727471e95b6823533a8836e301616ca87917"]='journalctl _COMM=sudo --since '\''%MINUTES% min ago'\'' --no-pager -o short-iso 2>/dev/null || grep -i sudo /var/log/auth.log | tail -n %LINES%'
HASHES["d42bfb226ac4341b351d69def69fc9cb97b81be06ce8882e4fabd246e9956b42"]='dmesg --time-format iso 2>/dev/null | tail -n %LINES% && echo "---SSEP---" && journalctl -p err --since '\''%MINUTES% min ago'\'' --no-pager -o short-iso 2>/dev/null | tail -n %LINES% && echo "---SSEP---" && systemctl list-units --failed --no-legend --no-pager 2>/dev/null'
HASHES["7d10fced96b38c84f90db07708f266e83da48ca763189eaed7fe1a00348385eb"]='echo ok'
HASHES["c90415568db828a7f2f1c2dc374bd25d6ed406b5cfbf20dd0a20ecebccc8316c"]='sudo ss -tlnp 2>/dev/null | tail -n +2 | awk '\''{print $4, $6}'\'''
HASHES["4c3958a131c5abbf7982b078dbf94e1fc6f83c998de9721fb516daa8dbbe1b2d"]='sudo ss -tnp state established 2>/dev/null | tail -n +2 | head -50 | awk '\''{print $4, $5, $6}'\'''
HASHES["41e63b3cffbf3c0e6fbf038d2a50f3d506e6d8cfd9be4613ae3e491234789b0b"]='ss -tn state syn-recv 2>/dev/null | tail -n +2 | awk '\''{print $5}'\'' | grep -oP '\''[\d.]+(?=:)'\'' | sort | uniq -c | sort -rn | head -10'
HASHES["0f96ff4886b8c2764c2f3e02da1cc042b8b3202e67c6487071f56112bbe02930"]='ausearch --start recent -m EXECVE,USER_AUTH,USER_ACCT --format text 2>/dev/null | tail -n %LINES% || journalctl _TRANSPORT=audit --since '\''%MINUTES% min ago'\'' --no-pager -o short-iso 2>/dev/null | tail -n %LINES%'
HASHES["a0417b4d93d9edcab8224db0f75582ff7eb204854409a8e90d3c2595603e62df"]='journalctl -u systemd-resolved --since '\''%MINUTES% min ago'\'' --no-pager 2>/dev/null | grep -i '\''query['\'' || grep -i '\''query'\'' /var/log/syslog 2>/dev/null | tail -n %LINES%'
HASHES["8dafdb3de65b94f35eb62a34d2ae6d4de01ee1837424483032bcb79117fdafde"]='journalctl --since '\''%MINUTES% min ago'\'' -p err..emerg --no-pager -o short-iso 2>/dev/null | head -n %LINES%'
HASHES["650a734558dcaee716dc069b485c46162f85f7989e624477a72c3f3b2e6ed33a"]='cat /proc/loadavg && echo "---HSEP---" && nproc && echo "---HSEP---" && free -b && echo "---HSEP---" && df --output=target,pcent,avail -x tmpfs -x devtmpfs 2>/dev/null || df -h && echo "---HSEP---" && cat /proc/uptime && echo "---HSEP---" && grep -E '\''SwapTotal|SwapFree'\'' /proc/meminfo'
HASHES["66f621aa9f94767c3d594278a6dd6c52762170e6c7b878f26a57cebb51f2d4dc"]='cat /proc/diskstats && echo "---PSEP---" && cat /proc/net/dev && echo "---PSEP---" && sleep 1 && echo "---PSEP---" && cat /proc/diskstats && echo "---PSEP---" && cat /proc/net/dev'
HASHES["8a20c696aed220dce9da9f429323171393f4b77c05f414e41151b2e8dc60bb0c"]='ps aux --sort=-%cpu 2>/dev/null | head -n %LINES% | tail -n +2 | awk '\''{print $2, $1, $3, $4, $11}'\'''
HASHES["a4fd34596b62eff78043ace84fc303baf1c7c920d5d23a662cecb15c849677d8"]='docker ps --format '\''{{.Image}}\t{{.Names}}'\'' 2>/dev/null && echo '\''---IMAGES---'\'' && docker images --format '\''{{.Repository}}\t{{.Tag}}\t{{.Digest}}\t{{.Size}}'\'' 2>/dev/null | head -50'
HASHES["c59e720167118c04d0f60b5d1729a4751e53dfe6adb3e7efc511de94208d12ef"]='which trivy 2>/dev/null'
HASHES["62641aeef36eb805dbaf9c3653977935c1f71a33e9a69e7da34f21eb9e343681"]='last -F -n %LINES% 2>/dev/null || last -n %LINES% 2>/dev/null || echo '\'''\'''
HASHES["d87c726dbeb373b699d9477fd9c638b5f06532a113a862f5e4ed92f9c2b09ed9"]='sudo lastb -F -n %LINES% 2>/dev/null || sudo lastb -n %LINES% 2>/dev/null || echo '\'''\'''
HASHES["fd379f9d2ea0539b56de943e732783700fa307f98468a7b80ea0376642a6cdf9"]='w -h 2>/dev/null || who 2>/dev/null || echo '\'''\'''
HASHES["d7c2495f259632850bbeb80f27a3cffbd4140f8bb0b2a98657ec71b8142d3029"]='grep '\''^VERSION='\'' /usr/local/bin/guardian-shell 2>/dev/null || echo '\''VERSION=unknown'\'''
HASHES["f77db98a8df1ec2b1e77a6efffda18db467fc039d0ec89f244029d4893f9372c"]='sudo tail -n %LINES% /var/log/nginx/access.log 2>/dev/null || echo '\'''\'''
HASHES["721d6694632ed70c30ec0780000a3139fc307996b434e7a4cad2c3536c712b9c"]='sudo tail -n %LINES% /var/log/nginx/error.log 2>/dev/null || echo '\'''\'''
HASHES["82a1f6dc95b675930447b1b7f17e3960acd5952ee6ac7a7d32770315b4195140"]='sudo journalctl -u mysql -u mysqld -n %LINES% --no-pager 2>/dev/null || sudo tail -n %LINES% /var/log/mysql/error.log 2>/dev/null || echo '\'''\'''
HASHES["410a814ecedf107c621676218bd5e5fb26068b5bccd69b9b1bb28d76233b2ef5"]='sudo journalctl -u postgresql -n %LINES% --no-pager 2>/dev/null || echo '\'''\'''
HASHES["1aba280c7103d22feeb80a63bf8adcde87548b06402c6d8a5eea35610e313718"]='sudo journalctl -u redis -u redis-server -n %LINES% --no-pager 2>/dev/null || sudo tail -n %LINES% /var/log/redis/redis-server.log 2>/dev/null || echo '\'''\'''
HASHES["61a33f3e9e9dbc7f962ed15de602e1d4553e9c8dfe81ebf0bc7164a6329ed5a2"]='which fail2ban-client'
HASHES["f4283e3adaba620d0dbf22a8382e5137e9326f110b1083a881cc5a48aea3afef"]='sudo fail2ban-client set guardian-jail banip --bantime -1 %IP%'
HASHES["867a4ff5ac11609419bbf9a56855ca4b4e2abb7f25533b5ed7f8d3ca65c02161"]='sudo ufw deny from %IP% comment '\''guardian-block-%CONTAINER_ID%'\'''
HASHES["8dfc8de8f11db185ebc5cf2affbbccd74e50e395a3596913d37d6b483f456dae"]='sudo ufw deny from %IP% comment '\''guardian-prop-%CONTAINER_ID%'\'''
HASHES["d5ce19cdf11cef11f0509d057fc9adc5094cac6390d748ef416b2c2754bb5f64"]='sudo ufw status | grep -q '\''%IP%'\'''
HASHES["70c93d2e0a80fabf5f836be3b42378b9dbf6e3be53e01e5f9600d1989abc7fa2"]='sudo fail2ban-client status guardian-jail 2>/dev/null | grep -q '\''%IP%'\'''
HASHES["04d90afa2e620320340b73cf7aac1706e0a31510dcff71ca27d41d1dad97e202"]='sudo ufw delete deny from %IP%'
HASHES["f78c1329acba2677341716a88bce17e1483d007dfd6016fb090fb6afe727f686"]='sudo fail2ban-client set guardian-jail unbanip %IP%'
HASHES["408aa5dee6c040d2d7395f663b3af7c897ae2a4fbd097a6a06ed9c42b939876b"]='sudo iptables -N GUARDIAN-INPUT 2>&1'
HASHES["9d0851da29c3b3f6fb6d1b414ab6222ef01683684071fdbf084680af269636c6"]='sudo iptables -C INPUT -j GUARDIAN-INPUT 2>/dev/null'
HASHES["8ace238828936adbaf08999120f3b61fb1773ed20028ff683f4e255ecb18f795"]='sudo iptables -I INPUT 1 -j GUARDIAN-INPUT'
HASHES["82ab5d49358493adf04db0cca5468b5c370f51d92d9af98b2b0b47e628ff1d0e"]='sudo iptables -A GUARDIAN-INPUT -s %IP% -j DROP'
HASHES["a7553556aadabeb586006f8fc53efba01d8d79e4215faa850d51a05aebf84017"]='sudo iptables -S GUARDIAN-INPUT 2>/dev/null | grep -q -- '\''-s %IP%/32'\'''
HASHES["0b9c0898fbc24ca15b72f9cf6f79a9a746b3a90d938a638c259760966c3c0cb6"]='sudo iptables -D GUARDIAN-INPUT -s %IP% -j DROP'
HASHES["e3fff8bcf665acbbb226799cbb80d8bf1a165cfbd626486a1b9ebbe2a141a64a"]='sudo iptables -I GUARDIAN-INPUT -s %IP% -m limit --limit %LINES%/sec --limit-burst %LINES% -j ACCEPT'
HASHES["82ab5d49358493adf04db0cca5468b5c370f51d92d9af98b2b0b47e628ff1d0e"]='sudo iptables -A GUARDIAN-INPUT -s %IP% -j DROP'
HASHES["0b9c0898fbc24ca15b72f9cf6f79a9a746b3a90d938a638c259760966c3c0cb6"]='sudo iptables -D GUARDIAN-INPUT -s %IP% -j DROP'
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
  # %MINUTES% — find -mmin -60 / "60 min ago" (singular) / "60 minutes ago"
  s=$(printf '%s' "$s" | sed -E "s/-mmin -[0-9]+/-mmin -%MINUTES%/g")
  s=$(printf '%s' "$s" | sed -E "s/['\"][0-9]+ minutes ago['\"]/'%MINUTES% minutes ago'/g")
  s=$(printf '%s' "$s" | sed -E "s/['\"][0-9]+ min ago['\"]/'%MINUTES% min ago'/g")
  # %LINES% — tail -100 / tail -n 200 / docker logs --tail 50.
  # Importante preservar a forma do flag (-n vs nu): cada forma é hash diferente.
  s=$(printf '%s' "$s" | sed -E "s/(tail|--tail) -n [0-9]+/\1 -n %LINES%/g")
  s=$(printf '%s' "$s" | sed -E "s/(tail|--tail) -[0-9]+/\1 -%LINES%/g")
  s=$(printf '%s' "$s" | sed -E "s/(tail|--tail) [0-9]+/\1 %LINES%/g")
  s=$(printf '%s' "$s" | sed -E "s/last -F -n [0-9]+/last -F -n %LINES%/g")
  # %CONTAINER_ID% — hex de 12-64 chars (docker IDs full ou short)
  s=$(printf '%s' "$s" | sed -E "s/\b[0-9a-f]{12,64}\b/%CONTAINER_ID%/g")
  # %IP% — endereço IPv4 com ou sem CIDR (ex: 1.2.3.4 ou 1.2.3.4/32)
  s=$(printf '%s' "$s" | sed -E "s/\b([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?\b/%IP%/g")
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
  done < <(printf '%s' "$cmd" | grep -oE "(-mmin -|['\"])[0-9]+( min(utes)? ago)?" | grep -oE "[0-9]+" || true)

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

  # %IP% — octetos válidos (0-255) com CIDR opcional (0-32)
  local ip_re='^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$'
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    [[ "$v" =~ $ip_re ]] || return 1
  done < <(printf '%s' "$cmd" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?\b" || true)

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
