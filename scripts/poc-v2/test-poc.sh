#!/usr/bin/env bash
# PoC v2 — Test suite.
#
# Valida que:
#   1. Comandos REAIS (com timestamps/contadores reais que collectors gerariam) normalizam
#      para os templates do allowed-commands.txt e batem em hash → ALLOWED
#   2. Tentativas de command injection óbvias → DENIED
#   3. Comandos parecidos mas fora do allowlist → DENIED
#   4. Placeholders fora dos limites (LINES > 10000, MINUTES > 1440) → DENIED
#
# Roda LOCALMENTE (não precisa SSH em ovh-spark) — chama o wrapper como filho com
# SSH_ORIGINAL_COMMAND setado, intercepta exit code.
#
# Requer: bash 4+ (declare -A). Em macOS: brew install bash, executar com /opt/homebrew/bin/bash.

set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SHELL_BIN="$ROOT/src/security/guardian-shell-poc.sh"

[[ -x "$SHELL_BIN" ]] || { echo "FATAL: $SHELL_BIN not built — run build-poc-shell.sh first"; exit 1; }

# Bash 4+ check
if (( BASH_VERSINFO[0] < 4 )); then
  echo "FATAL: this script requires Bash 4+ (you have $BASH_VERSION)."
  echo "  macOS: brew install bash, then run with /opt/homebrew/bin/bash"
  echo "  Linux: should already be Bash 4+ or 5+"
  exit 1
fi

PASS=0
FAIL=0
TESTS=()

# Mock: redireciona log e bypassa o exec final pra não rodar comandos reais.
# Usamos um wrapper que sobrescreve LOGFILE e injeta um trap pra interceptar `exec`.
# Mais simples: cria cópia do shell com `exec` substituído por `echo EXEC_WOULD_RUN`.
TEST_SHELL=$(mktemp -t guardian-shell-test.XXXXXX.sh)
sed -e 's|^LOGFILE=.*|LOGFILE=/tmp/guardian-shell-test.log|' \
    -e 's|^exec env -i|echo EXEC_WOULD_RUN: env -i|' \
    -e 's|^  bash -c "\$CMD"|  bash -c "echo OK"|' \
    "$SHELL_BIN" > "$TEST_SHELL"
chmod +x "$TEST_SHELL"

run_test() {
  local name=$1
  local expected_exit=$2  # 0 = should ALLOW, 126 = should DENY
  local cmd=$3
  TESTS+=("$name")

  local actual_exit
  SSH_ORIGINAL_COMMAND="$cmd" SSH_CLIENT="10.0.0.1 22 22" bash "$TEST_SHELL" >/dev/null 2>&1
  actual_exit=$?

  if [[ "$actual_exit" == "$expected_exit" ]]; then
    printf '  ✅ %-60s (exit=%d)\n' "$name" "$actual_exit"
    PASS=$((PASS + 1))
  else
    printf '  ❌ %-60s (expected=%d actual=%d)\n' "$name" "$expected_exit" "$actual_exit"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== ALLOWED tests (real collector commands → must hash-match) ==="
echo ""

# T1: log-collector.ts:16 — comando real com timestamp ISO
NOW_ISO=$(date -u -d '5 minutes ago' '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -u -v-5M '+%Y-%m-%d %H:%M:%S')
run_test "log-collector authLogs (5min ago, tail 100)" 0 \
  "sudo journalctl -u ssh -u sshd --since '$NOW_ISO' --no-pager -o short-iso 2>/dev/null || sudo tail -n 100 /var/log/auth.log 2>/dev/null || echo ''"

# T2: log-collector.ts:36 — ufw com tail variável
run_test "log-collector ufwLogs (tail 200)" 0 \
  "sudo tail -n 200 /var/log/ufw.log 2>/dev/null || echo ''"

# T3: sudo-collector.ts:9 — minutes variável
run_test "sudo-collector (15 min ago, tail 100)" 0 \
  "journalctl _COMM=sudo --since '15 min ago' --no-pager -o short-iso 2>/dev/null || grep -i sudo /var/log/auth.log | tail -n 100"

# T4: system-collector.ts:15 — &&-chain estática
run_test "system-collector (tail 30, 5 min, tail 20)" 0 \
  'dmesg --time-format iso 2>/dev/null | tail -n 30 && echo "---SSEP---" && journalctl -p err --since "5 min ago" --no-pager -o short-iso 2>/dev/null | tail -n 20 && echo "---SSEP---" && systemctl list-units --failed --no-legend --no-pager 2>/dev/null'

echo ""
echo "=== DENIED tests (must reject) ==="
echo ""

# T5: shell interativo
run_test "interactive shell (empty CMD)" 126 ""

# T6: command injection óbvia (concatena comando arbitrário com ;)
run_test "command injection via semicolon" 126 \
  "sudo tail -n 100 /var/log/ufw.log; cat /etc/shadow"

# T7: backtick substitution
run_test "command substitution via backticks" 126 \
  'sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo `id`'

# T8: $() substitution
run_test "command substitution via dollar-paren" 126 \
  'sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo $(whoami)'

# T9: comando totalmente fora do allowlist
run_test "out-of-allowlist (cat /etc/shadow)" 126 \
  "cat /etc/shadow"

# T10: comando parecido mas com flag diferente
run_test "near-miss (tail -F instead of -n)" 126 \
  "sudo tail -F /var/log/ufw.log 2>/dev/null || echo ''"

# T11: %LINES% fora de limite (>10000)
run_test "LINES exceeds cap (99999)" 126 \
  "sudo tail -n 99999 /var/log/ufw.log 2>/dev/null || echo ''"

# T12: %MINUTES% fora de limite (>1440)
run_test "MINUTES exceeds cap (5000)" 126 \
  "journalctl _COMM=sudo --since '5000 min ago' --no-pager -o short-iso 2>/dev/null || grep -i sudo /var/log/auth.log | tail -n 100"

# T13: ISO_DATETIME malformada
run_test "ISO_DATETIME malformed (year 99999)" 126 \
  "sudo journalctl -u ssh -u sshd --since '99999-13-45 99:99:99' --no-pager -o short-iso 2>/dev/null || sudo tail -n 100 /var/log/auth.log 2>/dev/null || echo ''"

# T14: control char NUL no meio
run_test "control char (NUL injection)" 126 \
  $'sudo tail -n 100 /var/log/ufw.log\x00; rm -rf /'

# Cleanup
rm -f "$TEST_SHELL"

echo ""
echo "================================"
echo "PASS: $PASS / $((PASS + FAIL))"
echo "FAIL: $FAIL / $((PASS + FAIL))"
echo "================================"

(( FAIL == 0 )) || exit 1
