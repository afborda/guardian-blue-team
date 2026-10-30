#!/usr/bin/env bash
# Move regras "DENY from <ip>" do UFW para antes dos ACCEPT de porta.
#
# No hetzner-prod as primeiras regras são ACCEPT para 49222, 80 e 443.
# O `ufw deny from IP` acrescenta no fim, então o pacote para essas portas
# casa com o ACCEPT e a lista de 580 IPs não barra SSH nem o site.
# Portas já fechadas pela política padrão (deny incoming) continuam fechadas.
#
# Não apaga regras ALLOW nem DENY de porta (ex.: 5432). Só move
# "Anywhere DENY IN <ip>".
#
# Cada comando do ufw reescreve o ruleset. Com centenas de IPs isso leva
# bastante tempo. Por padrão só lista. Para aplicar:
#   APPLY=1 bash scripts/ufw-promote-denies.sh
#
# Conferir depois:
#   iptables -L ufw-user-input -n --line-numbers | head
#   ip6tables -L ufw6-user-input -n --line-numbers | head
# A primeira regra tem que ser DROP de um IP, não ACCEPT de porta.
set -euo pipefail

APPLY="${APPLY:-0}"

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw não está instalado" >&2
  exit 1
fi

mapfile -t RULES < <(ufw status numbered | sed -nE 's/^\[ *([0-9]+)\] +Anywhere( \(v6\))? +DENY IN +([^ #]+).*/\1 \3/p')

if [[ ${#RULES[@]} -eq 0 ]]; then
  echo "Nenhuma regra DENY de IP encontrada."
  exit 0
fi

echo "Regras DENY de IP: ${#RULES[@]}"
if [[ "$APPLY" != "1" ]]; then
  printf '%s\n' "${RULES[@]}" | head -20
  echo "Dry-run. Nada foi alterado. Para aplicar: APPLY=1 bash $0"
  exit 0
fi

IPS=()
# Apaga do maior número para o menor, para o índice não andar.
for ((i = ${#RULES[@]} - 1; i >= 0; i--)); do
  num="${RULES[$i]%% *}"
  ip="${RULES[$i]#* }"
  IPS+=("$ip")
  ufw --force delete "$num"
done

for ((i = ${#IPS[@]} - 1; i >= 0; i--)); do
  ufw insert 1 deny from "${IPS[$i]}" to any comment "guardian-promoted"
done

echo "Pronto. Confira as primeiras regras de ufw-user-input e ufw6-user-input."
