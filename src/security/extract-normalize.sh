#!/usr/bin/env bash
# extract-normalize.sh — isola a função normalize() do guardian-shell.sh para testes de paridade.
#
# Uso (DENTRO de container Linux/Ubuntu): echo "comando" | bash src/security/extract-normalize.sh
#       → imprime o comando após normalização (sem newline final extra).
#
# Por que: tests/security/normalize.parity.test.ts spawn um container Ubuntu via
# `docker run --rm -v $(pwd):/work ubuntu:22.04 bash -c ...` e dentro dele chama este
# script. Compara saída byte-a-byte com normalize() em TS.
#
# Não roda em macOS host porque BSD sed não suporta `\b`. Use `docker run` ou um
# Linux box. Se quiser rodar local em macOS pra debug rápido, instale `brew install
# gnu-sed` e troque manualmente `sed -E` por `gsed -E` no guardian-shell.sh (NÃO
# commitar essa mudança — quebra produção).
#
# Implementação: extrai o bloco entre `normalize() {` e o `}` que fecha a função,
# anexa um stub que lê o arg e chama normalize(), executa via `bash -c`.
# A vantagem é que QUALQUER mudança no guardian-shell.sh propaga automaticamente
# pra cá — sem manter dois shells em sincronia manual.

set -euo pipefail

SHELL_SRC="$(dirname "$0")/guardian-shell.sh"
[[ -f "$SHELL_SRC" ]] || { echo "FATAL: $SHELL_SRC not found" >&2; exit 1; }

# Lê o input completo do stdin
INPUT=$(cat)

# Extrai a definição da função normalize() — do `normalize() {` até o primeiro `}` em coluna 0.
FN=$(awk '/^normalize\(\) \{/,/^\}/' "$SHELL_SRC")

[[ -n "$FN" ]] || { echo "FATAL: could not extract normalize() from $SHELL_SRC" >&2; exit 1; }

# Roda a função num sub-bash com o input. Usa printf '%s' pra evitar trailing newline
# que o `echo` adicionaria — paridade byte-a-byte exige preservação exata.
bash -c "$FN
printf '%s' \"\$(normalize \"\$1\")\"" _ "$INPUT"
