# Guardian Tier 0 — PoC v2 Runbook

> **Objetivo**: validar Opção 3 (hash-allowlist + per-placeholder regex) com 3 collectors representativos antes de prosseguir para PR4 (`ServerUpgradeService`).
>
> **Data alvo**: 2026-05-31 / 2026-06-01
> **Servidor de teste**: ovh-spark (54.36.100.35)

---

## Pré-condições

- [x] PR1 mergeado (schema soc_servers + collector_state)
- [x] `src/security/guardian-shell.sh` v2 escrito (hash + regex)
- [x] `src/security/allowed-commands.txt` v2 com 4 templates âncora
- [x] `scripts/poc-v2/build-poc-shell.sh` gera shell pronto pra deploy
- [x] `scripts/poc-v2/test-poc.sh` valida ALLOWED + DENIED scenarios
- [ ] Acesso SSH a ovh-spark via alias `ovh-spark` (já configurado)
- [ ] Bash 4+ no servidor de teste (Ubuntu 22.04+ tem 5.x — ok)

---

## Etapa 1 — Build local

```bash
cd /Users/I776289/Documents/study/guardian
bash scripts/poc-v2/build-poc-shell.sh
```

Deve produzir:
- `src/security/guardian-shell-poc.sh` (~162 linhas, executável)
- `scripts/poc-v2/poc-templates.txt` (audit log: 4 hashes × 4 templates)

Verificar que sintaxe bash passa:
```bash
bash -n src/security/guardian-shell-poc.sh && echo OK
```

## Etapa 2 — Deploy em ovh-spark

> ⚠️ **Importante**: o PoC NÃO substitui o login shell do usuário ubuntu. Apenas instala o wrapper em `/tmp` e roda como executável standalone. Não há risco de lockout.

```bash
scp src/security/guardian-shell-poc.sh ovh-spark:/tmp/guardian-shell-poc.sh
scp scripts/poc-v2/test-poc.sh        ovh-spark:/tmp/test-poc.sh
ssh ovh-spark 'mkdir -p /tmp/poc-v2 && mv /tmp/guardian-shell-poc.sh /tmp/poc-v2/ && mv /tmp/test-poc.sh /tmp/poc-v2/ && chmod +x /tmp/poc-v2/*.sh'
```

## Etapa 3 — Adaptar test-poc.sh para apontar pro shell em /tmp

O script de teste no formato atual procura o wrapper em `$ROOT/src/security/`. Em ovh-spark precisa apontar pro path remoto:

```bash
ssh ovh-spark "sed -i 's|ROOT=.*|ROOT=/tmp/poc-v2|' /tmp/poc-v2/test-poc.sh && \
                sed -i 's|SHELL_BIN=.*|SHELL_BIN=/tmp/poc-v2/guardian-shell-poc.sh|' /tmp/poc-v2/test-poc.sh"
```

## Etapa 4 — Rodar testes

```bash
ssh ovh-spark bash /tmp/poc-v2/test-poc.sh
```

### Resultado esperado

```
=== ALLOWED tests (real collector commands → must hash-match) ===

  ✅ log-collector authLogs (5min ago, tail 100)              (exit=0)
  ✅ log-collector ufwLogs (tail 200)                          (exit=0)
  ✅ sudo-collector (15 min ago, tail 100)                     (exit=0)
  ✅ system-collector (tail 30, 5 min, tail 20)                (exit=0)

=== DENIED tests (must reject) ===

  ✅ interactive shell (empty CMD)                             (exit=126)
  ✅ command injection via semicolon                           (exit=126)
  ✅ command substitution via backticks                        (exit=126)
  ✅ command substitution via dollar-paren                     (exit=126)
  ✅ out-of-allowlist (cat /etc/shadow)                        (exit=126)
  ✅ near-miss (tail -F instead of -n)                         (exit=126)
  ✅ LINES exceeds cap (99999)                                 (exit=126)
  ✅ MINUTES exceeds cap (5000)                                (exit=126)
  ✅ ISO_DATETIME malformed (year 99999)                       (exit=126)
  ✅ control char (NUL injection)                              (exit=126)

================================
PASS: 14 / 14
FAIL: 0 / 14
================================
```

## Etapa 5 — Validação manual via SSH ForcedCommand

> **Só rodar essa etapa se Etapa 4 passou 14/14.**

Esta etapa simula o uso real: ssh com `command="..."` em authorized_keys.

```bash
# 1. Adicionar wrapper como ForcedCommand temporário pra um KEY de teste:
ssh ovh-spark 'cat > /tmp/poc-v2/test-key.pub <<EOF
command="/tmp/poc-v2/guardian-shell-poc.sh",no-pty,no-X11-forwarding,no-agent-forwarding,no-port-forwarding ssh-ed25519 AAAAC3...test-key... guardian-poc-key
EOF'

# 2. Gerar par de chaves SOMENTE pra esse teste:
ssh-keygen -t ed25519 -N '' -f /tmp/guardian-poc-test-key -C guardian-poc

# 3. Anexar pubkey ao authorized_keys (com prefixo command="..."):
PUBKEY=$(cat /tmp/guardian-poc-test-key.pub)
ssh ovh-spark "echo 'command=\"/tmp/poc-v2/guardian-shell-poc.sh\",no-pty,no-X11-forwarding $PUBKEY' >> ~/.ssh/authorized_keys"

# 4. Conectar usando essa chave + comando válido:
ssh -i /tmp/guardian-poc-test-key ovh-spark "sudo tail -n 50 /var/log/ufw.log 2>/dev/null || echo ''"
# Esperado: stdout do tail (ou string vazia)

# 5. Conectar tentando shell interativo:
ssh -i /tmp/guardian-poc-test-key ovh-spark
# Esperado: imediatamente fechar com "guardian-shell: interactive_shell"

# 6. Tentar injection:
ssh -i /tmp/guardian-poc-test-key ovh-spark "tail -n 50 /var/log/auth.log; cat /etc/shadow"
# Esperado: "guardian-shell: hash_mismatch", exit 126

# 7. CLEANUP — remover linha do authorized_keys + chave temp:
ssh ovh-spark "sed -i '/guardian-poc/d' ~/.ssh/authorized_keys"
rm -f /tmp/guardian-poc-test-key /tmp/guardian-poc-test-key.pub
```

## Etapa 6 — Análise do log

```bash
ssh ovh-spark sudo cat /var/log/guardian-shell-test.log 2>/dev/null || \
ssh ovh-spark cat /tmp/guardian-shell-test.log
```

Espera-se ver:
- 4 linhas `ALLOWED` para os 4 templates âncora
- ≥10 linhas `DENIED_*` com diferentes razões (HASH_MISMATCH, PLACEHOLDER_INVALID, INTERACTIVE_SHELL, CONTROL_CHARS)
- Cada linha contém: timestamp, versão, status, src_ip, cmd quoted

## Critérios de saída — gate para PR4

| Critério | Requisito | Status |
|----------|-----------|--------|
| Etapa 4 passa | 14/14 | ⏳ pendente run |
| Etapa 5 (T1-T6) confirma comportamento real via SSH ForcedCommand | T1=stdout, T2-T6=exit 126 | ⏳ |
| Log estruturado no formato esperado | sim | ⏳ |
| Nenhum falso negativo (comando real do collector recusado) | 0 | ⏳ |
| Nenhum falso positivo (injection passou) | 0 | ⏳ |

**Se algum critério falha → não avançar para PR4. Investigar normalize() drift entre TS e bash.**

---

## Cleanup pós-PoC

Independente do resultado:

```bash
ssh ovh-spark "rm -rf /tmp/poc-v2 /tmp/guardian-shell-test.log"
ssh ovh-spark "sed -i '/guardian-poc/d' ~/.ssh/authorized_keys"
rm -f /tmp/guardian-poc-test-key*
```

## Próximo passo se PoC verde

1. Commit: `feat(security): Tier 0 PR2 — guardian-shell v2 + allowlist + PoC validated`
2. Atualizar `docs/GUARDIAN-TIER0-IMPLEMENTATION.md`: marcar PR2 como ✅, PR3 (PoC) como ✅
3. Iniciar PR4: `scripts/generate-allowlist.ts` em TypeScript (replica `normalize()` do bash em TS) + testes de paridade + integração em `ssh-collector.ts:buildArgs()` para usar wrapper quando `installMode === 'guardian'`
