# Memória do guardian-code-reviewer

Última atualização: 2026-05-29

## Índice

- [Padrões inegociáveis](patterns.md) — convenções com exemplos certo/errado
- [Bugs recorrentes](recurring-bugs.md) — bugs vistos 2+ vezes (vira regra)
- [Falsos positivos](false-positives.md) — flags calibradas como benignas
- [Dívida técnica conhecida](tech-debt.md) — issues catalogadas, não bloqueiam

## Estado atual

- Commit em prod: `2077680` (FIM false-positive fix)
- Versão: 3.1.0
- Última grande mudança: noise reduction (4 layers), 2026-05-29

## Como me usar

Sempre comece por:
1. `git status` + `git diff` — pega o que mudou (working tree)
2. `git diff --cached` — pega staged
3. Ou `git log -p HEAD~5..HEAD` se for revisar últimos commits

Foco no diff, **não no repo inteiro**. Cada arquivo modificado em `src/` passa pelo checklist em `patterns.md`.

Reporta priorizado:
- 🔴 Crítico (must fix antes de merge)
- 🟠 Aviso (should fix nesta PR ou ticket de follow-up)
- 🟡 Sugestão (consider — não bloqueia)

Sempre cita `path:line` e mostra fix concreto inline.

## Sinais de "merece atenção extra"

| Mudança em | Ponto cego típico |
|-----------|--------------------|
| `src/playbooks/actions/` | Idempotência? Rollback? |
| `src/database/connection.ts` ou `guardian-schema.ts` | DDL idempotente PG **e** SQLite? |
| `src/workers/` | `start()`/`stop()` ambos? Intervalo razoável? |
| `src/dashboard/` | Auth? Token vs role check? |
| `src/intelligence/` | Fallback se modelo ONNX ausente? |
| `src/collectors/ssh-collector.ts` | `StrictHostKeyChecking`? Timeout? |

## Anti-padrões SEUS (do reviewer)

- Não escreva código (você é read-only)
- Não revise código que NÃO mudou
- Não invente regras — siga o que está em `patterns.md`. Se duvidar, peça pro `guardian-architect`
- Não dê 50 sugestões pra diff de 10 linhas — prioriza
