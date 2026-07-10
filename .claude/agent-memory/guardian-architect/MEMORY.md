# Memória do guardian-architect

Última atualização: 2026-05-29

## Índice

- [Roadmap atual](roadmap.md) — fases Tier 0-4, status, datas
- [Decisões arquiteturais](decisions.md) — ADRs com data e justificativa
- [Auditorias pendentes](audits.md) — 26 achados (16 round 1 + 10 round 2)
- [Padrões do projeto](patterns.md) — convenções inegociáveis
- [Modelo de instalação](install-model.md) — guardian-shell aprovado
- [Versão atual em prod](deployment.md) — v3.1.0 desde 2026-05-29

## Estado atual (resumo)

- **Versão prod**: 3.1.1 (commit b23dc8f, tag v3.1.1, deploy 2026-05-31)
- **Deploy**: Hetzner, container `guardian` em `/root/.guardian`, postgres em container `guardian-db`
- **SSH alias**: `hetzner`
- **Última feature shipping**: noise reduction (4 layers) v3.1.0
- **Próximo grande passo**: modelo de instalação seguro (guardian-shell) — aguardando autorização do usuário

## Onde paramos (2026-05-29)

Usuário pediu pra criar sistema multi-agente pra acompanhar o roadmap. Sistema criado em `.claude/agents/`:
- `guardian-architect` (este) — orquestrador, opus, memory project
- `guardian-security-installer` — modelo de instalação, opus, memory project
- `guardian-docs-writer` — README + docs/, sonnet, memory project
- `guardian-code-reviewer` — read-only, opus, memory project

Próximo passo aguardando confirmação do usuário:
1. Implementar modelo de instalação seguro (Tier 0 da auditoria) — 6-8h
2. Atualizar README PT+EN com features faltantes
3. Criar portfolio docs/ com tutoriais de instalação, operação, arquitetura, avançado

## Como me usar

Quando o usuário perguntar:
- "onde estamos?" → leia `roadmap.md`
- "o que decidimos sobre X?" → leia `decisions.md`
- "qual o próximo passo?" → leia `roadmap.md` + status atual
- "o que falta na auditoria?" → leia `audits.md`

Quando o usuário tomar decisão nova: atualize o arquivo relevante imediatamente com data absoluta.
