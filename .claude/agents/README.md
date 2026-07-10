# Sistema de agentes do Guardian

Última atualização: 2026-05-29

Este diretório contém **4 agentes persistentes** que acompanham o desenvolvimento do Guardian. Cada agente tem:
- Um arquivo `.md` neste diretório (system prompt + frontmatter)
- Memória própria em `../agent-memory/<nome>/` (índice + arquivos de contexto)
- Escopo de responsabilidade claro

## Os 4 agentes

| Agente | Modelo | Cor | Memória | Tools | Função |
|--------|--------|-----|---------|-------|--------|
| `guardian-architect` | opus | cyan | sim | Read, Grep, Glob, Bash, TodoWrite, WebFetch | Orquestrador, mantém roadmap e ADRs |
| `guardian-security-installer` | opus | red | sim | + Write, Edit | Modelo de instalação seguro (guardian-shell) |
| `guardian-docs-writer` | sonnet | green | sim | + Write, Edit | README + docs/ em PT-BR e EN |
| `guardian-code-reviewer` | opus | yellow | sim | Read, Grep, Glob, Bash | Read-only review com checklist do projeto |

## Por que esse design

### Multi-agente em vez de um agente "faz-tudo"

- **Foco**: cada um tem prompt curto e específico, então respostas são mais precisas
- **Memória especializada**: o que o code-reviewer precisa lembrar (bugs recorrentes, padrões) é diferente do que o docs-writer precisa (estilo, glossário)
- **Modelos diferentes**: arquitetura precisa de opus pra raciocinar, docs precisam de sonnet pra escrever bem em escala

### Memória persistente (`memory: project`)

- Cada agente tem `.claude/agent-memory/<nome>/MEMORY.md` carregado **automaticamente** no início de cada invocação
- Agente atualiza a memória ao longo da conversa quando aprende algo novo
- Memória é **versionada no git** junto com o código — outro contributor abre o repo e tem o mesmo time de agentes

### `memory: project` vs `memory: user`

- `memory: project` (escolha aqui): no repo, vai com o checkout
- `memory: user` (não usado): em `~/.claude/`, fica no laptop do operador
- Para Guardian, projeto é o que importa — quem quer contribuir precisa do contexto

## Como invocar

Mencione o agente por nome:
- "@guardian-architect onde paramos no roadmap?"
- "@guardian-docs-writer atualiza o README com a feature de noise reduction"
- "@guardian-security-installer começa a implementar o Tier 0"
- "@guardian-code-reviewer revisa o diff atual"

Ou use auto-delegation: descreva o que precisa, Claude principal escolhe o agente certo se a `description` no frontmatter casar.

## Limitação importante

**Subagents NÃO podem invocar outros subagents.** Isso significa:
- O `guardian-architect` **não delega** pro security-installer; ele descreve o que precisa e VOCÊ (Claude principal) chama o próximo agente
- Você é o "agent zero" que orquestra
- Cada agente entrega um relatório/resultado, você decide o próximo passo

## Estrutura das memórias

```
.claude/agent-memory/
├── guardian-architect/
│   ├── MEMORY.md           ← índice (sempre carregado)
│   ├── roadmap.md          ← Tier 0–4 status
│   ├── decisions.md        ← ADRs com data
│   └── (futuros: audits.md, deployment.md, etc)
├── guardian-security-installer/
│   ├── MEMORY.md
│   ├── install-model-current.md
│   ├── install-model-approved.md
│   ├── allowlist.md
│   ├── os-quirks.md
│   └── incidents.md
├── guardian-docs-writer/
│   ├── MEMORY.md
│   ├── style-guide.md
│   ├── glossary-pt-en.md
│   ├── docs-status.md
│   └── features-to-document.md
└── guardian-code-reviewer/
    ├── MEMORY.md
    ├── patterns.md
    ├── recurring-bugs.md
    ├── false-positives.md
    └── tech-debt.md
```

## Convenção pra atualizar memória

- **MEMORY.md sempre <200 linhas** — Claude trunca após isso
- **Datas absolutas** ("2026-05-29"), nunca relativas ("ontem")
- **Frontmatter opcional** mas recomendado: `name`, `description`, `type`
- **Quando adicionar arquivo novo:** atualiza MEMORY.md do agente com link

## Quando criar agente novo

Considere se:
- Tem domínio claro e separado dos 4 atuais
- Vai ser invocado regularmente (não one-off)
- Memória persistente faz diferença

Não crie agente pra:
- Tarefa única (use Task tool com subagent genérico)
- Domínio que cabe em um dos 4 atuais
- Auxiliar ad-hoc do dia (use prompt direto)

## Quando aposentar agente

- Domínio virou irrelevante: mover memória pra `archive/` em vez de deletar
- Agente foi mesclado com outro: deletar `.md` mas preservar memória até próxima major

## Próximos passos pra evolução

Conforme Guardian crescer, candidatos a agentes futuros:
- `guardian-ml-trainer` — quando tiver mais modelos ONNX a manter
- `guardian-incident-responder` — agente que assiste em pós-mortem real de incidentes
- `guardian-perf-profiler` — quando o pipeline tiver issues de throughput

Mas só criar quando justificar.
