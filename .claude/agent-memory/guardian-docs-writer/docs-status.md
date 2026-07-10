# Status dos arquivos de documentação

Última atualização: 2026-05-29

## Convenção

Status:
- ✅ existe e está atualizado
- 🟡 existe mas desatualizado
- ❌ não existe ainda
- ⏸️ planejado pra v2

Sincronização EN com PT:
- ✅ sincronizado
- 🟡 dessincronizado (PT mais novo)
- ❌ não traduzido

## README

| Arquivo | Status | Última verificação | Notas |
|---------|--------|---------------------|-------|
| `README.md` (PT) | 🟡 | 2026-05-29 | 13 features novas faltando — ver `features-to-document.md` |
| `README.en.md` ou `README.md` em inglês | ❌ | — | Não confirmado se existe |

## docs/pt/

| Arquivo | Status | Notas |
|---------|--------|-------|
| `00-introducao.md` | ❌ | |
| `instalacao/01-pre-requisitos.md` | ❌ | |
| `instalacao/02-primeira-instalacao.md` | ❌ | |
| `instalacao/03-variaveis-ambiente.md` | ❌ | |
| `instalacao/04-adicionar-servidor.md` | ❌ | Depende de Tier 0 estar implementado |
| `instalacao/05-telegram-setup.md` | ❌ | |
| `operacao/01-dashboard-tour.md` | ❌ | |
| `operacao/02-lendo-alertas.md` | ❌ | |
| `operacao/03-respondendo-incidente.md` | ❌ | |
| `operacao/04-bloqueios-manuais.md` | ❌ | |
| `operacao/05-comandos-telegram.md` | ❌ | |
| `operacao/06-relatorio-diario.md` | ❌ | |
| `arquitetura/01-visao-geral.md` | ❌ | |
| `arquitetura/02-pipeline-detalhado.md` | ❌ | |
| `arquitetura/03-workers.md` | ❌ | |
| `arquitetura/04-intelligence.md` | ❌ | |
| `arquitetura/05-ai-providers.md` | ❌ | |
| `arquitetura/06-database.md` | ❌ | |
| `arquitetura/07-noise-reduction.md` | ❌ | Feature recente, prioridade |
| `arquitetura/08-modelo-de-seguranca.md` | ❌ | Depende de Tier 0 |
| `avancado/01-criar-playbook.md` | ❌ | |
| `avancado/02-criar-notifier.md` | ❌ | |
| `avancado/03-detection-rules.md` | ❌ | |
| `avancado/04-treinar-ml.md` | ❌ | |
| `avancado/05-postgresql-prod.md` | ❌ | |
| `faq.md` | ❌ | |
| `troubleshooting.md` | ❌ | |

## docs/en/

Mesma lista, todos ❌.

## Estratégia de produção

Quando começar a escrever, ordem sugerida (do mais útil pro menos):
1. `00-introducao.md` — orienta o resto
2. `instalacao/02-primeira-instalacao.md` — prático, traz usuários novos
3. `instalacao/03-variaveis-ambiente.md` — tabela referência, alta utilidade
4. `operacao/01-dashboard-tour.md` — pessoa instala e quer ver funcionando
5. `arquitetura/01-visao-geral.md` — explica o "porquê é mágico kkkk"
6. `arquitetura/07-noise-reduction.md` — feature diferenciada
7. `operacao/02-lendo-alertas.md` + `03-respondendo-incidente.md`
8. Demais conforme demanda

## Quando este arquivo deve mudar

Toda vez que:
- Cria arquivo: muda ❌ → ✅ + data
- Edita arquivo: atualiza data e marca EN como 🟡 se aplicável
- Traduz: muda EN ❌ → ✅
- Feature deprecada: marca PT e EN com nota "DEPRECATED"
