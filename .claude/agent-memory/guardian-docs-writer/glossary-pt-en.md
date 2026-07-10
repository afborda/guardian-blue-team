# Glossário PT/EN

Última atualização: 2026-05-29

## Convenção

| Português | English | Definição curta |
|-----------|---------|------------------|

## Conceitos centrais

| Português | English | Definição |
|-----------|---------|-----------|
| Pipeline de segurança | Security pipeline | Sequência: collectors → normalizer → detector → enricher → correlator → playbook |
| Coletor / *Collector* | Collector | Componente que busca dados (SSH, Docker events, webhook) |
| Normalizador | Normalizer | Converte log raw em `NormalizedEvent` |
| Detector | Detector | Aplica regras de detecção, gera `DetectedEvent` |
| Enriquecedor | Enricher | Adiciona threat intel + ML scoring |
| Correlacionador | Correlator | Agrupa eventos em incidentes |
| *Playbook* | Playbook | Sequência de ações automáticas |
| Notificador / *Notifier* | Notifier | Plugin que envia alertas (Telegram, Discord, etc) |
| Trabalhador / *Worker* | Worker | Processo background |
| Camadas de redução de ruído | Noise reduction layers | 4 camadas que filtram alertas redundantes |
| Bloqueio | Block | Regra UFW/fail2ban que nega tráfego de um IP |
| Pontuação de ameaça | Threat score | Valor 0-100 calculado por ML/regras |

## ML / Intelligence

| Português | English | Definição |
|-----------|---------|-----------|
| Classificador DGA | DGA classifier | ONNX que detecta domínios gerados algoritmicamente |
| Cadeia de Markov | Markov chain | Modelo probabilístico de transições de comando sudo por usuário |
| Decomposição STL | STL decomposition | Tendência + sazonalidade + resíduo em séries temporais |
| Perfil de comportamento | Behavior profile | Estatísticas baseline por usuário/container |
| Embedding de incidente | Incident embedding | Vetor `bge-m3` pra busca semântica em RAG |
| Caçador de ameaças | Threat hunter | Worker proativo que pede análise IA periódica |

## AI / RAG

| Português | English | Definição |
|-----------|---------|-----------|
| Cascata multi-provider | Multi-provider cascade | Ollama → Gemini → OpenAI → Claude com fallback |
| Memória de incidentes | Incident memory | Tabela vetorizada usada como RAG pra LLM |
| Estratégia local-first | Local-first strategy | Tentar Ollama antes de APIs externas |
| Análise contextual | Contextual analysis | LLM recebe top-K incidentes similares como contexto |

## Operação

| Português | English | Definição |
|-----------|---------|-----------|
| Servidor monitorado | Monitored server | Máquina que Guardian acessa via SSH read-only |
| Servidor SOC | SOC server | Sinônimo, é a coluna `soc_servers` na DB |
| Incidente | Incident | Grupo de eventos correlacionados |
| Evento | Event | Linha de log normalizada |
| Severidade | Severity | low / medium / high / critical |
| Auto-bloqueio | Auto-block | Playbook bloqueia IP sem intervenção manual |
| Lista confiável | Allowlist / trusted list | IPs em `TRUSTED_IPS` env, exempt de regras |
| Token do dashboard | Dashboard token | String em `DASHBOARD_TOKEN` ou `DASHBOARD_USERS` |

## Infra

| Português | English | Definição |
|-----------|---------|-----------|
| Container Docker | Docker container | Unidade de execução; Guardian roda em container |
| Banco SQLite (dev) | SQLite database (dev) | Default sem `DATABASE_URL` |
| Banco PostgreSQL (prod) | PostgreSQL database (prod) | Recomendado em produção |
| View materializada | Materialized view | `user_command_transitions`, `user_command_thresholds` (PG only) |
| *Webhook* | Webhook | Endpoint HTTP que recebe push (Telegram, Falco) |
| *Heartbeat* | Heartbeat | Ping periódico que detecta silêncio |

## Segurança / Install

| Português | English | Definição |
|-----------|---------|-----------|
| *Allowlist* de comandos | Command allowlist | Regex permitidos no guardian-shell |
| Modelo de instalação | Install model | Como Guardian é instalado num servidor (legacy ou guardian-shell) |
| *Blast radius* | Blast radius | Tamanho do dano se Guardian for comprometido |
| Token de instalação | Install token | Token one-shot TTL 15min pra bootstrap |
| Fingerprint do host | Host fingerprint | Hash da chave pública SSH do servidor, pinned |
| *Append-only* log | Append-only log | Log com `chattr +a` que nem root edita |

## Vulnerabilidades / Threat Intel

| Português | English | Definição |
|-----------|---------|-----------|
| CVE | CVE | Common Vulnerabilities and Exposures (mantém em maiúsculas) |
| Score EPSS | EPSS score | Probabilidade de exploit (0-1) |
| CISA KEV | CISA KEV | Known Exploited Vulnerabilities catalog |
| Feed de inteligência | Threat intel feed | AbuseIPDB, VirusTotal, OSV.dev, EPSS, KEV |
| Reputação de IP | IP reputation | Score AbuseIPDB + cache local |

## Dashboard / UI

| Português | English | Definição |
|-----------|---------|-----------|
| Página inicial | Overview page | `/dashboard` raiz |
| Mapa de ataques | Attack map | Visualização geo de IPs maliciosos |
| Lista de servidores | Servers list | `/dashboard/servers` |
| Lista de incidentes | Incidents list | `/dashboard/incidents` |
| Lista de bloqueios | Blocks list | `/dashboard/blocks` |
| Modo escuro | Dark mode | Default no dashboard atual |

## Termos a evitar

- "Hacker" → use "atacante" / "attacker" (mais preciso, sem conotação ambígua)
- "Sistema" sozinho → seja específico: "o Guardian", "o servidor", "o container"
- "Notificação" pra qualquer coisa → diferencia "alerta" (Telegram) de "evento" (log) de "incidente" (correlato)

## Quando este arquivo deve mudar

- Termo novo aparece no código: adicione com tradução
- Usuário corrigiu tradução: atualize aqui (e nas docs já existentes)
- Termo deprecado (feature removida): mova pra seção "Histórico" no fim
