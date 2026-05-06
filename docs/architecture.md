# Arquitetura

Como Guardian funciona internamente — pipeline de dados, workers, e estrutura de pastas.

---

## Visao Geral

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Guardian Core                                │
│                                                                          │
│  ┌────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────┐  │
│  │ Collectors │───►│   Pipeline   │───►│ Intelligence │───►│Playbook│  │
│  │  (SSH)     │    │(Norm→Det→Enr)│    │  (ML + AI)   │    │ Engine │  │
│  └────────────┘    └──────────────┘    └──────────────┘    └────────┘  │
│        │                  │                    │                  │      │
│        ▼                  ▼                    ▼                  ▼      │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                         PostgreSQL                                  │ │
│  │  security_events │ server_metrics │ soc_incidents │ behavior_profiles│
│  └────────────────────────────────────────────────────────────────────┘ │
│        │                                                     │          │
│        ▼                                                     ▼          │
│  ┌──────────┐  ┌─────────┐  ┌───────┐  ┌──────┐  ┌───────────────┐   │
│  │ Telegram │  │ Discord │  │ Slack │  │ ntfy │  │ Dashboard     │   │
│  │   Bot    │  │         │  │       │  │      │  │ (HTMX/SSR)   │   │
│  └──────────┘  └─────────┘  └───────┘  └──────┘  └───────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
         ↕                                    ↕                    ↕
   [Telegram API]                     [SSH Targets]         [Ollama/Cloud AI]
    webhook+polling                   seus servidores        local-first
```

---

## Pipeline de Seguranca

Fluxo de um evento de seguranca do inicio ao fim:

```
SSH Logs do servidor
       │
       ▼
┌─────────────┐    auth.log, ufw.log, docker events, proc, dns...
│  Collector  │    Executa comandos SSH, retorna linhas brutas
└──────┬──────┘
       │ RawLogEntry[]
       ▼
┌─────────────┐    Identifica tipo de evento, extrai campos
│ Normalizer  │    (IP, usuario, porta, processo, etc.)
└──────┬──────┘
       │ NormalizedEvent[]
       ▼
┌─────────────┐    Aplica 15+ regras de deteccao
│  Detector   │    (brute force, mining, port scan, etc.)
└──────┬──────┘
       │ DetectedEvent[]
       ▼
┌─────────────┐    Threat intel (AbuseIPDB, VirusTotal)
│  Enricher   │    + ML behavioral scoring (SSH/container)
└──────┬──────┘
       │ EnrichedEvent[]
       ▼
┌─────────────┐    Agrupa eventos em incidentes
│ Correlator  │    (mesmo IP + mesma categoria = mesmo incidente)
└──────┬──────┘
       │ Incident
       ▼
┌─────────────┐    Executa playbook apropriado
│  Playbook   │    (block IP, kill process, alert, etc.)
│   Engine    │    Auto-learn: armazena resolucao no RAG
└──────┬──────┘
       │
       ▼
┌─────────────┐    Telegram, Discord, Slack, Email, ntfy, Webhook, WhatsApp
│  Notifiers  │
└─────────────┘
```

---

## Workers (Background Jobs)

| Worker | Intervalo | O que faz |
|--------|-----------|-----------|
| **Event Collector** | 2 min | Coleta logs de seguranca de todos os servidores |
| **Score Calculator** | 5 min (metricas) / 1h (scores) | Coleta CPU/mem/disk + calcula 6 scores |
| **Intelligence** | 1h | ML profiling (SSH + containers) + anomaly + trends |
| **FIM** | 4h | File integrity, cron jobs, SSH keys (baseline compare) |
| **CVE Monitor** | 6h | Varre pacotes vs OSV.dev |
| **Vuln Scanner** | 12h | Scan aprofundado de vulnerabilidades |
| **Daily Report** | 1x/dia (08:00 BRT) | Relatorio matinal via Telegram |
| **Block Cleanup** | 1h | Remove blocks expirados do UFW |
| **Metrics Retention** | 1x/dia | Limpa dados > 30 dias |

---

## Fluxo de Dados — De Onde Vem, Para Onde Vai

```
[Servidor Alvo via SSH]
    │
    ├──► security_events (tabela)     ──► Dashboard Logs, Incidents
    ├──► server_metrics (tabela)      ──► Dashboard Health, Scores
    ├──► behavior_profiles (tabela)   ──► ML scoring no Enricher
    └──► incident_memory (tabela)     ──► RAG context para AI

[Telegram API]
    │
    ├──► Comandos do usuario           ──► Respostas/acoes
    └──► Webhooks de callback          ──► Playbook approval/actions

[AI Provider (Ollama/Cloud)]
    │
    ├──► Analise de incidentes         ──► ai_summary em socIncidents
    ├──► Natural language queries      ──► Resposta via Telegram
    └──► CVE fix recommendations       ──► Telegram com botoes

[Threat Intel APIs]
    │
    ├──► AbuseIPDB                     ──► enrichment em securityEvents
    └──► VirusTotal                    ──► enrichment em securityEvents
```

---

## Estrutura de Pastas

```
src/
├── collectors/              # Coleta de dados via SSH (agentless)
│   ├── ssh-collector.ts         # Camada base — executa comandos SSH
│   ├── log-collector.ts         # auth.log, UFW, Docker events
│   ├── docker-collector.ts      # Container stats + anomalias
│   ├── health-collector.ts      # CPU, memoria, disco, uptime
│   ├── system-collector.ts      # Erros kernel, journal, units falhando
│   ├── performance-collector.ts # Disk I/O, network throughput
│   ├── process-collector.ts     # Processos suspeitos (mining, tmp exec)
│   ├── network-collector.ts     # Flood de conexoes
│   ├── fim-collector.ts         # File integrity (SHA256 baselines)
│   ├── sudo-collector.ts        # Auditoria de comandos sudo
│   ├── cron-collector.ts        # Enumeracao de cron jobs
│   ├── ssh-keys-collector.ts    # Auditoria de authorized_keys
│   └── dns-collector.ts         # Monitoramento de queries DNS
│
├── pipeline/                # Processamento de eventos
│   ├── normalizer.ts            # Logs brutos → eventos estruturados
│   ├── detector.ts              # Regras de deteccao (15+)
│   ├── enricher.ts              # Threat intel + ML scoring
│   ├── correlator.ts            # Eventos → Incidentes
│   ├── ingestor.ts              # Persistencia de eventos
│   ├── metrics-ingestor.ts      # Persistencia de metricas
│   └── score-calculator.ts      # Scoring 6 dimensoes
│
├── intelligence/            # ML + analise estatistica
│   ├── anomaly-detector.ts      # Z-score (desvio da baseline 7 dias)
│   ├── trend-predictor.ts       # Regressao linear (previsao de esgotamento)
│   ├── ssh-behavior.ts          # Perfis comportamentais por usuario SSH
│   ├── container-behavior.ts    # Perfis comportamentais por container
│   ├── root-cause.ts            # Analise de causa raiz (AI)
│   └── recommendations.ts      # Recomendacoes de otimizacao
│
├── services/                # Logica de negocio
│   ├── ai-provider.ts           # Multi-provider AI (local-first)
│   ├── server.service.ts        # CRUD de servidores
│   ├── soc-analyst.service.ts   # Consultas NL + analise RAG-augmented
│   └── incident-memory.service.ts # Memoria de incidentes (RAG)
│
├── workers/                 # Background jobs
│   ├── event-collector.worker.ts     # Seguranca (2min)
│   ├── fim.worker.ts                 # Integridade (4h)
│   ├── score-calculator.worker.ts    # Metricas (5min) + Scores (1h)
│   ├── intelligence.worker.ts        # ML + anomaly + trends (1h)
│   ├── metrics-retention.worker.ts   # Limpeza > 30d (diario)
│   ├── daily-report.worker.ts        # Relatorio matinal (08:00 BRT)
│   ├── block-cleanup.worker.ts       # Blocks expirados
│   ├── cve-monitor.worker.ts         # CVE scanning (6h)
│   └── vuln-scanner.worker.ts        # Vulnerability scan (12h)
│
├── playbooks/               # Engine de resposta automatica
│   ├── engine.ts                # Executor de playbooks (steps + conditions)
│   ├── definitions.ts           # 15 playbooks definidos
│   └── actions.ts               # Acoes atomicas (block IP, kill proc, etc.)
│
├── plugins/                 # Sistema de notificacao
│   ├── notifier-manager.ts      # Orquestrador (dispatch para canais ativos)
│   ├── telegram.plugin.ts       # Telegram
│   ├── discord.plugin.ts        # Discord
│   ├── slack.plugin.ts          # Slack
│   ├── email.plugin.ts          # Email (Resend)
│   ├── whatsapp.plugin.ts       # WhatsApp (Evolution API)
│   ├── ntfy.plugin.ts           # ntfy
│   └── webhook.plugin.ts        # Webhook customizado
│
├── telegram/                # Bot Telegram
│   ├── commands.ts              # 30+ comandos (/status, /block, etc.)
│   ├── callbacks.ts             # Botoes inline (aprovar, bloquear, etc.)
│   └── login-verification.ts   # Verificacao de logins suspeitos
│
├── dashboard/               # Dashboard web
│   ├── routes.ts                # Rotas (11 paginas + APIs)
│   └── views/                   # Templates HTML (layout + partials)
│
├── database/                # Schema e conexao
│   ├── connection.ts            # Drizzle ORM setup
│   └── guardian-schema.ts       # Tabelas PostgreSQL
│
├── config/                  # Configuracao
│   ├── environment.ts           # Validacao Zod das env vars
│   └── constants.ts             # Thresholds, patterns, timeouts
│
├── threat-intel/            # Integracoes de threat intelligence
│   ├── abuseipdb.ts             # AbuseIPDB API
│   └── virustotal.ts            # VirusTotal API
│
├── vuln-scanner/            # Scanner de vulnerabilidades
│   └── osv-scanner.ts           # Consulta OSV.dev
│
└── index.ts                 # Entry point — Express + worker orchestration
```

---

## Banco de Dados (PostgreSQL)

### Tabelas principais

| Tabela | O que armazena | Retencao |
|--------|---------------|----------|
| `security_events` | Eventos de seguranca normalizados | 30 dias |
| `server_metrics` | Metricas de infra (CPU, mem, disk, I/O) | 30 dias |
| `soc_incidents` | Incidentes correlacionados | Permanente |
| `server_scores` | Scores 6 dimensoes (horario) | 90 dias |
| `behavior_profiles` | Perfis ML (SSH, container) | Atualizado continuamente |
| `incident_memory` | Casos resolvidos para RAG | Permanente |
| `blocked_ips` | IPs bloqueados ativos | Ate expirar |
| `cve_alerts` | CVEs encontrados | Permanente |
| `playbook_executions` | Historico de playbooks | 90 dias |

### Espaco em disco estimado

| Cenario | security_events | server_metrics | Total estimado |
|---------|----------------|----------------|---------------|
| 1 servidor, pouco trafego | ~50MB/mes | ~20MB/mes | ~100MB/mes |
| 1 servidor, muito ataque | ~200MB/mes | ~20MB/mes | ~300MB/mes |
| 5 servidores | ~500MB/mes | ~100MB/mes | ~800MB/mes |
| Retencao 30d (limpeza automatica) | Max ~1GB | Max ~500MB | Max ~2GB |

---

## Docker Compose — Servicos

```
┌─────────────────────────────────────────────────────┐
│  docker compose                                      │
│                                                      │
│  ┌──────────┐  ┌────────────┐  ┌──────────────────┐│
│  │ guardian │  │ guardian-db│  │  ollama          ││
│  │ (Node.js)│  │(PostgreSQL)│  │  (AI local)      ││
│  │ 512MB    │  │  256MB     │  │  12GB max        ││
│  └──────────┘  └────────────┘  └──────────────────┘│
│                                  ┌──────────────────┐│
│                                  │  ollama-pull     ││
│                                  │  (one-shot)      ││
│                                  └──────────────────┘│
│                                                      │
│  Network: guardian-internal (bridge)                 │
│  Network: traefik-public (external, para HTTPS)     │
└─────────────────────────────────────────────────────┘
```

| Servico | Imagem | RAM limit | Funcao |
|---------|--------|-----------|--------|
| guardian | build local | 512MB | App principal |
| guardian-db | postgres:16-alpine | 256MB | Banco de dados |
| ollama | ollama/ollama:latest | 12GB | AI local |
| ollama-pull | ollama/ollama:latest | — | Baixa modelos (exit apos) |
