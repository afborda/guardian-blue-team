<p align="center">
  <img src="https://img.shields.io/badge/Guardian-Blue%20Team-0066cc?style=for-the-badge&logo=shield&logoColor=white" alt="Guardian Blue Team">
</p>

<h1 align="center">Guardian Blue Team</h1>

<p align="center">
  <strong>Lightweight SIEM/SOAR + Infrastructure Observability for the rest of us</strong>
</p>

<p align="center">
  <a href="#english">English</a> | <a href="#portugues">Portugues</a>
</p>

<p align="center">
  <a href="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml"><img src="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://ghcr.io/afborda/guardian-blue-team"><img src="https://img.shields.io/badge/Docker-ghcr.io-blue" alt="Docker"></a>
</p>

---

<a id="english"></a>

# English

Guardian is an agentless SIEM/SOAR that monitors your servers via SSH, detects threats in real-time, computes infrastructure health scores, predicts resource exhaustion, and responds automatically. Built for solo operators, small startups, and homelabbers who want enterprise-grade monitoring without enterprise complexity.

## Why Guardian?

| Feature | Fail2ban | CrowdSec | Wazuh | **Guardian** |
|---------|----------|----------|-------|--------------|
| Setup time | 5 min | 30 min | 2+ hours | **30 seconds** |
| Install on targets | Yes | Yes | Yes | **No (agentless SSH)** |
| Response actions | Block IP | Block IP | Scripts | **Playbooks + approval** |
| Notifications | Email | — | Email | **7 channels** |
| CVE monitoring | — | — | Yes | **Yes (OSV.dev + AI fix)** |
| Health scoring | — | — | — | **6 dimensions** |
| Anomaly detection | — | — | — | **Statistical baseline** |
| Trend prediction | — | — | — | **Linear regression** |
| AI analysis | — | — | — | **4 providers** |
| Dashboard | — | Web | Web | **HTMX (lightweight)** |
| Mobile-first | — | — | — | **Telegram/WhatsApp** |
| Resource usage | Minimal | Low | High | **~50MB RAM** |

## Quick Start

```bash
# One-line Docker (SQLite, zero dependencies)
docker run -d --name guardian \
  -e TELEGRAM_BOT_TOKEN=your_token \
  -e TELEGRAM_CHAT_ID=your_chat_id \
  -v guardian_data:/data \
  -v ~/.ssh:/home/node/.ssh:ro \
  -p 3334:3334 \
  ghcr.io/afborda/guardian-blue-team:latest
```

Or use the interactive installer:

```bash
curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh | bash
```

The installer guides you through SSH key generation, environment configuration, AI provider selection, and first server setup with a beautiful terminal UI.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Guardian Core                                 │
├─────────────┬────────────┬─────────────┬─────────────┬───────────────┤
│  Collectors │  Pipeline  │ Intelligence│  Playbook   │   Dashboard   │
│  (SSH/proc) │(Bronze→Gold)│(Anomaly/AI) │   Engine    │  (HTMX/SSR)  │
├─────────────┴────────────┴─────────────┴─────────────┴───────────────┤
│                        Plugin System (7 notifiers)                     │
├────────┬─────────┬────────┬────────┬───────┬────────┬────────────────┤
│Telegram│ Discord │ Slack  │ Email  │ ntfy  │Webhook │  WhatsApp      │
└────────┴─────────┴────────┴────────┴───────┴────────┴────────────────┘
      ↕                    ↕                    ↕               ↕
 [Telegram Bot]     [PostgreSQL/SQLite]    [SSH Targets]   [AI Providers]
  commands+alerts     event storage        your servers    Gemini/GPT/Claude/Ollama
```

### Data Pipeline (Bronze → Silver → Gold)

```
Collectors (5min)          Pipeline                    Output
─────────────────          ────────                    ──────
Health  ─┐                 ┌─ Bronze ──────────────┐
System  ─┼─► SSH cmds ──► │ server_metrics (raw)  │──► Dashboard
Perf    ─┘                 └───────────────────────┘
                                    │
                           ┌─ Gold ─┴──────────────┐
                           │ server_scores (6 dim) │──► Telegram
                           └───────────────────────┘
                                    │
                           ┌─ Intelligence ────────┐
                           │ Anomaly + Trends + AI │──► Alerts
                           └───────────────────────┘
```

### Security Event Pipeline

```
SSH Logs → Normalize → Detect → Enrich → Correlate → Playbook → Notify
  (2min)     (parse)   (rules)  (intel)  (incidents)  (auto)    (7ch)
```

## Features

### Security Monitoring (SIEM/SOAR)

**Threat Detection (9 built-in rules):**
- SSH brute force (20+ failed attempts from same IP)
- Port scanning (5+ ports probed in 10 minutes)
- Crypto mining processes (xmrig, minerd, cpuminer, kdevtmpfsi, kinsing)
- Suspicious binaries (execution from /tmp, /dev/shm, hidden paths)
- Unauthorized logins (SSH from untrusted IPs/fingerprints)
- Password logins (flags when key-only auth should be enforced)
- Unusual hour logins (00:00-06:00 from non-trusted IPs)
- Lateral movement (SSH from IP that previously brute-forced)
- Container escape (5+ container deaths in 10 minutes)

**Automated Response (8 playbooks):**
- Block malicious IPs via UFW (auto or with human approval)
- Kill crypto mining processes
- Pause/disconnect compromised containers
- Enrich IPs with threat intelligence (AbuseIPDB, VirusTotal)
- Track repeat offenders across servers

**CVE Monitoring:**
- Scans installed packages (Debian, Alpine, npm) against OSV.dev
- AI-powered fix recommendations with risk assessment
- One-click patching via Telegram with human approval

### Infrastructure Observability

**Collectors (agentless, via SSH to /proc):**

| Collector | Data | Source |
|-----------|------|--------|
| Health | CPU load, memory, swap, disk usage, uptime | `/proc/loadavg`, `free`, `df`, `/proc/uptime` |
| System | Kernel errors, journal errors, failed systemd units | `dmesg`, `journalctl`, `systemctl` |
| Performance | Disk I/O (read/write Bps), Network I/O (rx/tx Bps) | `/proc/diskstats`, `/proc/net/dev` (delta sampling) |

**6-Dimension Server Scoring (0-100, penalty-based):**

| Score | Measures | Weight |
|-------|----------|--------|
| Health | CPU load ratio, memory %, disk %, swap % | 20% |
| Security | Open incidents, attack events, blocked IPs | 25% |
| Quality | Failed services, kernel errors, journal errors, uptime | 15% |
| Waste | Idle CPU, unused memory, idle resources | 10% |
| Vulnerability | Open CVEs (critical/high), days since last scan | 20% |
| Availability | Uptime, service restarts, container crashes | 10% |

**Overall Score** = weighted average of all 6 dimensions.

### AI Intelligence Layer

Works with 4 providers (configurable, with automatic fallback):

| Provider | Config | Use case |
|----------|--------|----------|
| Gemini | `GEMINI_API_KEY` | Free tier, fast, recommended |
| OpenAI | `OPENAI_API_KEY` | GPT-4o-mini for analysis |
| Claude | `ANTHROPIC_API_KEY` | Best reasoning |
| Ollama | `OLLAMA_URL` | Local, free, slower |

**Capabilities:**

| Feature | Requires API? | Description |
|---------|---------------|-------------|
| Anomaly Detection | No | Statistical baseline (mean + 2.5σ over 7 days) |
| Trend Prediction | No | Linear regression — predicts disk/memory exhaustion |
| Root Cause Analysis | Optional | AI explains why a score dropped significantly |
| Optimization Recommendations | Optional | Weekly suggestions prioritized by impact |
| Natural Language Queries | Yes | Ask questions via `/ask` in Telegram |

### Dashboard (HTMX, server-rendered)

| Page | URL | Description |
|------|-----|-------------|
| Overview | `/dashboard` | Stats summary (servers, incidents, blocks, CVEs) |
| Fleet Health | `/dashboard/health` | Score cards per server with color coding |
| Server Detail | `/dashboard/health/:id` | Metrics, disks, failed units for one server |
| Scores Grid | `/dashboard/scores` | Comparative table: servers × 6 dimensions |
| Incidents | `/dashboard/incidents` | Open incidents with severity |
| Servers | `/dashboard/servers` | Registered servers + last seen |
| CVE Alerts | `/dashboard/cve` | Pending CVEs with one-click actions |
| IP Blocks | `/dashboard/blocks` | Active IP blocks with unblock button |
| Security Logs | `/dashboard/logs` | Recent security events |

### Telegram Commands

| Command | Description |
|---------|-------------|
| `/status` | Server overview (load, mem, disk) |
| `/health` | Fleet health with scores and metrics |
| `/scores` | 6-dimension score grid for all servers |
| `/scores <server>` | Detailed scores for one server |
| `/servers` | List all servers + connectivity check |
| `/containers` | Running Docker containers |
| `/events` | Recent security events (filterable) |
| `/incidents` | Open incidents |
| `/threat <ip>` | IP reputation + local history |
| `/hunt <ip\|user>` | Search logs by IOC |
| `/playbook list` | Available playbooks |
| `/playbook run <name> <server> [ip]` | Execute a playbook |
| `/vulns` | Vulnerability summary |
| `/ask <question>` | AI-powered natural language query |
| `/report` | Trigger daily report |
| `/report full` | Full historical report |
| `/add-server <name> <host> [port] [user] [key]` | Register a server |
| `/rm-server <name>` | Remove a server |

## Configuration

### Required

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | From [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | From [@userinfobot](https://t.me/userinfobot) |

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3334` | HTTP server port |
| `NODE_ENV` | `development` | `production` for optimized logging |
| `DATABASE_URL` | SQLite | PostgreSQL URL or `sqlite:/path/to/file.db` |
| `DASHBOARD_TOKEN` | — | Token to access web dashboard |
| `NOTIFIERS` | `telegram` | Comma-separated: `telegram,discord,slack,whatsapp,email,ntfy,webhook` |

### AI Providers

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_PROVIDER` | `auto` | `gemini`, `openai`, `claude`, `ollama`, or `auto` |
| `GEMINI_API_KEY` | — | Google AI Studio key |
| `OPENAI_API_KEY` | — | OpenAI key |
| `ANTHROPIC_API_KEY` | — | Anthropic key |
| `OLLAMA_URL` | `http://localhost:11434` | Local Ollama instance |
| `OLLAMA_MODEL` | `qwen3:4b` | Model for analysis |

### Threat Intelligence

| Variable | Default | Description |
|----------|---------|-------------|
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB (free: 1000/day) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal (free: 500/day) |
| `ABUSE_CONFIDENCE_THRESHOLD` | `70` | Min confidence to auto-block |

### CVE Monitor

| Variable | Default | Description |
|----------|---------|-------------|
| `CVE_MONITOR_ENABLED` | `true` | Enable/disable scanning |
| `CVE_MONITOR_MIN_CVSS` | `7.0` | Min CVSS to alert (7.0 = High+) |
| `CVE_MONITOR_INTERVAL_HOURS` | `6` | How often to check |

## Development

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
npm install
cp .env.example .env  # fill in your values

npm run dev           # hot-reload dev server
npm run build         # TypeScript → dist/
npm run type-check    # tsc --noEmit
npm run test          # vitest (53 tests)
npm run lint          # ESLint
```

### Project Structure

```
src/
├── collectors/           # SSH-based data collection (agentless)
│   ├── ssh-collector.ts      # Base SSH execution layer
│   ├── log-collector.ts      # auth.log, ufw, docker events
│   ├── health-collector.ts   # CPU, memory, disk, uptime
│   ├── system-collector.ts   # kernel errors, journal, failed units
│   ├── performance-collector.ts  # disk I/O, network throughput
│   ├── process-collector.ts  # suspicious process detection
│   └── network-collector.ts  # connection flood detection
├── pipeline/             # Event processing
│   ├── normalizer.ts         # Raw logs → structured events
│   ├── detector.ts           # Rule-based threat detection
│   ├── enricher.ts           # Threat intelligence enrichment
│   ├── correlator.ts         # Event → Incident correlation
│   ├── ingestor.ts           # Event persistence (security)
│   ├── metrics-ingestor.ts   # Metrics persistence (Bronze)
│   └── score-calculator.ts   # 6-dimension scoring (Gold)
├── intelligence/         # AI + statistical analysis
│   ├── anomaly-detector.ts   # Baseline learning + deviation alerts
│   ├── trend-predictor.ts    # Linear regression predictions
│   ├── root-cause.ts         # AI root cause analysis
│   └── recommendations.ts   # Optimization recommendations
├── services/             # Business logic
│   ├── ai-provider.ts        # Multi-provider AI (Gemini/OpenAI/Claude/Ollama)
│   ├── ai.service.ts         # Legacy AI service
│   ├── server.service.ts     # Server CRUD
│   └── soc-analyst.service.ts # Natural language queries
├── workers/              # Background jobs
│   ├── event-collector.worker.ts     # Security events (2min)
│   ├── score-calculator.worker.ts    # Metrics (5min) + Scores (1h)
│   ├── intelligence.worker.ts        # Anomaly + Trends (1h)
│   ├── metrics-retention.worker.ts   # Cleanup >30d (daily)
│   ├── daily-report.worker.ts        # Morning report (08:00 BRT)
│   ├── block-cleanup.worker.ts       # Expired IP blocks
│   ├── cve-monitor.worker.ts         # CVE scanning
│   └── vuln-scanner.worker.ts        # Package vulnerability scan
├── playbooks/            # Automated response playbooks
├── plugins/              # Notification plugin system
├── telegram/             # Telegram bot commands + callbacks
├── dashboard/            # HTMX web dashboard
├── database/             # Drizzle ORM schema + connection
├── config/               # Environment + constants
└── index.ts              # Express server + worker orchestration
```

## Docker Compose

```yaml
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    env_file: .env
    ports:
      - "3334:3334"
    volumes:
      - guardian_data:/data
      - ~/.ssh:/home/node/.ssh:ro
    restart: unless-stopped

  # Optional: PostgreSQL for multi-server production
  guardian-db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - pg_data:/var/lib/postgresql/data

volumes:
  guardian_data:
  pg_data:
```

## License

AGPL-3.0 — see [LICENSE](LICENSE).

---

<a id="portugues"></a>

# Portugues (PT-BR)

Guardian e um SIEM/SOAR agentless que monitora seus servidores via SSH, detecta ameacas em tempo real, computa scores de saude da infraestrutura, preve esgotamento de recursos, e responde automaticamente. Feito para operadores solo, startups pequenas, e homelabbers que querem monitoramento de nivel enterprise sem a complexidade enterprise.

## Por que Guardian?

| Feature | Fail2ban | CrowdSec | Wazuh | **Guardian** |
|---------|----------|----------|-------|--------------|
| Tempo de setup | 5 min | 30 min | 2+ horas | **30 segundos** |
| Instala nos alvos | Sim | Sim | Sim | **Nao (agentless SSH)** |
| Acoes de resposta | Block IP | Block IP | Scripts | **Playbooks + aprovacao** |
| Notificacoes | Email | — | Email | **7 canais** |
| Monitoramento CVE | — | — | Sim | **Sim (OSV.dev + AI fix)** |
| Score de saude | — | — | — | **6 dimensoes** |
| Deteccao de anomalias | — | — | — | **Baseline estatistico** |
| Predicao de tendencias | — | — | — | **Regressao linear** |
| Analise por IA | — | — | — | **4 providers** |
| Dashboard | — | Web | Web | **HTMX (leve)** |
| Mobile-first | — | — | — | **Telegram/WhatsApp** |
| Uso de recursos | Minimo | Baixo | Alto | **~50MB RAM** |

## Inicio Rapido

```bash
# Docker em uma linha (SQLite, zero dependencias)
docker run -d --name guardian \
  -e TELEGRAM_BOT_TOKEN=seu_token \
  -e TELEGRAM_CHAT_ID=seu_chat_id \
  -v guardian_data:/data \
  -v ~/.ssh:/home/node/.ssh:ro \
  -p 3334:3334 \
  ghcr.io/afborda/guardian-blue-team:latest
```

Ou use o instalador interativo:

```bash
curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh | bash
```

O instalador guia voce por: geracao de chave SSH, configuracao do .env, escolha do provedor de IA, e setup do primeiro servidor — tudo com interface colorida no terminal.

## Arquitetura

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Guardian Core                                 │
├─────────────┬────────────┬─────────────┬─────────────┬───────────────┤
│  Coletores  │  Pipeline  │Inteligencia │  Playbook   │   Dashboard   │
│  (SSH/proc) │(Bronze→Gold)│(Anomalia/IA)│   Engine    │  (HTMX/SSR)  │
├─────────────┴────────────┴─────────────┴─────────────┴───────────────┤
│                     Sistema de Plugins (7 notificadores)               │
├────────┬─────────┬────────┬────────┬───────┬────────┬────────────────┤
│Telegram│ Discord │ Slack  │ Email  │ ntfy  │Webhook │  WhatsApp      │
└────────┴─────────┴────────┴────────┴───────┴────────┴────────────────┘
      ↕                    ↕                    ↕               ↕
 [Telegram Bot]     [PostgreSQL/SQLite]    [Servidores SSH] [Provedores IA]
  comandos+alertas    armazenamento        seus servidores  Gemini/GPT/Claude/Ollama
```

### Pipeline de Dados (Bronze → Silver → Gold)

```
Coletores (5min)            Pipeline                      Saida
────────────────            ────────                      ─────
Health  ─┐                  ┌─ Bronze ──────────────┐
System  ─┼─► cmds SSH ──►  │ server_metrics (bruto)│──► Dashboard
Perf    ─┘                  └───────────────────────┘
                                     │
                            ┌─ Gold ─┴──────────────┐
                            │ server_scores (6 dim) │──► Telegram
                            └───────────────────────┘
                                     │
                            ┌─ Inteligencia ────────┐
                            │ Anomalia + Tendencia  │──► Alertas
                            └───────────────────────┘
```

## Funcionalidades

### Monitoramento de Seguranca (SIEM/SOAR)

**Deteccao de Ameacas (9 regras embutidas):**
- Brute force SSH — 20+ tentativas de login falhadas do mesmo IP
- Port scanning — 5+ portas sondadas em 10 minutos
- Mineracao de cripto — Detecta xmrig, minerd, cpuminer, kdevtmpfsi, kinsing
- Binarios suspeitos — Execucao de /tmp, /dev/shm, paths ocultos
- Logins nao autorizados — SSH de IPs/fingerprints nao confiados
- Logins por senha — Alerta quando autenticacao por chave deveria ser obrigatoria
- Logins em horario incomum — Acesso entre 00:00-06:00 de IPs nao confiados
- Movimento lateral — SSH de IP que anteriormente fez brute force
- Escape de container — 5+ mortes de container em 10 minutos

**Resposta Automatizada (8 playbooks):**
- Bloquear IPs maliciosos via UFW (automatico ou com aprovacao humana)
- Matar processos de mineracao de cripto
- Pausar/desconectar containers comprometidos
- Enriquecer IPs com threat intelligence (AbuseIPDB, VirusTotal)
- Rastrear reincidentes entre servidores

**Monitoramento de CVE:**
- Escaneia pacotes instalados (Debian, Alpine, npm) contra OSV.dev
- Recomendacoes de fix por IA com avaliacao de risco
- Patching em um clique via Telegram com aprovacao humana

### Observabilidade de Infraestrutura

**Coletores (agentless, via SSH lendo /proc):**

| Coletor | Dados | Fonte |
|---------|-------|-------|
| Health | Load CPU, memoria, swap, uso de disco, uptime | `/proc/loadavg`, `free`, `df`, `/proc/uptime` |
| System | Erros kernel, erros journal, unidades systemd falhadas | `dmesg`, `journalctl`, `systemctl` |
| Performance | Disk I/O (read/write Bps), Network I/O (rx/tx Bps) | `/proc/diskstats`, `/proc/net/dev` (delta sampling) |

**Scoring de Servidor em 6 Dimensoes (0-100, baseado em penalidades):**

| Score | O que mede | Peso |
|-------|-----------|------|
| Health | Load ratio CPU, memoria %, disco %, swap % | 20% |
| Security | Incidentes abertos, eventos de ataque, IPs bloqueados | 25% |
| Quality | Servicos falhados, erros kernel, erros journal, uptime | 15% |
| Waste | CPU ociosa, memoria nao usada, recursos desperdicados | 10% |
| Vulnerability | CVEs abertas (criticas/altas), dias desde ultimo scan | 20% |
| Availability | Uptime, reinicializacoes de servicos, crashes de container | 10% |

**Score Geral** = media ponderada das 6 dimensoes.

### Camada de Inteligencia com IA

Funciona com 4 provedores (configuravel, com fallback automatico):

| Provedor | Config | Uso |
|----------|--------|-----|
| Gemini | `GEMINI_API_KEY` | Tier gratis, rapido, recomendado |
| OpenAI | `OPENAI_API_KEY` | GPT-4o-mini para analise |
| Claude | `ANTHROPIC_API_KEY` | Melhor raciocinio |
| Ollama | `OLLAMA_URL` | Local, gratis, mais lento |

**Capacidades:**

| Funcionalidade | Precisa API? | Descricao |
|----------------|-------------|-----------|
| Deteccao de Anomalias | Nao | Baseline estatistico (media + 2.5σ sobre 7 dias) |
| Predicao de Tendencias | Nao | Regressao linear — preve esgotamento de disco/memoria |
| Analise de Causa Raiz | Opcional | IA explica por que um score caiu significativamente |
| Recomendacoes de Otimizacao | Opcional | Sugestoes semanais priorizadas por impacto |
| Consultas em Linguagem Natural | Sim | Faca perguntas via `/ask` no Telegram |

### Dashboard (HTMX, renderizado no servidor)

| Pagina | URL | Descricao |
|--------|-----|-----------|
| Overview | `/dashboard` | Resumo (servidores, incidentes, blocks, CVEs) |
| Fleet Health | `/dashboard/health` | Cards de score por servidor com cores |
| Detalhe Servidor | `/dashboard/health/:id` | Metricas, discos, unidades falhadas |
| Grid de Scores | `/dashboard/scores` | Tabela comparativa: servidores x 6 dimensoes |
| Incidentes | `/dashboard/incidents` | Incidentes abertos com severidade |
| Servidores | `/dashboard/servers` | Servidores registrados + ultima conexao |
| Alertas CVE | `/dashboard/cve` | CVEs pendentes com acoes one-click |
| Blocks IP | `/dashboard/blocks` | Blocks ativos com botao de unblock |
| Logs | `/dashboard/logs` | Eventos de seguranca recentes |

### Comandos Telegram

| Comando | Descricao |
|---------|-----------|
| `/status` | Overview dos servidores (load, mem, disco) |
| `/health` | Saude da frota com scores e metricas |
| `/scores` | Grid de scores (6 dimensoes) de todos servidores |
| `/scores <server>` | Scores detalhados de um servidor |
| `/servers` | Lista + verificacao de conectividade |
| `/containers` | Containers Docker rodando |
| `/events` | Eventos de seguranca recentes (filtravel) |
| `/incidents` | Incidentes abertos |
| `/threat <ip>` | Reputacao do IP + historico local |
| `/hunt <ip\|user>` | Buscar nos logs por IOC |
| `/playbook list` | Playbooks disponiveis |
| `/playbook run <nome> <server> [ip]` | Executar um playbook |
| `/vulns` | Resumo de vulnerabilidades |
| `/ask <pergunta>` | Consulta em linguagem natural com IA |
| `/report` | Forcar relatorio diario |
| `/report full` | Relatorio historico completo |
| `/add-server <nome> <host> [porta] [user] [key]` | Registrar servidor |
| `/rm-server <nome>` | Remover servidor |

## Configuracao

### Obrigatorias

| Variavel | Descricao |
|----------|-----------|
| `TELEGRAM_BOT_TOKEN` | De [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | De [@userinfobot](https://t.me/userinfobot) |

### Principais

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `PORT` | `3334` | Porta HTTP |
| `NODE_ENV` | `development` | `production` para logs otimizados |
| `DATABASE_URL` | SQLite | URL PostgreSQL ou `sqlite:/caminho/arquivo.db` |
| `DASHBOARD_TOKEN` | — | Token para acessar dashboard web |
| `NOTIFIERS` | `telegram` | Separados por virgula: `telegram,discord,slack,whatsapp,email,ntfy,webhook` |

### Provedores de IA

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `AI_PROVIDER` | `auto` | `gemini`, `openai`, `claude`, `ollama`, ou `auto` |
| `GEMINI_API_KEY` | — | Chave Google AI Studio |
| `OPENAI_API_KEY` | — | Chave OpenAI |
| `ANTHROPIC_API_KEY` | — | Chave Anthropic |
| `OLLAMA_URL` | `http://localhost:11434` | Instancia Ollama local |
| `OLLAMA_MODEL` | `qwen3:4b` | Modelo para analise |

### Threat Intelligence

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB (gratis: 1000/dia) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal (gratis: 500/dia) |
| `ABUSE_CONFIDENCE_THRESHOLD` | `70` | Confianca minima para auto-block |

### Monitor CVE

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `CVE_MONITOR_ENABLED` | `true` | Ativar/desativar scan |
| `CVE_MONITOR_MIN_CVSS` | `7.0` | CVSS minimo para alertar (7.0 = High+) |
| `CVE_MONITOR_INTERVAL_HOURS` | `6` | Intervalo de verificacao |

## Desenvolvimento

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
npm install
cp .env.example .env  # preencha seus valores

npm run dev           # servidor com hot-reload
npm run build         # TypeScript → dist/
npm run type-check    # tsc --noEmit
npm run test          # vitest (53 testes)
npm run lint          # ESLint
```

### Estrutura do Projeto

```
src/
├── collectors/           # Coleta de dados via SSH (agentless)
│   ├── ssh-collector.ts      # Camada base de execucao SSH
│   ├── log-collector.ts      # auth.log, ufw, docker events
│   ├── health-collector.ts   # CPU, memoria, disco, uptime
│   ├── system-collector.ts   # erros kernel, journal, unidades falhadas
│   ├── performance-collector.ts  # disk I/O, network throughput
│   ├── process-collector.ts  # deteccao de processos suspeitos
│   └── network-collector.ts  # deteccao de flood de conexoes
├── pipeline/             # Processamento de eventos
│   ├── normalizer.ts         # Logs brutos → eventos estruturados
│   ├── detector.ts           # Deteccao baseada em regras
│   ├── enricher.ts           # Enriquecimento com threat intel
│   ├── correlator.ts         # Evento → Incidente
│   ├── ingestor.ts           # Persistencia de eventos (seguranca)
│   ├── metrics-ingestor.ts   # Persistencia de metricas (Bronze)
│   └── score-calculator.ts   # Scoring 6 dimensoes (Gold)
├── intelligence/         # IA + analise estatistica
│   ├── anomaly-detector.ts   # Aprendizado de baseline + alertas de desvio
│   ├── trend-predictor.ts    # Predicoes por regressao linear
│   ├── root-cause.ts         # Analise de causa raiz com IA
│   └── recommendations.ts   # Recomendacoes de otimizacao
├── services/             # Logica de negocio
│   ├── ai-provider.ts        # Multi-provider IA (Gemini/OpenAI/Claude/Ollama)
│   ├── server.service.ts     # CRUD de servidores
│   └── soc-analyst.service.ts # Consultas em linguagem natural
├── workers/              # Jobs em background
│   ├── event-collector.worker.ts     # Eventos de seguranca (2min)
│   ├── score-calculator.worker.ts    # Metricas (5min) + Scores (1h)
│   ├── intelligence.worker.ts        # Anomalias + Tendencias (1h)
│   ├── metrics-retention.worker.ts   # Limpeza >30d (diario)
│   ├── daily-report.worker.ts        # Relatorio matinal (08:00 BRT)
│   ├── block-cleanup.worker.ts       # Blocks IP expirados
│   ├── cve-monitor.worker.ts         # Scan de CVEs
│   └── vuln-scanner.worker.ts        # Scan de vulnerabilidades em pacotes
├── playbooks/            # Playbooks de resposta automatizada
├── plugins/              # Sistema de plugins de notificacao
├── telegram/             # Comandos + callbacks do bot Telegram
├── dashboard/            # Dashboard web HTMX
├── database/             # Schema Drizzle ORM + conexao
├── config/               # Ambiente + constantes
└── index.ts              # Servidor Express + orquestracao de workers
```

## Docker Compose

```yaml
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    env_file: .env
    ports:
      - "3334:3334"
    volumes:
      - guardian_data:/data
      - ~/.ssh:/home/node/.ssh:ro
    restart: unless-stopped

  # Opcional: PostgreSQL para producao multi-servidor
  guardian-db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - pg_data:/var/lib/postgresql/data

volumes:
  guardian_data:
  pg_data:
```

## Licenca

AGPL-3.0 — veja [LICENSE](LICENSE).
