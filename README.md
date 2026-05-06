<p align="center">
  <img src="docs/guardian-overview.png" alt="Guardian Blue Team — Architecture Overview" width="100%">
</p>

<p align="center">
  <a href="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml"><img src="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://ghcr.io/afborda/guardian-blue-team"><img src="https://img.shields.io/badge/Docker-ghcr.io-blue" alt="Docker"></a>
</p>

<p align="center">
  <a href="README.pt-BR.md">Leia em Portugues</a>
</p>

---

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
| ML anomaly detection | — | — | — | **Behavioral baselines** |
| Trend prediction | — | — | — | **Linear regression** |
| AI analysis | — | — | — | **Local-first (Ollama) + cloud fallback** |
| Incident memory (RAG) | — | — | — | **Learns from past incidents** |
| Dashboard | — | Web | Web | **HTMX (lightweight)** |
| Mobile-first | — | — | — | **Telegram/WhatsApp** |
| Resource usage | Minimal | Low | High | **~50MB RAM** |

---

## Requirements

### Guardian Host (where Guardian runs)

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| CPU | 1 core | 2+ cores |
| RAM | 512MB (without Ollama) | 4GB+ (with Ollama) |
| RAM for Ollama | — | 8-12GB (for qwen3:4b/8b) |
| Disk | 2GB | 10GB+ (logs + models) |
| Docker | 20.10+ | 24+ |
| Docker Compose | v2+ | v2.20+ |
| Network | Outbound HTTPS (Telegram, AI APIs) | Public IP or reverse proxy for webhook |
| OS | Any with Docker | Ubuntu 22.04+, Debian 12+ |

### Target Servers (monitored via SSH)

| Requirement | Details |
|-------------|---------|
| SSH access | Key-based auth (password not supported) |
| SSH user | Root or user with `sudo NOPASSWD` for: `ufw`, `docker`, `journalctl`, `systemctl`, `ausearch` |
| OS | Linux (Debian/Ubuntu/Alpine tested) |
| Packages (optional) | `ufw` (firewall), `docker` (container monitoring), `auditd` (audit logs) |

### Data You Need Before Starting

| Data | Where to get it | Required? |
|------|----------------|-----------|
| **Telegram Bot Token** | Create a bot via [@BotFather](https://t.me/BotFather) | Yes |
| **Telegram Chat ID** | Send `/start` to [@userinfobot](https://t.me/userinfobot) | Yes |
| **Public URL** (`GUARDIAN_BASE_URL`) | Your domain pointing to Guardian (e.g. `https://guardian.example.com`) | Yes (for bot to receive messages) |
| **SSH private key** | Generate with `ssh-keygen -t ed25519` | Yes |
| **SSH public key on targets** | Add to `~/.ssh/authorized_keys` on each target server | Yes |
| AI API key (Gemini/OpenAI/Claude) | Provider's dashboard | No (Ollama is local and free) |
| AbuseIPDB API key | [abuseipdb.com](https://www.abuseipdb.com/) (free: 1000/day) | No (enriches threat intel) |
| Domain + SSL cert | DNS + Let's Encrypt via Traefik | No (for dashboard HTTPS) |

---

## Quick Start

### Interactive Installer (recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh)
```

The installer guides you through SSH key generation, environment configuration, AI provider selection, and first server setup with a beautiful terminal UI.

### Docker Compose (production)

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
cp .env.example .env
# Edit .env with your values (see Configuration below)
docker compose up -d
```

This starts 4 containers:
- **guardian** — main application
- **guardian-db** — PostgreSQL 16
- **guardian-ollama** — local AI (Ollama)
- **guardian-ollama-pull** — one-shot model downloader (exits after pulling models)

### Docker (minimal, single container)

```bash
docker run -d --name guardian \
  -e TELEGRAM_BOT_TOKEN=your_token \
  -e TELEGRAM_CHAT_ID=your_chat_id \
  -e GUARDIAN_BASE_URL=https://guardian.example.com \
  -e DATABASE_URL=postgres://user:pass@host:5432/guardian \
  -v ~/.ssh:/home/node/.ssh:ro \
  -p 3334:3334 \
  ghcr.io/afborda/guardian-blue-team:latest
```

### After Starting

1. Send `/help` to your Telegram bot — if it responds, everything is working
2. Register your first server: `/add-server myserver 1.2.3.4 22 root`
3. Wait 2-5 minutes for the first collection cycle
4. Check `/status` to see metrics, `/events` for security events

### Uninstall

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh) --uninstall
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Guardian Core                                 │
├─────────────┬────────────┬─────────────┬─────────────┬───────────────┤
│  Collectors │  Pipeline  │ Intelligence│  Playbook   │   Dashboard   │
│  (SSH/proc) │(Norm→Det→  │(ML Behavior │   Engine    │  (HTMX/SSR)  │
│             │ Enrich→Cor)│ + AI + RAG) │             │               │
├─────────────┴────────────┴─────────────┴─────────────┴───────────────┤
│                        Plugin System (7 notifiers)                     │
├────────┬─────────┬────────┬────────┬───────┬────────┬────────────────┤
│Telegram│ Discord │ Slack  │ Email  │ ntfy  │Webhook │  WhatsApp      │
└────────┴─────────┴────────┴────────┴───────┴────────┴────────────────┘
      ↕                    ↕                    ↕               ↕
 [Telegram Bot]     [PostgreSQL]          [SSH Targets]   [AI: Ollama → Cloud]
  commands+actions   event storage        your servers    local-first fallback
```

### Security Event Pipeline

```
SSH Logs → Normalize → Detect → Enrich → Correlate → Playbook → Notify
  (2min)     (parse)   (rules)  (intel    (incidents)  (auto)    (7ch)
                                +ML score)
```

### ML Intelligence Pipeline (hourly)

```
Per server → SSH Behavior Profiler → Anomaly scores for logins
           → Container Behavior    → Crashloop / memory leak detection
           → Statistical Anomaly   → Z-score deviation alerts
           → Trend Predictor       → Disk/memory exhaustion forecast
```

---

## Features

### Security Monitoring (SIEM/SOAR)

**Threat Detection (15+ built-in rules):**
- SSH brute force (20+ failed attempts from same IP)
- Port scanning (5+ ports probed in 10 minutes)
- Crypto mining processes (xmrig, minerd, cpuminer, kdevtmpfsi, kinsing)
- Suspicious binaries (execution from /tmp, /dev/shm, hidden paths)
- Unauthorized logins (SSH from untrusted IPs/fingerprints)
- Password logins (flags when key-only auth should be enforced)
- Unusual hour logins (00:00-06:00 from non-trusted IPs)
- Lateral movement (SSH from IP that previously brute-forced)
- Container escape (5+ container deaths in 10 minutes)
- Critical file tampering (FIM — /etc/passwd, shadow, sudoers, sshd_config)
- Suspicious sudo commands (curl, wget, nc, base64 -d, chmod 777)
- Cron persistence (new cron jobs with reverse shell / download patterns)
- Unauthorized SSH keys (new keys added to authorized_keys)
- DNS DGA detection (high-entropy domains via Shannon entropy)
- DNS suspicious TLDs (.tk, .ml, .ga, .cf, .top, .xyz, .pw, .cc)

**Automated Response (15 playbooks):**
- Block malicious IPs via UFW (auto or with human approval)
- Kill crypto mining processes
- Pause/disconnect compromised containers
- Enrich IPs with threat intelligence (AbuseIPDB, VirusTotal)
- Track repeat offenders across servers
- Alert on critical file integrity violations
- Flag suspicious sudo activity
- Detect cron-based persistence mechanisms
- Alert on unauthorized SSH key additions
- Respond to DNS-based C2 indicators

**CVE Monitoring:**
- Scans installed packages (Debian, Alpine, npm) against OSV.dev
- AI-powered fix recommendations with risk assessment
- One-click patching via Telegram with human approval

### ML Intelligence Layer

| Feature | How it works | What it catches |
|---------|-------------|-----------------|
| SSH Behavior Profiling | Builds per-user baselines (hours, IPs, fingerprints, velocity) | Login from new IP at unusual hour = high anomaly score |
| Container Behavior | Tracks CPU/memory mean+stddev, restart frequency, uptime | Crashloops, memory leaks, CPU spikes (crypto mining) |
| Statistical Anomaly | Z-score over 7-day rolling window | Metric deviations > 2.5σ from normal |
| Trend Prediction | Linear regression on disk/memory usage | Predicts resource exhaustion days in advance |
| Incident Memory (RAG) | Stores resolved incidents, finds similar cases | AI uses past context for better recommendations |
| Auto-Learn | Playbook resolutions auto-stored in memory | Guardian improves over time without manual input |

### AI Analysis (Local-First)

Guardian tries **Ollama first** (local, fast, private), then falls back to cloud providers:

```
Ollama (local) → Gemini → OpenAI → Claude
```

| Provider | Config | Notes |
|----------|--------|-------|
| **Ollama** | `OLLAMA_URL` | Primary. Included in docker-compose. Free, private. |
| Gemini | `GEMINI_API_KEY` | Free tier available. Fast. |
| OpenAI | `OPENAI_API_KEY` | GPT-4o-mini for analysis |
| Claude | `ANTHROPIC_API_KEY` | Best reasoning quality |

**AI Capabilities:**
- Root cause analysis (why did this score drop?)
- Natural language queries (`/ask why is my server slow?`)
- Incident analysis with historical context (RAG)
- CVE fix recommendations
- Weekly optimization suggestions

### Dashboard (HTMX, server-rendered)

| Page | URL | Description |
|------|-----|-------------|
| Overview | `/dashboard` | Stats summary, pipeline visualization, recent threats |
| Fleet Health | `/dashboard/health` | Score cards per server with color coding |
| Server Detail | `/dashboard/health/:id` | Metrics, disks, failed units for one server |
| Scores Grid | `/dashboard/scores` | Comparative table: servers x 6 dimensions |
| Incidents | `/dashboard/incidents` | Open incidents with severity |
| Servers | `/dashboard/servers` | Registered servers + last seen |
| CVE Alerts | `/dashboard/cve` | Pending CVEs with actions |
| IP Blocks | `/dashboard/blocks` | Active IP blocks with unblock button |
| Security Logs | `/dashboard/logs` | Recent security events (filterable) |
| Timeline | `/dashboard/timeline` | Chronological event correlation |
| Attack Map | `/dashboard/map` | Geographic distribution of attacking IPs |
| API Status | `/dashboard/apis` | System status and service health |

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
| `/files [server]` | File integrity changes |
| `/sudo [hours]` | Sudo activity (default 24h) |
| `/crons [server]` | Cron jobs / recent changes |
| `/keys [server]` | SSH keys / recent changes |
| `/dns [server] [hours]` | DNS queries / anomalies |
| `/playbook list` | Available playbooks |
| `/playbook run <name> <server> [ip]` | Execute a playbook |
| `/vulns` | Vulnerability summary |
| `/scan <server>` | Trigger vulnerability scan |
| `/ask <question>` | AI-powered natural language query |
| `/report` | Trigger daily report |
| `/report full` | Full historical report |
| `/add-server <name> <host> [port] [user] [key]` | Register a server |
| `/rm-server <name>` | Remove a server |
| `/block <ip> [server] [hours]` | Block an IP via UFW (default: 24h) |
| `/unblock <ip> [server]` | Unblock an IP |
| `/firewall [server]` | Show UFW firewall status |
| `/services [server]` | List running services/containers |
| `/ai` | Show AI provider status (which is active, latency) |
| `/learn <incident_id> <resolution>` | Teach Guardian from a resolved incident |
| `/memory` | Show incident memory stats (RAG) |
| `/apis` | External API health check |
| `/help` | Full command list |

---

## Configuration

### Required (Guardian won't work without these)

| Variable | Description | Where to get it |
|----------|-------------|-----------------|
| `TELEGRAM_BOT_TOKEN` | Bot authentication token | [@BotFather](https://t.me/BotFather) → /newbot |
| `TELEGRAM_CHAT_ID` | Your chat/group ID for alerts | [@userinfobot](https://t.me/userinfobot) |
| `GUARDIAN_BASE_URL` | Public URL for Telegram webhook (e.g. `https://guardian.example.com`) | Your domain + reverse proxy |
| `DATABASE_URL` | PostgreSQL connection string | Included in docker-compose |

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3334` | HTTP server port |
| `NODE_ENV` | `development` | `production` for optimized logging |
| `DASHBOARD_TOKEN` | — | Token to access web dashboard (auto-generated by installer) |
| `NOTIFIERS` | `telegram` | Comma-separated: `telegram,discord,slack,whatsapp,email,ntfy,webhook` |

### AI Providers

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_PROVIDER` | `auto` | `ollama`, `gemini`, `openai`, `claude`, or `auto` (local-first) |
| `OLLAMA_URL` | `http://ollama:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `qwen3:4b` | Model for analysis tasks |
| `OLLAMA_CHAT_MODEL` | `qwen3:0.6b` | Lightweight model for chat/NL queries |
| `GEMINI_API_KEY` | — | Google AI Studio key |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Gemini model |
| `OPENAI_API_KEY` | — | OpenAI key |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model |
| `ANTHROPIC_API_KEY` | — | Anthropic key |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6-20250514` | Claude model |

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

### Notification Channels (all optional)

| Variable | Description |
|----------|-------------|
| `DISCORD_WEBHOOK_URL` | Discord webhook URL |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL |
| `RESEND_API_KEY` | Resend API key for email alerts |
| `RESEND_FROM_EMAIL` | Sender email address |
| `WHATSAPP_API_URL` | Evolution API URL |
| `WHATSAPP_INSTANCE` | Evolution API instance name |
| `WHATSAPP_NUMBER` | Destination phone number |
| `NTFY_SERVER` | ntfy server URL (default: https://ntfy.sh) |
| `NTFY_TOPIC` | ntfy topic name |
| `WEBHOOK_URL` | Custom webhook endpoint |
| `WEBHOOK_SECRET` | HMAC secret for webhook signing |

### SSH Defaults

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST_SSH_HOST` | `127.0.0.1` | Default SSH host |
| `HOST_SSH_PORT` | `22` | Default SSH port |
| `HOST_SSH_USER` | `ubuntu` | Default SSH user |
| `HOST_SSH_KEY_PATH` | `/home/node/.ssh/id_ed25519` | Path to SSH private key |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTED_IPS` | — | Comma-separated IPs that bypass `unauthorized_login` alerts |
| `TRUSTED_FINGERPRINTS` | — | Comma-separated SSH key fingerprints (`SHA256:xxx`) |
| `TELEGRAM_WEBHOOK_SECRET` | — | Secret header for Telegram webhook validation |

### Docker Compose Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_KEY_DIR` | `~/.ssh` | Path to SSH keys (mounted read-only) |
| `GUARDIAN_DOMAIN` | `guardian.localhost` | Domain for Traefik routing |
| `GUARDIAN_DB_PASSWORD` | `guardian_secret` | PostgreSQL password |

---

## Docker Compose (full production stack)

```yaml
services:
  guardian:
    build: .
    container_name: guardian
    restart: unless-stopped
    env_file: .env
    depends_on:
      guardian-db:
        condition: service_healthy
      ollama:
        condition: service_started
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ${SSH_KEY_DIR:-~/.ssh}:/home/node/.ssh:ro
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 512M

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - guardian_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian -d guardian"]
      interval: 10s
      timeout: 5s
      retries: 5

  ollama:
    image: ollama/ollama:latest
    container_name: guardian-ollama
    restart: unless-stopped
    volumes:
      - ollama_models:/root/.ollama
    deploy:
      resources:
        limits:
          memory: 12G
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:11434/api/tags || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3

  ollama-pull:
    image: ollama/ollama:latest
    container_name: guardian-ollama-pull
    depends_on:
      ollama:
        condition: service_healthy
    entrypoint: ["sh", "-c", "ollama pull ${OLLAMA_MODEL:-qwen3:4b} && ollama pull nomic-embed-text"]
    environment:
      OLLAMA_HOST: http://ollama:11434
    restart: "no"

volumes:
  guardian_pgdata:
  ollama_models:
```

---

## Development

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
npm install
cp .env.example .env  # fill in your values

npm run dev           # hot-reload dev server
npm run build         # TypeScript → dist/
npm run type-check    # tsc --noEmit
npm run test          # vitest
npm run lint          # ESLint
```

### Project Structure

```
src/
├── collectors/           # SSH-based data collection (agentless)
│   ├── ssh-collector.ts      # Base SSH execution layer
│   ├── log-collector.ts      # auth.log, ufw, docker events
│   ├── docker-collector.ts   # Container stats + anomalies
│   ├── health-collector.ts   # CPU, memory, disk, uptime
│   ├── system-collector.ts   # kernel errors, journal, failed units
│   ├── performance-collector.ts  # disk I/O, network throughput
│   ├── process-collector.ts  # suspicious process detection
│   ├── network-collector.ts  # connection flood detection
│   ├── fim-collector.ts      # file integrity (SHA256 baselines)
│   ├── sudo-collector.ts     # sudo command auditing
│   ├── cron-collector.ts     # cron job enumeration
│   ├── ssh-keys-collector.ts # authorized_keys auditing
│   └── dns-collector.ts      # DNS query monitoring
├── pipeline/             # Event processing
│   ├── normalizer.ts         # Raw logs → structured events
│   ├── detector.ts           # Rule-based threat detection
│   ├── enricher.ts           # Threat intel + ML behavioral scoring
│   ├── correlator.ts         # Event → Incident correlation
│   ├── ingestor.ts           # Event persistence
│   ├── metrics-ingestor.ts   # Metrics persistence
│   └── score-calculator.ts   # 6-dimension scoring
├── intelligence/         # ML + statistical analysis
│   ├── anomaly-detector.ts   # Z-score baseline + deviation alerts
│   ├── trend-predictor.ts    # Linear regression predictions
│   ├── ssh-behavior.ts       # Per-user SSH login baselines
│   ├── container-behavior.ts # Per-container resource baselines
│   ├── root-cause.ts         # AI root cause analysis
│   └── recommendations.ts    # Optimization recommendations
├── services/             # Business logic
│   ├── ai-provider.ts        # Multi-provider AI (local-first)
│   ├── server.service.ts     # Server CRUD
│   ├── soc-analyst.service.ts # NL queries + RAG-augmented analysis
│   └── incident-memory.service.ts # Incident case memory (RAG)
├── workers/              # Background jobs
│   ├── event-collector.worker.ts     # Security events (2min)
│   ├── fim.worker.ts                 # File/cron/key baselines (4h)
│   ├── score-calculator.worker.ts    # Metrics (5min) + Scores (1h)
│   ├── intelligence.worker.ts        # ML profiling + anomaly (1h)
│   ├── metrics-retention.worker.ts   # Cleanup >30d (daily)
│   ├── daily-report.worker.ts        # Morning report (08:00 BRT)
│   ├── block-cleanup.worker.ts       # Expired IP blocks
│   ├── cve-monitor.worker.ts         # CVE scanning
│   └── vuln-scanner.worker.ts        # Package vulnerability scan
├── playbooks/            # Automated response engine
├── plugins/              # Notification plugin system (7 channels)
├── telegram/             # Bot commands + callbacks + actions
├── dashboard/            # HTMX web dashboard (11 pages)
├── database/             # Drizzle ORM schema + connection
├── config/               # Environment + constants
└── index.ts              # Express server + worker orchestration
```

---

## Security Considerations

- **No secrets in the repository** — all sensitive data is in `.env` (gitignored)
- **SSH keys** are mounted read-only into the container
- **Telegram webhook** validates `X-Telegram-Bot-Api-Secret-Token` header in production
- **Dashboard** requires `DASHBOARD_TOKEN` for access
- **AI requests** never send raw SSH keys or passwords — only log analysis data
- **Playbooks requiring system changes** (block IP, kill process) need explicit approval unless configured as auto-execute

## Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

AGPL-3.0 — see [LICENSE](LICENSE).
