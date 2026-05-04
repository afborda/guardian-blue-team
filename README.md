<p align="center">
  <img src="https://img.shields.io/badge/Guardian-Blue%20Team-0066cc?style=for-the-badge&logo=shield&logoColor=white" alt="Guardian Blue Team">
</p>

<h1 align="center">Guardian Blue Team</h1>

<p align="center">
  <strong>Lightweight SIEM/SOAR + Infrastructure Observability for the rest of us</strong>
</p>

<p align="center">
  <a href="README.pt-BR.md">Leia em Portugues</a>
</p>

<p align="center">
  <a href="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml"><img src="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://ghcr.io/afborda/guardian-blue-team"><img src="https://img.shields.io/badge/Docker-ghcr.io-blue" alt="Docker"></a>
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

FIM/Cron/SSH Keys → Baseline Compare → Detect → Correlate → Playbook → Notify
       (4h)            (DB diff)        (rules)  (incidents)   (auto)    (7ch)
```

## Features

### Security Monitoring (SIEM/SOAR)

**Threat Detection (15 built-in rules):**
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
- Alert on critical file integrity violations (requires approval)
- Flag suspicious sudo activity
- Detect cron-based persistence mechanisms (requires approval)
- Alert on unauthorized SSH key additions (requires approval)
- Respond to DNS-based C2 indicators (DGA + suspicious TLDs)

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
| Scores Grid | `/dashboard/scores` | Comparative table: servers x 6 dimensions |
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
| `/files [server]` | File integrity changes |
| `/sudo [hours]` | Sudo activity (default 24h) |
| `/crons [server]` | Cron jobs / recent changes |
| `/keys [server]` | SSH keys / recent changes |
| `/dns [server] [hours]` | DNS queries / anomalies |
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
| `GEMINI_MODEL` | `gemini-2.0-flash-001` | Gemini model |
| `OPENAI_API_KEY` | — | OpenAI key |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model |
| `ANTHROPIC_API_KEY` | — | Anthropic key |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6-20250514` | Claude model |
| `OLLAMA_URL` | `http://localhost:11434` | Local Ollama instance |
| `OLLAMA_MODEL` | `qwen3:4b` | Model for analysis |
| `OLLAMA_CHAT_MODEL` | `qwen3:0.6b` | Lightweight model for chat |

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

### Notification Channels

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

### Security — Trusted Entities

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUSTED_IPS` | — | Comma-separated IPs that bypass `unauthorized_login` alerts (your admin/home IPs) |
| `TRUSTED_FINGERPRINTS` | — | Comma-separated SSH key fingerprints (`SHA256:xxx`) that bypass `unauthorized_login` alerts |
| `DASHBOARD_TOKEN` | — | Secret token to access `/dashboard` (auto-generated by installer) |
| `TELEGRAM_WEBHOOK_SECRET` | — | Secret header for Telegram webhook validation (rejects in production if missing) |

## Interactive Installer

The installer (`install.sh`) walks you through the full setup in 7 steps. Here's everything it asks:

| Step | What it asks | Required? | Notes |
|------|-------------|-----------|-------|
| 1 | — | — | Auto-detects OS and package manager |
| 2 | — | — | Verifies prerequisites (Node.js 20+, npm, SSH client, Docker) |
| 3 | Install directory | No | Default: `~/.guardian` |
| 4 | — | — | Generates an ed25519 SSH key pair; shows public key to add to servers |
| 5 | **Telegram Bot Token** | Yes | From [@BotFather](https://t.me/BotFather) |
| 5 | **Telegram Chat ID** | Yes | From [@userinfobot](https://t.me/userinfobot) |
| 5 | AI Provider choice (1-5) | No | 1=Gemini, 2=OpenAI, 3=Claude, 4=Ollama, 5=Skip |
| 5 | AI API key | Only if 1-3 | Secret input (not echoed) |
| 5 | Database choice (1-2) | No | 1=SQLite (default), 2=PostgreSQL |
| 5 | PostgreSQL URL | Only if 2 | Connection string |
| 5 | AbuseIPDB API key | No | For threat intelligence (Enter to skip) |
| 5 | Trusted IPs | No | Comma-separated admin IPs to avoid false alerts |
| 5 | Trusted SSH fingerprints | No | Comma-separated `SHA256:xxx` values (get via `ssh-keygen -lf ~/.ssh/id_ed25519.pub`) |
| 6 | Deploy mode (1-2) | No | 1=Docker Compose (if available), 2=Native Node.js + systemd |
| 7 | **Server name** | Yes | Friendly name (e.g., `prod-web-1`) |
| 7 | **Server IP/hostname** | Yes | Target server address |
| 7 | SSH port | No | Default: `22` |
| 7 | SSH user | No | Default: `ubuntu` |

After setup, the installer:
- Creates `.env` with all configured values
- Tests SSH connectivity to the first server
- Creates a systemd service (native mode) or prepares Docker Compose
- Prints the dashboard URL with its auto-generated token

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
│   ├── network-collector.ts  # connection flood detection
│   ├── fim-collector.ts      # file integrity (SHA256 baselines)
│   ├── sudo-collector.ts     # sudo command auditing
│   ├── cron-collector.ts     # cron job enumeration
│   ├── ssh-keys-collector.ts # authorized_keys auditing
│   └── dns-collector.ts      # DNS query monitoring
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
│   ├── fim.worker.ts                 # File/cron/key baselines (4h)
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

## Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

AGPL-3.0 — see [LICENSE](LICENSE).
