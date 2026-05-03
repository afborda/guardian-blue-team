# Guardian Blue Team

> Lightweight SOAR for the rest of us

[![CI](https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg)](https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io-blue)](https://ghcr.io/afborda/guardian-blue-team)

Guardian is a lightweight SIEM/SOAR agent that monitors your servers via SSH, detects threats in real-time, and responds automatically or with your approval. Built for solo operators, small startups, and homelabbers who want real security monitoring without enterprise complexity.

---

## Why Guardian?

| Feature | Fail2ban | CrowdSec | Wazuh | **Guardian** |
|---------|----------|----------|-------|--------------|
| Setup time | 5 min | 30 min | 2+ hours | **30 seconds** |
| Response actions | Block IP | Block IP | Scripts | **Playbooks + approval** |
| Notifications | Email | — | Email | **7 channels** |
| CVE monitoring | — | — | Yes | **Yes (OSV.dev + AI fix)** |
| Dashboard | — | Web | Web | **HTMX (lightweight)** |
| Mobile-first | — | — | — | **Telegram/WhatsApp** |
| AI analysis | — | — | — | **Gemini/Ollama** |
| Resource usage | Minimal | Low | High | **~50MB RAM** |

---

## Quick Start (30 seconds)

```bash
docker run -d --name guardian \
  -e TELEGRAM_BOT_TOKEN=your_token \
  -e TELEGRAM_CHAT_ID=your_chat_id \
  -v guardian_data:/data \
  -v ~/.ssh:/home/node/.ssh:ro \
  -p 3334:3334 \
  ghcr.io/afborda/guardian-blue-team:latest
```

That's it. Guardian uses SQLite by default — no external database needed.

---

## What Guardian Does

### Threat Detection (9 built-in rules)

- **SSH brute force** — 20+ failed login attempts from same IP
- **Port scanning** — 5+ ports probed in 10 minutes
- **Crypto mining** — Detects xmrig, minerd, cpuminer, kdevtmpfsi, kinsing processes
- **Suspicious binaries** — Execution from /tmp/, /dev/shm/, hidden paths
- **Unauthorized logins** — SSH from untrusted IPs/fingerprints
- **Password logins** — Flags when key-only auth should be enforced
- **Unusual hour logins** — Access between 00:00-06:00 from non-trusted IPs
- **Lateral movement** — SSH login from IP that previously brute-forced
- **Container escape** — 5+ container deaths in 10 minutes

### Automated Response (8 playbooks)

- Block malicious IPs via UFW (auto or with approval)
- Kill crypto mining processes
- Pause/disconnect compromised containers
- Enrich IPs with threat intelligence (AbuseIPDB, VirusTotal)
- Track repeat offenders

### CVE Monitoring

- Scans installed packages (Debian, Alpine, npm) against OSV.dev
- AI-powered fix recommendations with risk assessment
- One-click patching with human approval

### AI-Powered Analysis

- Natural language security queries via `/ask`
- Automated incident summaries
- CVE remediation recommendations (command + risk + breaking changes)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       Guardian Core                            │
├────────────┬───────────┬─────────────┬────────────┬──────────┤
│ Collectors │ Detectors │ Correlator  │  Playbook  │    AI    │
│   (SSH)    │  (Rules)  │ (Incidents) │   Engine   │ (Gemini) │
├────────────┴───────────┴─────────────┴────────────┴──────────┤
│                      Plugin System                             │
├────────┬─────────┬──────────┬──────────┬─────────────────────┤
│Telegram│ Discord │  Slack   │  Email   │  Webhook/ntfy/WA    │
└────────┴─────────┴──────────┴──────────┴─────────────────────┘
        ↕                    ↕                     ↕
   [Dashboard]         [PostgreSQL]           [SSH Targets]
    :3334/dashboard      or SQLite           your servers
```

### Event Processing Pipeline

```
SSH Logs → Normalize → Detect → Enrich → Correlate → Playbook → Notify
  (2min)     (parse)   (rules)  (intel)  (incidents)  (auto)    (7ch)
```

---

## Configuration Reference

### Required Variables

| Variable | Description | How to get |
|----------|-------------|------------|
| `TELEGRAM_BOT_TOKEN` | Telegram Bot API token | Talk to [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | Your authorized chat ID | Talk to [@userinfobot](https://t.me/userinfobot) |

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3334` | HTTP server port |
| `NODE_ENV` | `development` | Set to `production` for optimized logging |
| `DATABASE_URL` | _(SQLite)_ | PostgreSQL connection string (leave empty for SQLite) |
| `NOTIFIERS` | `telegram` | Comma-separated list: `telegram,discord,slack,whatsapp,email,ntfy,webhook` |
| `DASHBOARD_TOKEN` | _(disabled)_ | Token to access web dashboard (dashboard disabled if unset) |

### AI Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | — | Google AI Studio API key (enables AI features) |
| `GEMINI_MODEL` | `gemini-2.0-flash-001` | Gemini model to use |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL (local AI fallback) |
| `OLLAMA_MODEL` | `qwen3:4b` | Ollama model for analysis |
| `OLLAMA_CHAT_MODEL` | `qwen3:0.6b` | Lighter model for chat |

### Threat Intelligence

| Variable | Default | Description |
|----------|---------|-------------|
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB lookups (free: 1000/day) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal lookups (free: 500/day) |
| `ABUSE_CONFIDENCE_THRESHOLD` | `70` | Min confidence score (0-100) to auto-block |

### CVE Monitor

| Variable | Default | Description |
|----------|---------|-------------|
| `CVE_MONITOR_ENABLED` | `true` | Enable/disable CVE scanning |
| `CVE_MONITOR_MIN_CVSS` | `7.0` | Minimum CVSS score to alert (7.0 = High+) |
| `CVE_MONITOR_INTERVAL_HOURS` | `6` | Hours between scans |

### Observability

| Variable | Default | Description |
|----------|---------|-------------|
| `UPTIME_KUMA_PUSH_URL` | — | Push URL for heartbeat monitoring (every 60s) |

### Legacy SSH (single server mode)

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST_SSH_HOST` | `127.0.0.1` | Default server host |
| `HOST_SSH_PORT` | `49222` | Default SSH port |
| `HOST_SSH_USER` | `ubuntu` | Default SSH user |
| `HOST_SSH_KEY_PATH` | — | Path to SSH private key |

> Prefer using `/add-server` via Telegram for multi-server setups.

---

## Notification Channels

Guardian supports 7 notification channels. Enable them via the `NOTIFIERS` environment variable:

```env
NOTIFIERS=telegram,discord,email
```

### Telegram (default, interactive)

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Yes | Authorized chat ID |
| `TELEGRAM_WEBHOOK_SECRET` | No | Webhook validation header |

Features: inline keyboard buttons for approve/reject/ignore actions, rate limiting (10 cmd/min).

### Discord

| Variable | Required | Description |
|----------|----------|-------------|
| `DISCORD_WEBHOOK_URL` | Yes | Discord webhook URL |

Features: color-coded embeds by severity (red=critical, orange=high, yellow=medium, blue=low).

### Slack (interactive)

| Variable | Required | Description |
|----------|----------|-------------|
| `SLACK_WEBHOOK_URL` | Yes | Slack incoming webhook URL |

Features: Block Kit formatting, action buttons (primary/danger styling).

### WhatsApp (interactive)

| Variable | Required | Description |
|----------|----------|-------------|
| `WHATSAPP_API_URL` | Yes | Evolution API or compatible WhatsApp API URL |
| `WHATSAPP_INSTANCE` | Yes | Instance name |
| `WHATSAPP_NUMBER` | Yes | Destination phone number |

Features: button messages (max 3 buttons per message).

### Email

| Variable | Required | Description |
|----------|----------|-------------|
| `RESEND_API_KEY` | Yes | Resend.com API key |
| `EMAIL_TO` | No | Recipient (default: key owner's email) |
| `EMAIL_FROM` | No | Sender (default: `Guardian <noreply@guardian.local>`) |

### ntfy (push notifications)

| Variable | Required | Description |
|----------|----------|-------------|
| `NTFY_TOPIC` | Yes | ntfy topic name |
| `NTFY_SERVER` | No | Server URL (default: `https://ntfy.sh`) |

Features: priority-mapped notifications (5=critical, 4=high, 3=medium, 2=low).

### Webhook (generic)

| Variable | Required | Description |
|----------|----------|-------------|
| `WEBHOOK_URL` | Yes | POST endpoint URL |
| `WEBHOOK_SECRET` | No | HMAC-SHA256 signing secret (header: `X-Guardian-Signature`) |

Payload format:
```json
{
  "title": "SSH Brute Force Detected",
  "body": "...",
  "severity": "high",
  "metadata": { "sourceIp": "1.2.3.4", "serverId": "5" },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Which channels support interactive buttons?

| Channel | Approve/Reject buttons | Playbook approval | CVE actions |
|---------|----------------------|-------------------|-------------|
| Telegram | Yes | Yes | Yes |
| Slack | Yes | Yes | Yes |
| WhatsApp | Yes (max 3) | Yes | Yes |
| Discord | No | No | No |
| Email | No | No | No |
| ntfy | No | No | No |
| Webhook | No | No | No |

---

## Database

### SQLite (zero-config, default)

If `DATABASE_URL` is not set, Guardian automatically creates a SQLite database at `/data/guardian.db` (Docker) or `./data/guardian.db` (local).

Best for: homelabs, single-server monitoring, getting started.

### PostgreSQL (production)

Set `DATABASE_URL` to a PostgreSQL connection string:

```env
DATABASE_URL=postgres://guardian:password@localhost:5432/guardian
```

Best for: multi-server production deployments, data durability, concurrent access.

### What's stored

| Table | Purpose |
|-------|---------|
| `soc_servers` | Server registry (name, host, SSH credentials, tags) |
| `security_events` | All security events with metadata and enrichment |
| `soc_incidents` | Correlated incidents (grouped events) |
| `playbook_executions` | Playbook run history with step results |
| `threat_intel_cache` | IP reputation data (AbuseIPDB, VirusTotal) with TTL |
| `vulnerabilities` | Vulnerability scan results (ports, SSL, packages) |
| `cve_alerts` | CVE notifications with status tracking |
| `blocked_ips` | IP block history with TTL and auto-unblock |

### Migrating from SQLite to PostgreSQL

1. Export data from SQLite (if needed)
2. Set `DATABASE_URL` to your PostgreSQL connection string
3. Restart Guardian — schema is auto-created on first run

---

## Web Dashboard

Access at: `http://your-server:3334/dashboard?token=YOUR_TOKEN`

### Authentication

The dashboard requires `DASHBOARD_TOKEN` to be set. If not configured, the dashboard returns 503 (disabled).

Access methods:
- Query parameter: `?token=your_token`
- Header: `Authorization: Bearer your_token`

### Pages

| Page | URL | Content |
|------|-----|---------|
| Overview | `/dashboard/` | Server count, open incidents, blocked IPs, pending CVEs, 24h event count |
| Incidents | `/dashboard/incidents` | Open incidents with severity, timestamps, AI summaries |
| Servers | `/dashboard/servers` | Server registry with health status and last seen |
| CVE Alerts | `/dashboard/cve` | Pending CVEs with Update/Ignore action buttons |
| IP Blocks | `/dashboard/blocks` | Active blocks with Unblock action |
| Security Logs | `/dashboard/logs` | Recent events table filtered by severity |

### Tech Stack

- HTML rendered server-side (no build step)
- [HTMX](https://htmx.org/) for dynamic loading
- [Pico.css](https://picocss.com/) for styling (dark mode auto)
- All data fetched from internal JSON API endpoints

### Is it public?

No. The dashboard is **private by default**:
- Disabled entirely if `DASHBOARD_TOKEN` is not set
- All routes require valid token
- No user registration or public access
- Use a reverse proxy (nginx, Traefik) with HTTPS in production

---

## AI Features

Guardian uses AI for two main capabilities. Both are optional and require either Gemini API key or a local Ollama instance.

### SOC Analyst (`/ask` command)

Ask natural language questions about your security posture:

```
/ask what's the most attacked server this week?
/ask summarize the incident #42
/ask any suspicious activity from Brazil IPs?
```

The AI has access to:
- Last 7 days of event statistics
- Incident summaries
- Server health data
- Threat intelligence cache

### AI-Assisted CVE Remediation

When a new CVE is detected with a known fix:

1. Guardian sends CVE context to Gemini (package, version, CVSS, ecosystem)
2. AI returns a structured recommendation:
   - **Exact command** to run (apt-get, apk, npm)
   - **Risk level** (low/medium/high)
   - **Explanation** of what the fix does
   - **Breaking changes** warning (if any)
   - **Alternative command** (safer option)
3. You receive a notification with 3 buttons: **Apply Fix**, **Use Alternative**, **Ignore**
4. Only after you approve does Guardian execute the command via SSH

If AI is unavailable, Guardian falls back to standard package upgrade commands.

### Configuration

**Option A: Google Gemini (recommended, free tier available)**
```env
GEMINI_API_KEY=your_api_key_from_aistudio_google_dev
GEMINI_MODEL=gemini-2.0-flash-001
```

**Option B: Ollama (fully local, no API key needed)**
```env
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen3:4b
OLLAMA_CHAT_MODEL=qwen3:0.6b
```

Gemini is the primary provider. If it fails, Guardian automatically falls back to Ollama.

---

## Telegram Commands

| Command | Description |
|---------|-------------|
| `/status` | Server health (CPU, RAM, disk, uptime) |
| `/servers` | List all registered servers with connectivity status |
| `/containers [server]` | Running Docker containers per server |
| `/events [severity]` | Last 20 security events (filter: info/low/medium/high) |
| `/incidents` | Open incidents with top attackers |
| `/threat <ip>` | IP reputation lookup (AbuseIPDB + local history) |
| `/hunt <ip\|user>` | Timeline of events for an IP or username |
| `/vulns` | CVE summary by severity and server |
| `/report` | Daily security report (24h summary) |
| `/report full` | Cumulative report since deployment |
| `/ask <question>` | AI analyst (requires Gemini or Ollama) |
| `/playbook list` | Available playbooks with auto/approval indicators |
| `/playbook run <name> <server> [ip]` | Manually trigger a playbook |
| `/add-server <name> <host> [port] [user] [key]` | Register a new server |
| `/rm-server <name>` | Remove a server |
| `/scan` | Alias for `/vulns` |
| `/help` | Full command reference |

### Rate Limiting

10 commands per 60 seconds. Exceeding the limit returns a warning message.

---

## Playbooks

Playbooks are automated response workflows triggered by detected threats. Each playbook defines a sequence of steps with optional conditions and approval gates.

### Built-in Playbooks

| Playbook | Trigger | Response | Approval |
|----------|---------|----------|----------|
| `ssh-brute-force` | 10+ SSH failures | Enrich IP → Block if malicious | Auto |
| `port-scan-response` | Port scan detected | Enrich IP → Block if score > 50 | Auto |
| `crypto-mining-response` | Mining process found | Kill process → Block source 7d | Auto |
| `lateral-movement-response` | SSH from prior attacker | Block 7d + critical alert | Auto |
| `connection-flood-response` | Connection flood | Enrich → Block if score > 30 | Auto |
| `container-escape-response` | Container escape | Pause + disconnect container | Requires approval |
| `suspicious-process` | Suspicious execution | Notify for investigation | Requires approval |
| `password-login-alert` | Password-based SSH | Notify (recommends key auth) | Auto |
| `unusual-hour-alert` | Login 00:00-06:00 | Medium severity notification | Auto |

### How Approval Works

For playbooks marked "Requires approval":
1. Guardian sends a notification with the proposed action
2. You receive **Approve** / **Reject** buttons (Telegram, Slack, or WhatsApp)
3. Approval requests expire after 30 minutes
4. Only after approval does Guardian execute the action

### Manual Triggering

```
/playbook run ssh-brute-force myserver 1.2.3.4
```

### Available Actions

- `block-ip` — Block via UFW (configurable duration: 6h to 7d)
- `unblock-ip` — Remove UFW block
- `kill-process` — Terminate process via SSH
- `pause-container` — Docker pause
- `disconnect-container` — Disconnect from Docker network
- `enrich-ip` — Threat intelligence lookup
- `check-repeat` — Count incidents from same IP in last 7 days
- `notify` — Broadcast to all configured notifiers

---

## CVE Monitoring

### How It Works

1. **Inventory collection** — Guardian SSHs into each server and collects installed packages
2. **Vulnerability check** — Packages are queried against [OSV.dev](https://osv.dev) (Google's open vulnerability database)
3. **Alert generation** — New CVEs above the CVSS threshold are sent as interactive notifications
4. **Remediation** — One-click update with AI analysis or standard package upgrade

### Supported Ecosystems

| Ecosystem | Collection Method | Update Command |
|-----------|------------------|----------------|
| Debian/Ubuntu | `dpkg-query -W` | `apt-get install --only-upgrade` |
| Alpine | `apk list --installed` | `apk upgrade` |
| npm | `npm list` | `npm update` / `npm install @version` |

### Scan Schedule

- **Automatic:** Every 6 hours (configurable via `CVE_MONITOR_INTERVAL_HOURS`)
- **Minimum CVSS:** 7.0 by default (only High and Critical)
- **Cache:** Package lists cached 24h per server

### Remediation Flow

```
CVE Detected → AI Analyzes (if available) → Notification with buttons
                                                    ↓
                                    [Apply Fix] [Alternative] [Ignore]
                                         ↓
                            SSH → Execute command → Verify → Report
```

---

## Detection Rules

### Thresholds (configurable in `src/config/constants.ts`)

| Rule | Threshold | Window |
|------|-----------|--------|
| SSH brute force | 20 failed attempts | Per source IP |
| Port scan | 5+ ports | 10 minutes |
| Container escape | 5+ container deaths | 10 minutes |
| Unusual hours | 00:00 - 06:00 | Login time (server timezone) |
| Correlation window | — | 10 minutes (general), 30 minutes (port scans) |

### Trusted IPs

IPs that should never trigger `unauthorized_login` alerts. Configure in `src/config/constants.ts`:

```typescript
trustedIps: [
  '203.0.113.10',   // Office IP
  '198.51.100.5',   // VPN exit
]
```

---

## Production Setup

### Docker Compose with PostgreSQL

```yaml
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    env_file: .env
    depends_on: [guardian-db]
    volumes:
      - ~/.ssh:/home/node/.ssh:ro
    ports:
      - "3334:3334"
    restart: unless-stopped

  guardian-db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${GUARDIAN_DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  pgdata:
```

### With Traefik (HTTPS)

```yaml
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    env_file: .env
    depends_on: [guardian-db]
    volumes:
      - ~/.ssh:/home/node/.ssh:ro
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.guardian.rule=Host(`guardian.yourdomain.com`)"
      - "traefik.http.routers.guardian.tls.certresolver=letsencrypt"
      - "traefik.http.services.guardian.loadbalancer.server.port=3334"
    restart: unless-stopped
```

### Minimal `.env` for production

```env
# Required
TELEGRAM_BOT_TOKEN=123456:ABC-DEF
TELEGRAM_CHAT_ID=987654321
DATABASE_URL=postgres://guardian:strongpassword@guardian-db:5432/guardian

# Recommended
DASHBOARD_TOKEN=a-long-random-string-here
GEMINI_API_KEY=your-gemini-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
NOTIFIERS=telegram
NODE_ENV=production

# Optional
CVE_MONITOR_ENABLED=true
CVE_MONITOR_MIN_CVSS=7.0
UPTIME_KUMA_PUSH_URL=https://uptime.yourdomain.com/api/push/xxx
```

---

## Adding Servers

### Via Telegram

```
/add-server myserver 192.168.1.100 22 ubuntu /home/node/.ssh/id_ed25519
```

Parameters:
- `name` — Unique identifier (used in commands and notifications)
- `host` — IP or hostname
- `port` — SSH port (default: 22)
- `user` — SSH username (default: ubuntu)
- `keyPath` — Path to SSH private key inside the container

### SSH Key Setup

Mount your SSH keys read-only in Docker:

```bash
-v ~/.ssh:/home/node/.ssh:ro
```

Guardian needs:
- Private key (ed25519 or RSA)
- Key must have access to target servers (add public key to `~/.ssh/authorized_keys` on targets)
- User must have `sudo` for blocking actions (UFW) and package updates

---

## Logs & Observability

### Structured Logging (Pino)

Guardian uses [Pino](https://getpino.io/) for JSON structured logging:

```bash
# Development (pretty-printed)
npm run dev

# Production (JSON, pipe to your log aggregator)
NODE_ENV=production node dist/index.js | jq .
```

### Health Endpoint

```
GET /health
→ { "status": "ok", "uptime": 86400 }
```

Public (no auth required). Use for load balancer health checks or monitoring.

### Uptime Kuma Integration

Set `UPTIME_KUMA_PUSH_URL` and Guardian will push a heartbeat every 60 seconds:

```env
UPTIME_KUMA_PUSH_URL=https://uptime.example.com/api/push/guardian-abc123
```

### Docker Health Check

The Docker image includes a built-in health check:
```
HEALTHCHECK --interval=30s --timeout=5s --retries=3
  CMD wget -q --spider http://localhost:3334/health || exit 1
```

---

## Security Considerations

### What's exposed to the network

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `/health` | None (public) | Health check only, returns `{"status":"ok"}` |
| `/webhook/telegram` | Webhook secret (optional) | Telegram bot updates |
| `/dashboard/*` | Token required | Web dashboard |
| `/api/dashboard/*` | Token required | Dashboard API |

### What's NOT exposed

- Database (internal only, no external port in Docker Compose)
- SSH keys (mounted read-only)
- API keys (never logged, never returned in responses)
- Raw event data (only accessible via authenticated dashboard or Telegram)

### Best Practices

1. **Always set `DASHBOARD_TOKEN`** — Without it, the dashboard is disabled (503)
2. **Use HTTPS in production** — Put Guardian behind a reverse proxy (Traefik, nginx, Caddy)
3. **Set `TELEGRAM_WEBHOOK_SECRET`** — Validates incoming Telegram updates
4. **Restrict SSH key permissions** — Mount as read-only (`:ro`), use dedicated keys per server
5. **Use PostgreSQL in production** — SQLite is single-writer; PostgreSQL handles concurrent access
6. **Keep `trustedIps` updated** — Prevents false positives from your own IPs

---

## Plugins

### Adding a Custom Notifier

Create a file in `src/plugins/notifiers/` implementing the `NotifierPlugin` interface:

```typescript
import type { NotifierPlugin, FormattedAlert, InteractiveAction } from '../types.js';

export class MyNotifier implements NotifierPlugin {
  name = 'my-notifier';
  enabled = true;

  async init(): Promise<void> {
    // Check config, set enabled = false if missing
  }

  async send(alert: FormattedAlert): Promise<void> {
    // Send the notification
  }

  // Optional: support interactive buttons
  async sendInteractive?(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void> {
    // Send with action buttons
  }
}
```

Register in `src/plugins/index.ts`:
```typescript
registerNotifier('my-notifier', () => new MyNotifier());
```

Add to your `NOTIFIERS` env var:
```env
NOTIFIERS=telegram,my-notifier
```

### Plugin Interfaces

- `NotifierPlugin` — Send alerts to external systems
- `DetectorPlugin` — Custom detection rules
- `ActionPlugin` — Custom playbook actions
- `EnricherPlugin` — Custom threat intelligence sources

See [CONTRIBUTING.md](CONTRIBUTING.md) for full plugin development guide.

---

## Background Workers

| Worker | Schedule | Function |
|--------|----------|----------|
| Event Collector | Every 2 min | Collects logs, detects threats, triggers playbooks |
| CVE Monitor | Every 6h | Scans packages against OSV.dev |
| Daily Report | 08:00 daily | Security summary to all notifiers |
| Vuln Scanner | Saturday 09:00 | Port scan, package audit, Docker images, SSL |
| Block Cleanup | Every 5 min | Auto-unblocks expired IPs |

All times are in server local timezone (BRT by default).

---

## Development

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
npm install
cp .env.example .env  # configure your tokens

npm run dev           # hot-reload development server
npm run test          # run tests
npm run type-check    # TypeScript validation
npm run build         # production bundle
npm run lint          # ESLint
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, plugin tutorials, and PR guidelines.

## Security

Report vulnerabilities via [SECURITY.md](SECURITY.md).

## License

[AGPL-3.0](LICENSE) — if you modify Guardian and offer it as a service, you must share your changes.
