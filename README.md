# Guardian Blue Team

Autonomous SIEM/SOAR agent for small-to-medium server fleets. Monitors multiple Linux servers via SSH, detects threats in real-time, responds automatically (or asks you first via Telegram), and generates daily security reports.

Built for sysadmins who want a security operations center (SOC) in a single container.

---

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Telegram Commands](#telegram-commands)
- [Detection Rules](#detection-rules)
- [Playbooks](#playbooks)
- [Creating Custom Playbooks](#creating-custom-playbooks)
- [Database Schema](#database-schema)
- [Standalone Mode](#standalone-mode)
- [Adding a Server](#adding-a-server)
- [Block Management](#block-management)
- [Fail2ban Setup](#fail2ban-setup)
- [Development](#development)
- [Roadmap](#roadmap)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          GUARDIAN BLUE TEAM                                    │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌─── Data Collection (SSH) ───────────────────────────────────────────────┐ │
│  │                                                                          │ │
│  │   Server A ──┐                                                           │ │
│  │   Server B ──┼──▶  SSH Collectors  ──▶  Raw Logs / Metrics              │ │
│  │   Server C ──┘     (auth, ufw, docker, process, network)                │ │
│  │                                                                          │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                           │                                                   │
│                           ▼                                                   │
│  ┌─── Processing Pipeline ─────────────────────────────────────────────────┐ │
│  │                                                                          │ │
│  │   Normalizer ──▶ Detector (9 rules) ──▶ Enricher (AbuseIPDB)           │ │
│  │        │                                       │                         │ │
│  │        ▼                                       ▼                         │ │
│  │   Correlator (dedup, group by IP) ──▶ Incidents (PostgreSQL)            │ │
│  │                                                                          │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                           │                                                   │
│                           ▼                                                   │
│  ┌─── Response Engine ─────────────────────────────────────────────────────┐ │
│  │                                                                          │ │
│  │   ┌── Auto-Execute ──────────────────────────────────────────────────┐  │ │
│  │   │  High confidence: block IP, kill process, isolate container      │  │ │
│  │   └──────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                          │ │
│  │   ┌── Human Approval (Telegram) ────────────────────────────────────┐  │ │
│  │   │  Medium confidence: propose action → [Approve] [Reject] [Watch] │  │ │
│  │   └──────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                          │ │
│  │   ┌── Alert Only ───────────────────────────────────────────────────┐  │ │
│  │   │  Low confidence: notify via Telegram, log for investigation     │  │ │
│  │   └──────────────────────────────────────────────────────────────────┘  │ │
│  │                                                                          │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
│  ┌─── Workers ─────────────────────────────────────────────────────────────┐ │
│  │                                                                          │ │
│  │   EventCollector   │ every 2min  │ SSH → collect → pipeline → respond   │ │
│  │   BlockCleanup     │ every 5min  │ Unblock IPs with expired TTL         │ │
│  │   DailyReport      │ 08:00 BRT   │ 24h summary to Telegram              │ │
│  │   VulnScanner      │ Sat 09:00   │ Port + package + Docker audit        │ │
│  │   ─── optional (AutomaBotHub) ──────────────────────────────────────    │ │
│  │   AbuseDetection   │ every 5min  │ AI analysis of n8n instances         │ │
│  │   ProfileBuilder   │ every 6h    │ Behavior baselines for instances     │ │
│  │                                                                          │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
│  ┌─── Integrations ───────────────────────────────────────────────────────┐  │
│  │  Telegram Bot │ AbuseIPDB │ Gemini AI │ Ollama │ Fail2ban │ UFW        │  │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                               │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Infrastructure Diagram

```
┌────────────────────────────────────────────────────────┐
│                Docker Compose Stack                      │
│                                                         │
│  ┌──────────────┐       ┌──────────────────────────┐   │
│  │  guardian-db  │◀─────│      guardian             │   │
│  │  (Postgres)   │      │  (Node.js SIEM agent)    │   │
│  │               │      │                          │   │
│  │  Port: 5432   │      │  Port: 3334 (/health)   │   │
│  │  Vol: pgdata  │      │  Vol: docker.sock (ro)   │   │
│  └──────────────┘       │  Vol: ~/.ssh (ro)        │   │
│                          └──────────┬───────────────┘   │
│                                     │                   │
│           guardian-internal          │  traefik-public   │
│           (database only)            │  (HTTPS ingress)  │
└──────────────────────────────────────┼──────────────────┘
                                       │
                              ┌────────▼────────┐
                              │    Traefik       │
                              │  (reverse proxy) │
                              └─────────────────┘
                                       │
                    ┌──────────────────┼───────────────────┐
                    │                  │                    │
              ┌─────▼─────┐    ┌──────▼──────┐    ┌──────▼──────┐
              │  Server A  │    │  Server B   │    │  Server C   │
              │  (SSH:49222)│   │  (SSH:49222) │   │  (SSH:22)   │
              └────────────┘    └─────────────┘    └─────────────┘
                              (monitored via SSH)
```

---

## Features

### Core (always active)

| Feature | Description |
|---------|-------------|
| Multi-server monitoring | SSH into N servers, collect logs/processes/network every 2 minutes |
| 9 detection rules | Brute force, port scan, crypto mining, lateral movement, container escape, etc. |
| 9 automated playbooks | Auto-block, kill processes, isolate containers, notify |
| Incident correlation | Groups related events, deduplicates repeat offenders |
| IP blocking with TTL | Auto-unblock after configurable duration (fail2ban or UFW) |
| Threat intelligence | AbuseIPDB enrichment, reputation scoring |
| Telegram bot | Commands, alerts, inline approval buttons, daily reports |
| Vulnerability scanning | Weekly audit: open ports, outdated packages, Docker images |
| Login verification | "Was this you?" flow for unknown SSH logins |

### Optional (AutomaBotHub integration)

| Feature | Description |
|---------|-------------|
| Instance abuse detection | AI-powered analysis of n8n container metrics |
| Behavior profiling | 90-day baselines for normal resource usage |
| Auto-suspend | Critical threats (crypto mining, DDoS) suspended immediately |
| Resource throttling | Reduce CPU/memory for abusive containers |

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
cp .env.example .env
```

Edit `.env` with at minimum:
- `TELEGRAM_BOT_TOKEN` — from @BotFather
- `TELEGRAM_CHAT_ID` — your chat ID
- `GUARDIAN_DB_PASSWORD` — choose a strong password
- Update `DATABASE_URL` to match the password

### 2. Set up Telegram webhook

```bash
# After deploying, register your webhook:
curl -X POST "https://api.telegram.org/bot<YOUR_TOKEN>/setWebhook" \
  -d "url=https://guardian.yourdomain.com/webhook/telegram"
```

### 3. Deploy

```bash
# Create the external network (if not exists)
docker network create traefik-public 2>/dev/null || true

# Start
docker compose up -d

# Verify
docker compose logs -f guardian
curl https://guardian.yourdomain.com/health
```

### 4. Add your first server

Send via Telegram:
```
/add-server production 192.168.1.100 49222 ubuntu /home/node/.ssh/id_ed25519
```

Guardian will start monitoring it in the next 2-minute cycle.

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| **Core** |
| `DATABASE_URL` | Yes | — | Guardian PostgreSQL connection |
| `TELEGRAM_BOT_TOKEN` | Yes | — | Telegram bot API token |
| `TELEGRAM_CHAT_ID` | Yes | — | Authorized chat for commands/alerts |
| `PORT` | No | `3334` | HTTP server port |
| `NODE_ENV` | No | `development` | `production` for less verbose logs |
| **AI** |
| `GEMINI_API_KEY` | No | — | Enables AI threat analysis + SOC queries |
| `GEMINI_MODEL` | No | `gemini-2.0-flash-001` | Gemini model |
| `OLLAMA_URL` | No | `http://localhost:11434` | Local AI fallback |
| `OLLAMA_MODEL` | No | `qwen3:4b` | Ollama model for analysis |
| **Threat Intel** |
| `ABUSEIPDB_API_KEY` | Recommended | — | IP reputation (free: 1000/day) |
| `VIRUSTOTAL_API_KEY` | No | — | Additional threat data |
| **AutomaBotHub** |
| `AUTOMABOTHUB_ENABLED` | No | `true` | Set `false` for standalone |
| `AUTOMABOTHUB_DATABASE_URL` | No | Same as `DATABASE_URL` | Separate DB for AutomaBotHub |
| `ABUSE_CONFIDENCE_THRESHOLD` | No | `70` | AI confidence to propose action |
| **Security** |
| `TELEGRAM_WEBHOOK_SECRET` | No | — | Validate webhook origin |
| **Monitoring** |
| `UPTIME_KUMA_PUSH_URL` | No | — | Heartbeat push (every 60s) |
| **Docker Compose** |
| `SSH_KEY_DIR` | No | `~/.ssh` | Host path to SSH keys |
| `GUARDIAN_DOMAIN` | No | `guardian.example.com` | Traefik domain |
| `GUARDIAN_DB_PASSWORD` | No | `guardian_secret` | Postgres password |

---

## Telegram Commands

| Command | Description |
|---------|-------------|
| `/status` | CPU, memory, disk, uptime of all servers |
| `/servers` | List servers with health status and last-seen |
| `/events [severity]` | Recent security events (filter: low/medium/high/critical) |
| `/incidents` | Open incidents with source IPs |
| `/threat <ip>` | AbuseIPDB lookup + local event history |
| `/hunt <ip\|user>` | Search last 20 events for an IOC |
| `/playbook list` | Show available playbooks |
| `/playbook run <name> <server> [ip]` | Execute a playbook manually |
| `/vulns` | Vulnerability summary by server |
| `/containers [server]` | Running Docker containers |
| `/scan` | Trigger immediate abuse detection |
| `/report` | Generate daily report now |
| `/ask <question>` | AI-powered security query (requires Gemini) |
| `/add-server <name> <host> [port] [user] [keypath]` | Register server |
| `/rm-server <name>` | Remove server |
| `/help` | Command reference |

---

## Detection Rules

| # | Rule | Trigger | Severity | Playbook |
|---|------|---------|----------|----------|
| 1 | SSH Brute Force | 20+ failed logins from same IP | high | `ssh-brute-force` (auto) |
| 2 | Port Scan | 10+ unique ports from same IP | medium | `port-scan-response` (auto) |
| 3 | Crypto Mining | xmrig/minerd/cpuminer process detected | critical | `crypto-mining-response` (auto) |
| 4 | Suspicious Binary | Execution from /tmp, /dev/shm, hidden paths | high | `suspicious-process` (approval) |
| 5 | Lateral Movement | SSH success after prior failures from same IP | critical | `lateral-movement-response` (auto) |
| 6 | Container Escape | Container dying 5+ times in 10min | high | `container-escape-response` (approval) |
| 7 | Connection Flood | 20+ connections from single IP | medium | `connection-flood-response` (auto) |
| 8 | Unauthorized Login | SSH from non-trusted IP/fingerprint | high | Login verification flow |
| 9 | Password Login | SSH with password instead of key | high | `password-login-alert` (notify) |
| 10 | Unusual Hour | SSH login 00:00-06:00 BRT from unknown IP | medium | `unusual-hour-alert` (notify) |

---

## Playbooks

| Playbook | Trigger | Actions | Approval |
|----------|---------|---------|----------|
| `ssh-brute-force` | ssh_brute_force | enrich → check-repeat → block 24h → notify | Auto |
| `port-scan-response` | port_scan | enrich → check-repeat → block 12h → notify | Auto |
| `crypto-mining-response` | crypto_mining | kill-process → enrich → block 7d → notify | Auto |
| `lateral-movement-response` | lateral_movement | enrich → block 7d → notify | Auto |
| `connection-flood-response` | connection_flood | enrich → check-repeat → block 6h → notify | Auto |
| `container-escape-response` | container_escape | pause → disconnect-network → notify | Manual |
| `suspicious-process` | suspicious_process | notify | Manual |
| `password-login-alert` | password_login | notify | Auto (alert only) |
| `unusual-hour-alert` | unusual_hour_login | notify | Auto (alert only) |

### Block conditions

Auto-block playbooks only execute the block step when:
- **ssh-brute-force**: `score > 50 OR repeatCount > 1`
- **port-scan-response**: `score > 50 OR repeatCount > 2`
- **connection-flood**: `score > 30 OR repeatCount > 1`
- **crypto/lateral**: Always block (no condition)

---

## Creating Custom Playbooks

Edit `src/playbooks/registry.ts`:

```typescript
{
  name: 'my-custom-playbook',
  description: 'Shown in /playbook list',
  trigger: { eventType: 'my_event_type', threshold: 5, window: '10m' },
  steps: [
    { action: 'enrich-ip' },
    { action: 'check-repeat' },
    { action: 'block-ip', params: { duration: '24h' }, condition: 'score > 50 OR repeatCount > 2' },
    { action: 'notify', params: { severity: 'high', message: 'Custom alert message' } },
  ],
  requiresApproval: false,
}
```

### Available Actions

| Action | Description | Params |
|--------|-------------|--------|
| `enrich-ip` | AbuseIPDB lookup, sets `score` variable | — |
| `check-repeat` | Count past incidents for IP (7 days), sets `repeatCount` | — |
| `block-ip` | Block via fail2ban (or UFW fallback) with TTL | `duration`: `1h`, `12h`, `7d` |
| `unblock-ip` | Remove block from fail2ban/UFW | `ip` (optional, defaults to context) |
| `kill-process` | Kill matching process via SSH | `processName` |
| `pause-container` | `docker pause` | `container` |
| `disconnect-container` | Remove from all Docker networks (isolate) | `container` |
| `notify` | Telegram alert | `severity`, `message` |

### Condition Syntax

```
score > 70                         # Simple comparison
score > 50 OR repeatCount > 2      # OR (any must match)
score > 30 AND repeatCount > 0     # AND (all must match)
authMethod != 0                    # Not equal
```

Operators: `>`, `<`, `>=`, `<=`, `==`, `!=`

---

## Database Schema

Guardian uses its own PostgreSQL instance:

```
┌─── guardian database ────────────────────────────────────────┐
│                                                               │
│  soc_servers (5 cols)         — monitored servers            │
│  security_events (15 cols)    — all collected events          │
│  soc_incidents (13 cols)      — correlated incidents          │
│  playbook_executions (10 cols)— playbook run history          │
│  blocked_ips (10 cols)        — active/expired IP blocks      │
│  threat_intel_cache (7 cols)  — AbuseIPDB response cache      │
│  vulnerabilities (11 cols)    — detected security issues      │
│                                                               │
│  Indexes: IP lookup, timestamp range, event type, severity    │
│                                                               │
└───────────────────────────────────────────────────────────────┘
```

If `AUTOMABOTHUB_ENABLED=true`, Guardian also reads from the AutomaBotHub database:
- `instances`, `plans`, `users`, `instance_metrics` (read-only)
- `guardian_decisions`, `abuse_incidents`, `instance_behavior_profiles` (read/write)

---

## Standalone Mode

Set `AUTOMABOTHUB_ENABLED=false` in `.env` to run Guardian without the n8n/AutomaBotHub integration.

In standalone mode, Guardian provides:
- Full multi-server SSH monitoring
- All 9 detection rules + 9 playbooks
- IP blocking with auto-unblock
- Telegram commands and alerts
- Daily reports and vulnerability scanning
- AI-powered threat analysis (if Gemini key provided)

This is the recommended setup for using Guardian on any Linux server fleet.

---

## Adding a Server

### Via Telegram

```
/add-server <name> <host> [port] [user] [keypath]
```

Example:
```
/add-server web-prod 203.0.113.50 49222 ubuntu /home/node/.ssh/id_ed25519
```

### Requirements on the target server

1. SSH key auth configured (password auth optional but flagged)
2. User has sudo access (for `ufw`, `fail2ban-client`, `docker`)
3. Ports not firewalled from Guardian's host

### SSH key setup

Mount your keys directory via `SSH_KEY_DIR` in `.env`. The container reads them as `/home/node/.ssh/`:

```bash
# On your host:
ssh-keygen -t ed25519 -f ~/.ssh/guardian_key -N ""
ssh-copy-id -i ~/.ssh/guardian_key.pub -p 49222 ubuntu@target-server
```

---

## Block Management

IPs are blocked with a TTL. The `BlockCleanupWorker` (every 5min) automatically unblocks expired entries.

### Blocking strategy

1. **Try fail2ban** — native TTL support, integrates with system logging
2. **Fallback to UFW** — `ufw deny from <ip>` + database TTL tracking

### View active blocks

```sql
SELECT ip, reason, blocked_at, expires_at
FROM blocked_ips
WHERE active = true
ORDER BY blocked_at DESC;
```

### Manual unblock

Via Telegram:
```
/playbook run unblock-ip <server-name> <ip-address>
```

---

## Fail2ban Setup

For servers with fail2ban installed, Guardian uses it for blocking (better TTL handling). Create this jail:

```ini
# /etc/fail2ban/jail.d/guardian.conf
[guardian-jail]
enabled = true
filter = guardian
action = iptables-multiport[name=guardian, port="0:65535", protocol=tcp]
logpath = /var/log/guardian-bans.log
maxretry = 1
bantime = 86400
findtime = 86400
```

```ini
# /etc/fail2ban/filter.d/guardian.conf
[Definition]
failregex = ^.*$
```

If fail2ban is not installed, Guardian automatically falls back to UFW with database-tracked expiry.

---

## Development

```bash
npm install          # Install dependencies
npm run dev          # Hot-reload (tsx watch)
npm run type-check   # TypeScript validation (tsc --noEmit)
npm run test         # Unit tests (Vitest)
npm run test:watch   # Tests in watch mode
npm run lint         # ESLint
npm run build        # Production build (tsup → dist/)
```

### Project structure

```
src/
├── index.ts                    # Express server + worker startup
├── config/
│   └── environment.ts          # Zod-validated env config
├── database/
│   ├── connection.ts           # PostgreSQL pools (guardian + automabothub)
│   ├── schema.ts               # Re-exports both schemas
│   ├── guardian-schema.ts      # SOC tables (owned by Guardian)
│   └── automabothub-schema.ts  # AutomaBotHub tables (read-only)
├── collectors/
│   ├── ssh-collector.ts        # Core SSH execution wrapper
│   ├── log-collector.ts        # Auth/UFW/Docker log collection
│   ├── process-collector.ts    # Process monitoring
│   ├── network-collector.ts    # Connection monitoring
│   └── docker-collector.ts     # Container events
├── pipeline/
│   ├── normalizer.ts           # Raw logs → NormalizedEvent
│   ├── detector.ts             # 9 detection rules
│   ├── enricher.ts             # Threat intel enrichment
│   ├── correlator.ts           # Event → Incident grouping
│   └── ingestor.ts             # Persist to database
├── playbooks/
│   ├── registry.ts             # 9 playbook definitions
│   ├── engine.ts               # Execution engine (conditions, steps)
│   └── actions/
│       ├── block-ip.ts         # fail2ban/UFW blocking with TTL
│       ├── enrich-ip.ts        # AbuseIPDB lookup
│       ├── check-repeat.ts     # Repeat offender detection
│       ├── kill-process.ts     # Process termination
│       ├── container-actions.ts # Pause/isolate containers
│       └── notify.ts           # Telegram notification
├── workers/
│   ├── event-collector.worker.ts  # Main collection loop
│   ├── block-cleanup.worker.ts    # TTL-based unblocking
│   ├── daily-report.worker.ts     # 08:00 BRT summary
│   ├── vuln-scanner.worker.ts     # Weekly audit
│   ├── abuse-detection.worker.ts  # AutomaBotHub abuse (optional)
│   └── profile-builder.worker.ts  # Behavior profiles (optional)
├── telegram/
│   ├── commands.ts             # Bot command handlers
│   ├── callbacks.ts            # Inline button handlers
│   └── login-verification.ts   # "Was this you?" flow
├── services/
│   ├── server.service.ts       # Multi-server CRUD
│   ├── ai-analyzer.service.ts  # Gemini/Ollama AI analysis
│   ├── soc-analyst.service.ts  # NL queries about security
│   ├── guardian-decision.service.ts  # Approval workflow
│   ├── host-security.service.ts # Fail2ban/UFW stats
│   └── instance-profile.service.ts  # Behavior profiling
├── threat-intel/
│   ├── manager.ts              # Central lookup + enrichment
│   ├── cache.ts                # In-memory TTL cache
│   └── abuseipdb.ts            # AbuseIPDB API client
├── vuln-scanner/               # Port/package/Docker scanning
└── utils/
    └── logger.ts               # Pino logger
```

---

## Roadmap

### Planned Features

| Feature | Priority | Complexity | Description |
|---------|----------|------------|-------------|
| **WAF / L7 Rate Limiting** | High | Medium | Instruct Traefik to apply rate-limit middlewares per route. Detect HTTP attack patterns (SQLi, XSS) in access logs. |
| **Forensic Snapshot** | High | Low | On incident detection, capture system state (processes, connections, open files, recent changes) before taking action. Evidence preservation. |
| **Container Network Isolation** | High | Done ✅ | Disconnect container from all networks while keeping it alive for analysis. |
| **Adaptive Thresholds** | Medium | Medium | Learn normal behavior per-server (baseline CPU, login frequency, port activity) and alert on deviations rather than fixed thresholds. |
| **Multi-tenant Dashboard** | Medium | High | Web UI with incident timeline, IP map, server health, playbook execution history. |
| **Log Retention Policies** | Medium | Low | Auto-archive/delete security_events older than N days to prevent unbounded growth. VACUUM and index maintenance. |
| **Honeypot Integration** | Medium | Medium | Deploy lightweight SSH/HTTP honeypots, feed events into Guardian's pipeline for early-warning detection. |
| **Slack/Discord Integration** | Low | Low | Alternative notification channels besides Telegram. |
| **MITRE ATT&CK Mapping** | Low | Medium | Tag each detection rule with ATT&CK technique IDs (T1110, T1053, etc.) for compliance reporting. |
| **Automated Remediation Docs** | Low | Low | After executing a playbook, generate an incident report (what happened, what was done, recommendations). |
| **VirusTotal Integration** | Low | Low | Hash-check suspicious binaries detected on servers. |
| **GeoIP Blocking** | Low | Medium | Auto-block entire countries if configured (e.g., block all SSH from countries you don't operate in). |
| **File Integrity Monitoring** | Medium | Medium | Track changes to critical files (/etc/passwd, /etc/shadow, sshd_config, crontabs). Alert on unauthorized modifications. |
| **Kubernetes Support** | Low | High | Extend beyond Docker to K8s pod/namespace monitoring via kubectl/API. |
| **Alert Fatigue Reduction** | Medium | Medium | ML-based alert scoring. Suppress repeated low-value alerts. Aggregate similar events into digests. |
| **Backup on Incident** | High | Low | Before blocking/killing, snapshot the relevant state (docker inspect, process tree, network connections) as forensic evidence. |
| **Custom Detection Rules (YAML)** | Medium | Medium | Load detection rules from YAML files instead of code — allow non-devs to add rules. |
| **Webhook Notifications** | Low | Low | POST incident data to arbitrary webhooks (integrate with PagerDuty, Opsgenie, etc.). |
| **TLS Certificate Monitoring** | Low | Low | Check SSL cert expiry for monitored services. Alert 14/7/1 days before expiration. |

### Architecture Improvements

| Improvement | Priority | Description |
|-------------|----------|-------------|
| **Event streaming** | Medium | Replace polling (2min) with rsyslog/journald forwarding for real-time detection |
| **Message queue** | Low | Add Redis/NATS between collectors and pipeline for buffering during load spikes |
| **Distributed mode** | Low | Run multiple Guardian instances sharing a DB for high-availability |
| **Plugin system** | Medium | Load playbook actions and detection rules from external modules |

---

## License

Private — all rights reserved.
