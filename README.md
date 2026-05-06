<p align="center">
  <img src="docs/guardian-overview.png" alt="Guardian Blue Team" width="100%">
</p>

<p align="center">
  <a href="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml"><img src="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://ghcr.io/afborda/guardian-blue-team"><img src="https://img.shields.io/badge/Docker-ghcr.io-blue" alt="Docker"></a>
  <img src="https://img.shields.io/badge/version-1.5.0-blue" alt="Version">
</p>

<p align="center">
  <a href="README.pt-BR.md"><strong>Portugues</strong></a> · <a href="docs/getting-started.md">Getting Started</a> · <a href="docs/architecture.md">Architecture</a> · <a href="docs/configuration.md">Configuration</a>
</p>

---

**Guardian** is an agentless SIEM/SOAR that monitors your servers via SSH, detects threats in real-time, and responds automatically. No agents to install, no complex setup — just point it at your servers and it starts protecting them.

It learns from every incident, builds behavioral baselines for users and containers, and improves its detection accuracy over time — all running locally on a single machine.

---

## At a Glance

| | Fail2ban | CrowdSec | Wazuh | **Guardian** |
|-|----------|----------|-------|:------------:|
| Setup | 5 min | 30 min | 2+ hours | **30 seconds** |
| Agents on targets | Yes | Yes | Yes | **No** |
| AI analysis | — | — | — | **Local-first** |
| Learns from incidents | — | — | — | **Yes (RAG)** |
| Behavioral ML | — | — | — | **Yes** |
| Mobile-first alerts | — | — | — | **Telegram** |

---

## Resource Consumption

| Component | RAM | Disk | CPU |
|-----------|-----|------|-----|
| Guardian (app) | 50-100MB | 200MB | 0.5 core |
| PostgreSQL | 64-256MB | 500MB-2GB | 0.2 core |
| Ollama (optional, local AI) | 4-6GB | 3GB | 2 cores (peak) |
| **Total without local AI** | **~300MB** | **~2GB** | **1 core** |
| **Total with local AI** | **~6GB** | **~5GB** | **2 cores** |

No local AI? Just set `GEMINI_API_KEY` — Google's free tier handles it.

---

## What It Protects Against

- **SSH**: brute force, unauthorized logins, lateral movement, unusual hours
- **Containers**: escape attempts, crashloops, crypto mining, resource abuse
- **File Integrity**: /etc/passwd, sudoers, sshd_config, authorized_keys tampering
- **Network**: port scanning, DNS DGA (C2 detection), suspicious TLDs
- **Supply Chain**: CVE monitoring on installed packages (OSV.dev)
- **Persistence**: malicious cron jobs, reverse shells, unauthorized SSH keys

15+ detection rules, 15 automated playbooks. [Full details →](docs/security-features.md)

---

## Why ML and RAG?

**ML Behavioral Baselines** — Guardian learns what "normal" looks like for each SSH user (login hours, IPs, keys) and each container (CPU, memory, restarts). When something deviates, it scores the anomaly 0-1 instead of firing a binary alert. Result: ~50% fewer false positives after 7 days.

**RAG Incident Memory** — Every resolved incident is stored. Next time something similar happens, Guardian tells the AI: "Last time this IP attacked, we blocked for 24h and it came back. Recommend permanent block." It gets smarter every week without manual training.

- Detection latency: ~2 minutes
- Automated response: ~5 seconds (playbook execution)
- Zero external dependencies for ML (pure TypeScript statistics)

[ML details →](docs/ml-intelligence.md) · [RAG details →](docs/rag-memory.md)

---

## Quick Start

### What you need

| Data | How to get it | Required? |
|------|--------------|:---------:|
| Telegram Bot Token | [@BotFather](https://t.me/BotFather) → `/newbot` | Yes |
| Telegram Chat ID | Send anything to [@userinfobot](https://t.me/userinfobot) | Yes |
| Public domain (HTTPS) | DNS pointing to your server | Yes |
| SSH key | Auto-generated or use existing `~/.ssh/id_ed25519` | Auto |
| AI API key | [aistudio.google.com](https://aistudio.google.com/) (free) or skip (Ollama runs locally) | No |

### Install

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
cp .env.example .env
```

Edit `.env` — fill **only these 4 values**:

```env
TELEGRAM_BOT_TOKEN=your_token_from_botfather
TELEGRAM_CHAT_ID=your_chat_id
GUARDIAN_BASE_URL=https://guardian.yourdomain.com
GUARDIAN_DB_PASSWORD=strong_password_here
```

Start:

```bash
docker compose up -d
```

Wait 2-3 minutes (Ollama downloads AI models on first run).

### Verify

Send `/help` to your bot on Telegram. If it responds, you're done.

Add your first server:
```
/add-server myserver 1.2.3.4 22 root
```

Wait 5 minutes, then:
```
/status     → server metrics
/events     → security events
/scores     → health scores
```

### What starts automatically

- Telegram webhook registered (bot starts receiving messages)
- PostgreSQL initialized with schema
- Ollama pulls models (qwen3:4b + nomic-embed-text)
- Event collection every 2 minutes
- ML profiling and anomaly detection every hour
- Daily report at 08:00 BRT

[Full installation guide with troubleshooting →](docs/getting-started.md)

---

## Telegram (30+ commands)

| Command | What it does |
|---------|-------------|
| `/status` | All servers at a glance |
| `/block <ip>` | Block IP immediately via UFW |
| `/ask <question>` | AI-powered natural language query |
| `/events` | Recent security events |
| `/memory` | Incident memory stats (RAG) |

[All 30+ commands with examples →](docs/telegram-commands.md)

---

## Dashboard

11-page web dashboard at `https://your-domain/dashboard?token=TOKEN`

Overview · Fleet Health · Scores · Incidents · Servers · CVE · Blocks · Logs · Timeline · Attack Map · API Status

[Dashboard details →](docs/dashboard.md)

---

## Documentation

| Doc | Description |
|-----|-------------|
| [Getting Started](docs/getting-started.md) | Requirements, step-by-step install, troubleshooting |
| [Architecture](docs/architecture.md) | Pipeline diagrams, folder structure, data flow |
| [Configuration](docs/configuration.md) | All environment variables with examples |
| [Security Features](docs/security-features.md) | Detection rules, playbooks, CVE monitoring |
| [ML Intelligence](docs/ml-intelligence.md) | Behavioral baselines, scoring, resource usage |
| [RAG Memory](docs/rag-memory.md) | How Guardian learns from past incidents |
| [Telegram Commands](docs/telegram-commands.md) | All commands with usage examples |
| [Dashboard](docs/dashboard.md) | Pages, access, technical stack |

---

## Contributing

Contributions welcome! Open an issue first to discuss.

## License

[AGPL-3.0](LICENSE)
