# Guardian Blue Team

> Lightweight SOAR for the rest of us

[![CI](https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg)](https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

Guardian is a lightweight SIEM/SOAR agent that monitors your servers via SSH, detects threats in real-time, and responds automatically or with your approval. Built for DevOps solo operators, small startups, and homelabbers who want real security monitoring without enterprise overhead.

## Comparison

| Feature | Fail2ban | CrowdSec | Wazuh | **Guardian** |
|---------|----------|----------|-------|--------------|
| Setup time | 5 min | 30 min | 2+ hours | **30 seconds** |
| Response actions | Block IP | Block IP | Scripts | **Playbooks + approval** |
| Notifications | Email | — | Email | **Telegram, Discord, Slack, WhatsApp, ntfy, Email, Webhook** |
| CVE monitoring | — | — | Yes | **Yes (OSV.dev)** |
| Dashboard | — | Web | Web | **Lightweight HTMX** |
| Mobile-first | — | — | — | **Yes (Telegram/WhatsApp)** |
| Resource usage | Minimal | Low | High | **Low (~50MB RAM)** |

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

## Features

- **Real-time threat detection** — SSH brute force, crypto mining, port scans, unauthorized logins
- **Automated response** — Block IPs via UFW, kill processes, with human approval when needed
- **CVE monitoring** — Scans installed packages against OSV.dev, notifies with one-click update
- **Multi-channel notifications** — Telegram, Discord, Slack, WhatsApp, Email, ntfy, Webhook
- **Plugin system** — Add custom notifiers, detectors, and response actions
- **Mini dashboard** — HTMX-powered web UI at `:3334/dashboard`
- **AI-powered analysis** — Natural language SOC analyst via Gemini/Ollama
- **Playbooks** — Configurable response workflows with approval gates

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Guardian Core                       │
├──────────┬────────────┬──────────────┬───────────────┤
│ Collector│  Detector  │  Correlator  │   Playbook    │
│  (SSH)   │  (Rules)   │ (Incidents)  │   Engine      │
├──────────┴────────────┴──────────────┴───────────────┤
│                Plugin System                          │
├──────────┬──────────┬──────────┬─────────────────────┤
│ Notifiers│ Detectors│ Actions  │     Enrichers       │
└──────────┴──────────┴──────────┴─────────────────────┘
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | — | Telegram Bot API token |
| `TELEGRAM_CHAT_ID` | Yes | — | Authorized chat ID |
| `DATABASE_URL` | No | SQLite | PostgreSQL connection string |
| `NOTIFIERS` | No | `telegram` | Comma-separated: telegram,discord,slack,whatsapp,email,ntfy,webhook |
| `DASHBOARD_TOKEN` | No | — | Token for web dashboard access |
| `CVE_MONITOR_MIN_CVSS` | No | `7.0` | Minimum CVSS score to alert |

See `.env.example` for all options.

## Production Setup (Docker Compose)

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

  guardian-db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

## Adding Servers

Via Telegram:
```
/add-server myserver 192.168.1.100 22 ubuntu /home/node/.ssh/id_ed25519
```

## Plugins

Drop a file in `src/plugins/notifiers/` implementing `NotifierPlugin` and register it. See [CONTRIBUTING.md](CONTRIBUTING.md) for a step-by-step guide.

## Dashboard

Access at `http://your-server:3334/dashboard?token=YOUR_DASHBOARD_TOKEN`

Pages: Overview, Incidents, Servers, CVE Alerts, IP Blocks, Security Logs.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, plugin tutorials, and PR guidelines.

## License

[AGPL-3.0](LICENSE) — if you modify Guardian and offer it as a service, you must share your changes.
