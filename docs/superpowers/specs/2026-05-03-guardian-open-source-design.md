# Guardian Blue Team — Open-Source Design Spec

## Context

Guardian Blue Team is a ~20K-line TypeScript SIEM/SOAR agent that monitors servers via SSH, detects threats, and responds automatically or with human approval. Currently it's a private tool with AutomaBotHub coupling. This spec defines what it takes to make it a compelling standalone open-source project.

**Problem it solves:** Tools like Wazuh/OSSEC are enterprise-grade and take hours to deploy. Fail2ban only blocks IPs. CrowdSec is community-driven but has no response automation. There's nothing **lightweight, mobile-first, and response-capable** for the person managing 1-10 servers.

**Target audience:** DevOps solo operators, small startups, homelabbers — anyone managing servers who wants real security monitoring without enterprise overhead.

**Positioning:** _"Lightweight SOAR for the rest of us"_ — fits between Fail2ban (too simple) and Wazuh (too complex).

**License:** AGPLv3

---

## 1. Plugin Architecture

All extensions follow a unified interface pattern. The core loads plugins automatically from well-known directories.

### 1.1 Plugin Types

```
src/plugins/
├── notifiers/      # Alert delivery channels
│   ├── telegram.ts
│   ├── discord.ts
│   ├── slack.ts
│   ├── whatsapp.ts
│   ├── email.ts
│   ├── ntfy.ts
│   └── webhook.ts
├── detectors/      # Threat detection rules
│   ├── ssh-brute-force.ts
│   ├── crypto-mining.ts
│   ├── port-scan.ts
│   ├── container-anomaly.ts
│   └── ...
├── actions/        # Response actions
│   ├── block-ip.ts
│   ├── kill-process.ts
│   ├── update-package.ts
│   └── ...
└── enrichers/      # Threat intelligence sources
    ├── abuseipdb.ts
    ├── osv-cve.ts
    └── ...
```

### 1.2 Interfaces

```typescript
// Notifier — delivery channel for alerts
interface NotifierPlugin {
  name: string;
  enabled: boolean;
  init?(): Promise<void>;
  send(alert: FormattedAlert): Promise<void>;
  sendInteractive?(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void>;
  handleCallback?(payload: unknown): Promise<CallbackResult>;
}

// Detector — identifies threats in event streams
interface DetectorPlugin {
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  detect(events: NormalizedEvent[], buffer: NormalizedEvent[]): DetectedThreat[];
}

// Action — executes response to threats
interface ActionPlugin {
  name: string;
  description: string;
  execute(ctx: PlaybookContext, params: Record<string, unknown>): Promise<ActionResult>;
}

// Enricher — adds context to events/IPs
interface EnricherPlugin {
  name: string;
  enrich(indicator: string, type: 'ip' | 'domain' | 'hash'): Promise<EnrichmentResult>;
}
```

### 1.3 Plugin Loading

- Core scans `src/plugins/*/` at startup
- Each plugin file exports a default instance implementing its interface
- `PluginManager` registers all found plugins and exposes them to the pipeline
- Users can add custom plugins by dropping files in the directory
- Config enables/disables via env: `NOTIFIERS=telegram,discord` or `DETECTORS=all`

---

## 2. Notifier System

Replaces the current hardcoded Telegram integration with a multi-channel dispatcher.

### 2.1 Supported Channels

| Notifier | Interactive? | API/Lib | Auth |
|----------|-------------|---------|------|
| Telegram | Yes (inline buttons) | Bot API | TELEGRAM_BOT_TOKEN |
| Discord | Yes (buttons/selects) | Webhooks + Interactions | DISCORD_WEBHOOK_URL |
| Slack | Yes (Block Kit) | Webhooks + Events API | SLACK_WEBHOOK_URL |
| WhatsApp | Yes (max 3 buttons) | Evolution API / Baileys | WHATSAPP_API_URL + WHATSAPP_INSTANCE |
| Email | No (one-way) | Resend / SMTP | RESEND_API_KEY or SMTP_* vars |
| ntfy | No (push with action URLs) | ntfy.sh HTTP | NTFY_TOPIC + NTFY_SERVER |
| Webhook | No (generic POST) | fetch | WEBHOOK_URL + WEBHOOK_SECRET |

### 2.2 NotifierManager

```typescript
class NotifierManager {
  private notifiers: NotifierPlugin[] = [];

  // Dispatch to all active notifiers
  async notify(alert: FormattedAlert): Promise<void>;

  // For interactive alerts (approve/reject), uses first interactive notifier
  async notifyInteractive(alert: FormattedAlert, actions: InteractiveAction[]): Promise<void>;

  // Route callbacks from webhooks to the correct notifier
  async handleCallback(source: string, payload: unknown): Promise<CallbackResult>;
}
```

### 2.3 Config Pattern

```env
# Comma-separated list of active notifiers
NOTIFIERS=telegram,discord,email

# Each notifier has prefixed env vars
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
DISCORD_WEBHOOK_URL=...
EMAIL_SMTP_HOST=...
```

---

## 3. Mini Dashboard

Lightweight web UI served by the existing Express server. No separate frontend build.

### 3.1 Stack

- **Rendering:** Server-side HTML templates (EJS or tagged template literals)
- **Interactivity:** HTMX (1 script tag, no build step)
- **Styling:** Pico.css or similar classless CSS (~5KB)
- **Auth:** `DASHBOARD_TOKEN` env var, validated via Basic Auth or query param
- **Route:** `/dashboard` on the existing Express app (port 3334)

### 3.2 Pages

| Page | Content |
|------|---------|
| `/dashboard` | Overview: server count, open incidents, blocked IPs, pending CVEs |
| `/dashboard/incidents` | Incident list with status filters, detail view |
| `/dashboard/servers` | Server health, last-seen, active blocks per server |
| `/dashboard/cve` | CVE alerts with update/ignore buttons (via HTMX) |
| `/dashboard/blocks` | Active IP blocks with manual unblock button |
| `/dashboard/logs` | Recent security events (last 100), filterable |

### 3.3 API Routes (JSON)

```
GET  /api/dashboard/stats          — counters for overview cards
GET  /api/dashboard/incidents      — paginated incidents
GET  /api/dashboard/servers        — server list with health
GET  /api/dashboard/cve-alerts     — pending CVE alerts
POST /api/dashboard/cve/:id/update — trigger package update
POST /api/dashboard/cve/:id/ignore — ignore CVE alert
POST /api/dashboard/blocks/:id/unblock — manual unblock
```

---

## 4. AutomaBotHub Removal

Complete removal of all AutomaBotHub-specific code:

### Remove:
- `src/database/automabothub-schema.ts`
- `src/workers/abuse-detection.worker.ts`
- `src/workers/profile-builder.worker.ts`
- `src/services/ai-analyzer.service.ts`
- `src/services/instance-profile.service.ts`
- `src/services/guardian-decision.service.ts`
- All conditional `config.automabothub.enabled` checks
- `AUTOMABOTHUB_ENABLED` and `AUTOMABOTHUB_DATABASE_URL` env vars
- `guardian_` callback route in `callbacks.ts`
- AutomaBotHub re-exports from `schema.ts`

### Keep:
- All SOC pipeline code (collectors, normalizer, detector, correlator, ingestor)
- Playbook engine + all actions
- CVE monitor
- Telegram commands + callbacks (refactored into notifier plugin)
- VulnScanner, DailyReport, EventCollector, BlockCleanup workers
- Threat intel (AbuseIPDB, VirusTotal)

---

## 5. Database Flexibility

### 5.1 Dual Support

- **PostgreSQL** (default for production): `DATABASE_URL=postgres://...`
- **SQLite** (zero-config for homelab): No `DATABASE_URL` set → auto-creates `/data/guardian.db`

Drizzle ORM supports both via different drivers. Schema stays the same, only the connection adapter changes.

### 5.2 Auto-Migration

On first startup:
1. Detect database type from `DATABASE_URL` (or lack thereof)
2. Run `drizzle-kit push` equivalent programmatically
3. No manual migration step required

---

## 6. Docker & Deployment

### 6.1 One-Liner (Homelab)

```bash
docker run -d --name guardian \
  -e TELEGRAM_BOT_TOKEN=xxx \
  -e TELEGRAM_CHAT_ID=123 \
  -v guardian_data:/data \
  -p 3334:3334 \
  ghcr.io/afborda/guardian-blue-team:latest
```

Uses SQLite (`/data/guardian.db`), no external DB needed.

### 6.2 Docker Compose (Production)

```yaml
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    env_file: .env
    depends_on: [guardian-db]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
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
```

### 6.3 GitHub Container Registry

- Auto-publish on tag push (`v1.0.0`)
- Multi-arch: `linux/amd64` + `linux/arm64` (Raspberry Pi support)

---

## 7. Community & OSS Files

### 7.1 Required Files

| File | Purpose |
|------|---------|
| `LICENSE` | AGPLv3 full text |
| `CONTRIBUTING.md` | How to add plugins, run tests, submit PRs |
| `SECURITY.md` | How to report vulnerabilities privately |
| `CODE_OF_CONDUCT.md` | Contributor Covenant |
| `CHANGELOG.md` | Keep-a-changelog format |
| `.github/ISSUE_TEMPLATE/bug_report.md` | Bug report template |
| `.github/ISSUE_TEMPLATE/feature_request.md` | Feature request template |
| `.github/PULL_REQUEST_TEMPLATE.md` | PR checklist |
| `.github/workflows/ci.yml` | Test + type-check + build on PRs |
| `.github/workflows/release.yml` | Build + push Docker image on tags |

### 7.2 CONTRIBUTING.md Highlights

- "Adding a Notifier Plugin" tutorial (5-step guide)
- "Adding a Detector" tutorial
- "Adding a Response Action" tutorial
- Development setup (3 commands)
- Test expectations (every plugin has unit tests)

---

## 8. CI/CD Pipeline

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]
jobs:
  test:
    - npm ci
    - npm run type-check
    - npm run test
    - npm run build

# .github/workflows/release.yml
on:
  push:
    tags: ['v*']
jobs:
  docker:
    - Build multi-arch image
    - Push to ghcr.io/afborda/guardian-blue-team
    - Create GitHub Release with changelog
```

---

## 9. Versioning & Roadmap

| Version | Milestone |
|---------|-----------|
| v1.0.0 | Core stable: detection, playbooks, Telegram, CVE monitor, dashboard |
| v1.1.0 | Plugin system + Discord/Slack/WhatsApp notifiers |
| v1.2.0 | SQLite support + Docker one-liner without deps |
| v1.3.0 | Community playbook marketplace (GitHub-based) |
| v2.0.0 | Agentless mode (agents push to Guardian API instead of SSH pull) |
| v2.1.0 | Multi-tenant / MSP mode |

---

## 10. README Structure (Public)

```
# Guardian Blue Team

> Lightweight SOAR for the rest of us

[Badges: CI, License, Docker pulls, GitHub stars]

## What is Guardian?
[2 paragraphs + comparison table vs Wazuh/CrowdSec/Fail2ban]

## Quick Start (30 seconds)
[Docker one-liner + first Telegram message screenshot]

## Features
[Feature grid with icons]

## Architecture
[ASCII pipeline diagram]

## Configuration
[Key env vars table]

## Adding Servers
[3-step Telegram flow]

## Plugins
[How to add notifiers/detectors/actions]

## Dashboard
[Screenshot]

## Contributing
[Link to CONTRIBUTING.md]

## License
AGPLv3
```

---

## Verification

After implementation:
1. Fresh `docker run` with only TELEGRAM vars → SQLite auto-creates, bot responds
2. `docker compose up` with PostgreSQL → full production setup works
3. All 29+ tests pass
4. `npm run type-check` clean
5. Dashboard loads at `:3334/dashboard` with token auth
6. Plugin system: drop a new detector file → auto-loaded on restart
7. CI pipeline: PR triggers test + build
8. GHCR: tag push publishes multi-arch Docker image
