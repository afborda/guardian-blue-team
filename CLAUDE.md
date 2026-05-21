# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev          # tsx watch src/index.ts (hot-reload)
npm run build        # tsup → dist/ (ESM + .d.ts)
npm run start        # node dist/index.js (production)
npm run test         # vitest run (all tests)
npm run test:watch   # vitest (interactive watch)
npm run lint         # eslint src/
npm run type-check   # tsc --noEmit

# ML / data utilities
npm run reembed-incidents   # re-vectorize incident_memory with current bge-m3 model
npm run train-dga           # python3 scripts/train_dga.py (generates ONNX DGA classifier)
```

To run a single test file:
```bash
npx vitest run tests/detector.test.ts
```

## Architecture

Guardian is an agentless SIEM/SOAR: it SSHes into monitored servers (read-only), processes their logs through a multi-stage pipeline, and responds automatically via firewall rules + Telegram alerts.

### Startup sequence (`src/index.ts`)
1. `initDatabase()` — creates all tables/indexes idempotently (no migration runner needed)
2. `registerBuiltinPlugins()` + `PluginManager.loadNotifiers()` — activate notification channels
3. `PlaybookRegistry.init()` + `ThreatIntelManager.start()` + `loadTrustedEntities()`
4. Express server listens (default port 3334)
5. Telegram webhook registered against `GUARDIAN_BASE_URL`
6. All 13 workers started; graceful shutdown reverses this via `Promise.allSettled`

### Security pipeline (`src/pipeline/`)
Events flow sequentially through five stages:
```
Collectors (SSH) → Normalizer → Detector (15+ rules) → Enricher (TI + ML) → Correlator → Playbook Engine
```
- **Normalizer**: parses raw log lines into `NormalizedEvent` structs
- **Detector**: applies detection rules; outputs `DetectedEvent[]`
- **Enricher**: calls AbuseIPDB/VirusTotal, scores via ML behavior profiles
- **Correlator**: groups events into incidents (same IP + same category = same incident)
- **PlaybookEngine** (`src/playbooks/engine.ts`): executes `PlaybookDefinition` steps against a `PlaybookContext`; actions are registered via `PlaybookEngine.registerAction(name, fn)`

### Workers (`src/workers/`)
All workers implement `start()` / `stop()`. Intervals from README:
- `EventCollectorWorker` — 2 min (main collection loop)
- `ScoreCalculatorWorker` — 5 min metrics / 1 h scores
- `DDoSEscalationWorker` — 2 min (rate-limit → block escalation)
- `IntelligenceWorker` — 1 h (ML profiling + anomaly + trends)
- `FIMWorker` — 4 h (file integrity baseline compare)
- `ThreatHunterWorker` — 4 h (proactive AI pattern analysis)
- `CVEMonitorWorker` — 6 h (OSV.dev package scan)
- `CVEIntelFeedsWorker` — on schedule (EPSS + CISA KEV sync)
- `VulnScannerWorker` — weekly
- `DailyReportWorker` — 08:00 BRT
- `BlockCleanupWorker`, `MetricsRetentionWorker`, `DiscoveryWorker`

### Intelligence layer (`src/intelligence/`)
- `anomaly-detector.ts` — STL decomposition (trend + seasonal + residual) on metrics; falls back to z-score when no period detectable
- `dga-classifier.ts` — ONNX logistic regression with 11 features (bigram log-likelihood etc.); falls back to entropy heuristic if `onnxruntime-node` is not installed (optional dep)
- `markov-user-profile.service.ts` — Markov chain on sudo command sequences; backed by `user_command_transitions` materialized view
- `ssh-behavior.ts` / `container-behavior.ts` — per-subject behavioral profiles in `behavior_profiles` table

### AI layer (`src/services/ai-provider.ts`)
Multi-provider with local-first strategy. Call order in `auto` mode: Ollama (120 s timeout) → Gemini → OpenAI → Claude. Controlled by `AI_STRATEGY` (`auto` | `local-only` | `api-only`) and `AI_PROVIDER`. Falls back to rule-based blocking when all providers fail.

### Database (`src/database/connection.ts`)
Supports **PostgreSQL** (production) and **SQLite** (dev/no-infrastructure). Selection is automatic: `DATABASE_URL` absent or `sqlite:` prefix → SQLite; otherwise PostgreSQL.

Schema is DDL-in-code: `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`. No migration runner. The `db` export is a lazy proxy — must call `initDatabase()` before use.

Compatibility helpers to abstract over engine differences:
- `dbTrue` / `dbFalse` — `1`/`0` on SQLite, `true`/`false` on PostgreSQL
- `dbNow()` / `dbDate(d)` — ISO string on SQLite, `Date` on PostgreSQL

Materialized views (`user_command_transitions`, `user_command_thresholds`) exist only in PostgreSQL; the intelligence worker refreshes them manually.

### Plugins / Notifiers (`src/plugins/`)
Notification channels (Telegram, Discord, Slack, Email, WhatsApp, ntfy, Webhook) are plugins loaded at startup via `NOTIFIERS` env var. `PluginManager` dispatches through all active notifiers. Each plugin implements the `NotifierPlugin` interface from `src/plugins/types.ts`.

### Dashboard (`src/dashboard/`)
Server-side rendered with HTMX templates. 12 pages accessible at `/dashboard?token=TOKEN`. Auth via `DASHBOARD_TOKEN` (single token) or `DASHBOARD_USERS` (`user:token:role;...` format). Routes split into `dashboardPages` (HTML) and `dashboardApi` (JSON).

## Key env vars

| Var | Required | Notes |
|-----|----------|-------|
| `TELEGRAM_BOT_TOKEN` | Yes | |
| `TELEGRAM_CHAT_ID` | Yes | |
| `GUARDIAN_BASE_URL` | Yes | HTTPS public URL for webhook registration |
| `DATABASE_URL` | No | Defaults to SQLite at `./data/guardian.db` |
| `DASHBOARD_TOKEN` | No | Single-token dashboard access |
| `DASHBOARD_USERS` | No | Multi-user: `user:token:role;...` (roles: admin/operator/viewer) |
| `AI_STRATEGY` | No | `auto` (default) / `local-only` / `api-only` |
| `OLLAMA_URL` | No | Default `http://localhost:11434` |
| `GEMINI_API_KEY` | No | Free tier works; used as Ollama fallback |
| `ABUSEIPDB_API_KEY` | No | IP enrichment (1000 free/day) |
| `FALCO_WEBHOOK_TOKEN` | No | Must be base64 (no single quotes); enables `/webhook/falco` |
| `TRUSTED_IPS` | No | Comma-separated IPs exempt from all rules |

## Testing

Tests live in `tests/`. The `tests/setup.ts` mocks `config`, `db`, and `logger` globally — tests run without a real database or Telegram connection. Coverage is configured for `src/pipeline/**` and `src/playbooks/**`.

The DGA classifier test (`dga-classifier.test.ts`) and STL test (`stl.test.ts`) exercise the pure ML/math logic and have no external deps.
