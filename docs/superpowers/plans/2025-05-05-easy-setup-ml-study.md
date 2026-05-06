# Guardian Blue Team — Easy Setup & ML Study Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update Gemini model to 2.5-flash, fix healthcheck bug, improve install.sh for beginners, and produce a deep ML models study document.

**Architecture:** The Guardian repo at `https://github.com/afborda/guardian-blue-team` is the source of truth. Local directory `/Users/I776289/Documents/pessoal/guardian` has a working copy that's behind the repo. Changes go to the local repo, then push to GitHub, then redeploy on Hetzner (`ssh hetzner`). The server is at `/root/.guardian` running Docker Compose.

**Tech Stack:** Node.js 20+, TypeScript, Docker, Bash (install.sh), Zod (config validation), Gemini API

---

## Task 1: Update Gemini Model Default to 2.5-flash

**Files:**
- Modify: `src/config/environment.ts` (line with `gemini-2.0-flash-001`)
- Modify: `.env.example` (line with `gemini-2.0-flash-001`)
- Modify: `install.sh` (any hardcoded model references)

- [ ] **Step 1: Update environment.ts default**

In `src/config/environment.ts`, change the Gemini model default:

```typescript
// Before
GEMINI_MODEL: z.string().default('gemini-2.0-flash-001'),

// After
GEMINI_MODEL: z.string().default('gemini-2.5-flash'),
```

- [ ] **Step 2: Update .env.example**

In `.env.example`, change:

```bash
# Before
GEMINI_MODEL=gemini-2.0-flash-001

# After
GEMINI_MODEL=gemini-2.5-flash
```

- [ ] **Step 3: Update install.sh model references**

Search `install.sh` for any hardcoded `gemini-2.0-flash-001` and replace with `gemini-2.5-flash`:

```bash
grep -n 'gemini-2.0' install.sh
# Replace all occurrences
sed -i '' 's/gemini-2.0-flash-001/gemini-2.5-flash/g' install.sh
```

- [ ] **Step 4: Update server .env**

```bash
ssh hetzner "sed -i 's/gemini-2.0-flash-001/gemini-2.5-flash/' /root/.guardian/.env"
```

- [ ] **Step 5: Verify build succeeds**

```bash
npm run type-check
```

Expected: No errors.

- [ ] **Step 6: Commit**

```bash
git add src/config/environment.ts .env.example install.sh
git commit -m "chore: update default Gemini model from 2.0-flash to 2.5-flash"
```

---

## Task 2: Fix Docker Healthcheck Inconsistency

**Files:**
- Modify: `docker-compose.yml`
- Modify: `Dockerfile` (verify consistency)

The issue: `docker-compose.yml` uses `curl -f` for healthcheck, but the GitHub repo's Dockerfile uses `wget` in HEALTHCHECK. The local Dockerfile installs `curl` — but Alpine images are smaller with just `wget`. We need to pick ONE strategy and be consistent.

**Decision:** Use `wget` everywhere (Alpine-native, no extra install needed). Remove `curl` from Dockerfile, add `wget` to healthcheck in compose.

- [ ] **Step 1: Update docker-compose.yml healthcheck**

In `docker-compose.yml`, change:

```yaml
# Before
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3334/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s

# After — remove healthcheck entirely, use Dockerfile's built-in HEALTHCHECK
```

Remove the `healthcheck:` block from `docker-compose.yml` since the `Dockerfile` already defines `HEALTHCHECK` with `wget`. Docker Compose should not override it.

- [ ] **Step 2: Update Dockerfile to use wget (remove curl dependency)**

```dockerfile
# Before
RUN apk add --no-cache curl docker-cli openssh-client

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:3334/health || exit 1

# After
RUN apk add --no-cache openssh-client

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=30s \
  CMD wget -q --spider http://localhost:3334/health || exit 1
```

Note: `docker-cli` is also removed — Guardian uses the Docker socket directly via `dockerode` (Node.js library), it doesn't need the CLI binary.

- [ ] **Step 3: Verify docker-compose.yml is clean**

Final `docker-compose.yml` should look like:

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
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ${SSH_KEY_DIR:-~/.ssh}:/home/node/.ssh:ro
    networks:
      - guardian-internal
      - traefik-public
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=traefik-public"
      - "traefik.http.routers.guardian.rule=Host(`${GUARDIAN_DOMAIN:-guardian.localhost}`)"
      - "traefik.http.routers.guardian.entrypoints=websecure"
      - "traefik.http.routers.guardian.tls.certresolver=letsencrypt"
      - "traefik.http.services.guardian.loadbalancer.server.port=3334"

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
    networks:
      - guardian-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian -d guardian"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  guardian_pgdata:

networks:
  guardian-internal:
    driver: bridge
  traefik-public:
    external: true
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml Dockerfile
git commit -m "fix: use wget for healthcheck, remove curl/docker-cli deps from image"
```

---

## Task 3: Sync Local environment.ts with Repo Version

**Files:**
- Modify: `src/config/environment.ts` (replace entirely with repo version)

The local `src/config/environment.ts` is missing ~15 fields that exist in the GitHub repo. The repo version (read from server) is the source of truth.

- [ ] **Step 1: Replace environment.ts with repo version**

Replace the entire contents of `src/config/environment.ts` with the version from the GitHub repo, with the Gemini model already updated to `gemini-2.5-flash`:

```typescript
import { z } from 'zod';

const envSchema = z.object({
  PORT: z.string().transform(Number).default('3334'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  DATABASE_URL: z.string().optional(),

  // Notifications
  NOTIFIERS: z.string().default('telegram'),

  // Docker
  DOCKER_HOST: z.string().optional(),

  // Telegram
  TELEGRAM_BOT_TOKEN: z.string().min(1, 'TELEGRAM_BOT_TOKEN is required'),
  TELEGRAM_CHAT_ID: z.string().min(1, 'TELEGRAM_CHAT_ID is required'),
  TELEGRAM_WEBHOOK_SECRET: z.string().optional(),

  // AI — Gemini
  GEMINI_API_KEY: z.string().optional(),
  GEMINI_MODEL: z.string().default('gemini-2.5-flash'),

  // AI — OpenAI
  OPENAI_API_KEY: z.string().optional(),
  OPENAI_MODEL: z.string().default('gpt-4o-mini'),

  // AI — Claude
  ANTHROPIC_API_KEY: z.string().optional(),
  ANTHROPIC_MODEL: z.string().default('claude-sonnet-4-6-20250514'),

  // AI — Ollama
  OLLAMA_URL: z.string().default('http://localhost:11434'),
  OLLAMA_MODEL: z.string().default('qwen3:4b'),
  OLLAMA_CHAT_MODEL: z.string().default('qwen3:0.6b'),

  // AI — Provider preference
  AI_PROVIDER: z.enum(['gemini', 'openai', 'claude', 'ollama', 'auto']).default('auto'),

  // Email
  RESEND_API_KEY: z.string().optional(),

  // Abuse detection
  ABUSE_CONFIDENCE_THRESHOLD: z.string().transform(Number).default('70'),

  // Health
  UPTIME_KUMA_PUSH_URL: z.string().optional(),

  // Host Security SSH
  HOST_SSH_HOST: z.string().default('127.0.0.1'),
  HOST_SSH_PORT: z.string().transform(Number).default('22'),
  HOST_SSH_USER: z.string().default('ubuntu'),
  HOST_SSH_KEY_PATH: z.string().optional(),

  // Security — Trusted entities
  TRUSTED_IPS: z.string().default(''),
  TRUSTED_FINGERPRINTS: z.string().default(''),

  // Threat Intelligence
  ABUSEIPDB_API_KEY: z.string().optional(),
  VIRUSTOTAL_API_KEY: z.string().optional(),

  // CVE Monitor
  CVE_MONITOR_ENABLED: z.string().transform(v => v !== 'false').default('true'),
  CVE_MONITOR_MIN_CVSS: z.string().transform(Number).default('7.0'),
  CVE_MONITOR_INTERVAL_HOURS: z.string().transform(Number).default('6'),
});

const env = envSchema.parse(process.env);

export const config = {
  server: {
    port: env.PORT,
    nodeEnv: env.NODE_ENV,
  },

  database: {
    url: env.DATABASE_URL || null,
    isSqlite: !env.DATABASE_URL || env.DATABASE_URL.startsWith('sqlite:'),
  },

  notifiers: env.NOTIFIERS.split(',').map(s => s.trim()).filter(Boolean),

  telegram: {
    botToken: env.TELEGRAM_BOT_TOKEN,
    chatId: env.TELEGRAM_CHAT_ID,
    webhookSecret: env.TELEGRAM_WEBHOOK_SECRET,
  },

  ai: {
    provider: env.AI_PROVIDER,
    geminiApiKey: env.GEMINI_API_KEY || null,
    geminiModel: env.GEMINI_MODEL,
    openaiApiKey: env.OPENAI_API_KEY || null,
    openaiModel: env.OPENAI_MODEL,
    anthropicApiKey: env.ANTHROPIC_API_KEY || null,
    anthropicModel: env.ANTHROPIC_MODEL,
    ollamaUrl: env.OLLAMA_URL,
    ollamaModel: env.OLLAMA_MODEL,
    ollamaChatModel: env.OLLAMA_CHAT_MODEL,
  },

  resend: {
    apiKey: env.RESEND_API_KEY || null,
    fromEmail: 'Guardian <noreply@guardian.local>',
  },

  abuse: {
    confidenceThreshold: env.ABUSE_CONFIDENCE_THRESHOLD,
  },

  health: {
    uptimeKumaPushUrl: env.UPTIME_KUMA_PUSH_URL || null,
  },

  hostSecurity: {
    sshHost: env.HOST_SSH_HOST,
    sshPort: env.HOST_SSH_PORT,
    sshUser: env.HOST_SSH_USER,
    sshKeyPath: env.HOST_SSH_KEY_PATH || null,
  },

  security: {
    trustedIps: env.TRUSTED_IPS.split(',').map(s => s.trim()).filter(Boolean),
    trustedFingerprints: env.TRUSTED_FINGERPRINTS.split(',').map(s => s.trim()).filter(Boolean),
  },

  threatIntel: {
    abuseIpDbKey: env.ABUSEIPDB_API_KEY || null,
    virusTotalKey: env.VIRUSTOTAL_API_KEY || null,
  },

  cveMonitor: {
    enabled: env.CVE_MONITOR_ENABLED,
    minCvss: env.CVE_MONITOR_MIN_CVSS,
    checkIntervalHours: env.CVE_MONITOR_INTERVAL_HOURS,
  },
} as const;

export type Config = typeof config;
```

- [ ] **Step 2: Fix any type errors in dependent files**

Run `npm run type-check` and fix any references to old config shape (e.g., files that reference `config.database.url` as non-null when it's now nullable, or missing `config.security`, `config.cveMonitor`, etc.).

- [ ] **Step 3: Commit**

```bash
git add src/config/environment.ts
git commit -m "feat: sync environment.ts with repo — add AI_PROVIDER, CVE, security fields"
```

---

## Task 4: Improve install.sh for Beginners

**Files:**
- Modify: `install.sh`

The install.sh is already 895 lines and functional. Improvements are targeted:

- [ ] **Step 1: Fix hardcoded Gemini model in install.sh**

Find and replace all instances of `gemini-2.0-flash-001` with `gemini-2.5-flash`:

```bash
grep -n 'gemini-2.0' install.sh
```

Replace each occurrence.

- [ ] **Step 2: Fix healthcheck in generated docker-compose**

In the install.sh script, the generated `docker-compose.yml` templates should NOT include a `healthcheck:` block for the Guardian container (it's in the Dockerfile). Search for any `curl -f http://localhost:3334/health` in the script and remove those healthcheck blocks from generated compose files.

- [ ] **Step 3: Add post-install validation**

After the `docker compose up -d` section (around line 800), add a validation block:

```bash
# ─── Post-install validation ────────────────────────────────────────────────────
echo ""
info "Validating installation..."

# Wait for health
ATTEMPTS=0
MAX_ATTEMPTS=12
while [[ $ATTEMPTS -lt $MAX_ATTEMPTS ]]; do
  if wget -qO- http://localhost:3334/health 2>/dev/null | grep -q '"status":"ok"'; then
    success "Guardian is healthy!"
    break
  fi
  ATTEMPTS=$((ATTEMPTS + 1))
  sleep 5
done

if [[ $ATTEMPTS -ge $MAX_ATTEMPTS ]]; then
  warn "Guardian is still starting. Check logs: docker compose logs -f"
fi

# Test Telegram
info "Testing Telegram bot..."
TELEGRAM_RESP=$(curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
  -d "chat_id=${TELEGRAM_CHAT_ID}" \
  -d "text=🛡️ Guardian Blue Team installed successfully on $(hostname)!" \
  -d "parse_mode=HTML" 2>/dev/null)
if echo "$TELEGRAM_RESP" | grep -q '"ok":true'; then
  success "Telegram notification sent! Check your chat."
else
  warn "Could not send Telegram test message. Verify your token and chat ID."
fi
```

- [ ] **Step 4: Add --upgrade flag support**

After the `--uninstall` handling block (around line 90), add:

```bash
if [[ "${1:-}" == "--upgrade" ]]; then
  banner
  INSTALL_DIR="${HOME}/.guardian"
  if [[ ! -d "$INSTALL_DIR" ]]; then
    error "Guardian not found at $INSTALL_DIR — install first."
    exit 1
  fi

  info "Upgrading Guardian..."
  cd "$INSTALL_DIR"

  # Pull latest image
  if docker compose pull 2>/dev/null; then
    success "Latest image pulled"
  else
    # If using build mode, pull latest code
    if [[ -d .git ]]; then
      git pull --ff-only 2>/dev/null && success "Code updated" || warn "Git pull failed"
    fi
  fi

  # Rebuild and restart
  docker compose up -d --build 2>/dev/null || docker compose up -d
  
  # Wait for health
  sleep 10
  if docker compose ps --format '{{.State}}' 2>/dev/null | grep -q "running"; then
    success "Guardian upgraded and running!"
  else
    warn "Check status: docker compose ps"
  fi
  exit 0
fi
```

- [ ] **Step 5: Commit**

```bash
git add install.sh
git commit -m "feat: improve install.sh — gemini 2.5, post-install validation, --upgrade flag"
```

---

## Task 5: Write Deep ML Models Study Document

**Files:**
- Create: `docs/ml-models-study.md`

This is a research document. It requires querying current pricing/capabilities of models.

- [ ] **Step 1: Research current model pricing and capabilities**

Gather data on:
- Gemini 2.5 Flash pricing (free tier: 1500 req/day, paid: $0.075/1M input)
- GPT-4o-mini pricing ($0.15/1M input, $0.60/1M output)
- Claude Haiku 3.5 pricing ($0.80/1M input, $4/1M output)
- Gemini 2.5 Pro pricing ($1.25/1M input, $10/1M output)
- Local model requirements (RAM/VRAM for Qwen3 4B, Phi-4, etc.)

- [ ] **Step 2: Write the ML study document**

Create `docs/ml-models-study.md` with the following structure:

```markdown
# Guardian Blue Team — AI/ML Models Study

## Executive Summary
[2-3 paragraphs: current state, recommended architecture, key findings]

## 1. Guardian's AI Tasks
[Table of all tasks, their characteristics, frequency, latency requirements]

## 2. Model Evaluation

### 2.1 Cloud LLMs — Fast Tier
[Gemini 2.5 Flash, GPT-4o-mini, Claude Haiku 3.5]
[Benchmark per task, cost analysis, latency]

### 2.2 Cloud LLMs — Deep Analysis
[Gemini 2.5 Pro, GPT-4o, Claude Sonnet 4.6]
[When to use, cost justification]

### 2.3 Local LLMs — Offline Fallback
[Qwen3 4B, Phi-4 Mini, Llama 3.2 3B, Mistral 7B, Gemma 2 9B]
[RAM requirements, quality comparison, deployment]

### 2.4 Classical ML — Ultra-Fast Detection
[Isolation Forest, XGBoost, LSTM]
[Use cases within Guardian, training data requirements]

### 2.5 Embeddings & RAG
[Nomic Embed, BGE-M3, Gemini Embedding]
[How to use for log correlation and threat intel]

## 3. Cost Analysis
[Table: model × monthly cost at 1000/10000/100000 events]

## 4. Recommended Architecture
[4-layer pipeline diagram and explanation]

## 5. Implementation Roadmap
[Short/Medium/Long term phases with specific deliverables]

## 6. Appendix: Benchmark Methodology
[How evaluations were conducted]
```

- [ ] **Step 3: Commit**

```bash
git add docs/ml-models-study.md
git commit -m "docs: add deep ML models study for Guardian AI pipeline"
```

---

## Task 6: Deploy Changes to Hetzner Server

**Files:** None (deployment commands only)

- [ ] **Step 1: Push all changes to GitHub**

```bash
git push origin main
```

- [ ] **Step 2: Pull changes on server**

```bash
ssh hetzner "cd /root/.guardian && git pull"
```

- [ ] **Step 3: Rebuild and restart**

```bash
ssh hetzner "cd /root/.guardian && docker compose up -d --build"
```

- [ ] **Step 4: Verify health**

```bash
ssh hetzner "sleep 30 && docker ps --format 'table {{.Names}}\t{{.Status}}' | grep guardian"
```

Expected: Both containers show `(healthy)`.

- [ ] **Step 5: Verify Gemini model is active**

```bash
ssh hetzner "docker logs guardian --tail 5 2>&1 | grep -i gemini"
```

Or send `/status` via Telegram to confirm Guardian is responding.

---

## Task 7: Update README Quick Start Section

**Files:**
- Modify: `README.md` (quick start section)
- Modify: `README.pt-BR.md` (Portuguese version)

- [ ] **Step 1: Verify README already has quick start**

The README already has a Quick Start section with the one-liner. Verify it's correct and the model reference is updated. If the README mentions `gemini-2.0-flash-001` anywhere, update it to `gemini-2.5-flash`.

```bash
grep -n 'gemini-2.0' README.md README.pt-BR.md
```

- [ ] **Step 2: Update any stale model references in READMEs**

Replace all occurrences found.

- [ ] **Step 3: Commit**

```bash
git add README.md README.pt-BR.md
git commit -m "docs: update model references to gemini-2.5-flash in READMEs"
```
