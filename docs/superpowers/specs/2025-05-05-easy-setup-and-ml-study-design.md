# Guardian Blue Team — Easy Setup & ML Models Study

**Date:** 2025-05-05  
**Status:** Approved  
**Scope:** Improve installation UX, fix bugs, update AI models, and research ML alternatives

---

## 1. Problem Statement

Guardian Blue Team has a working `install.sh` but the overall setup experience has friction:
- `docker-compose.yml` healthcheck uses `curl` but the Alpine container only has `wget`
- Default Gemini model (`gemini-2.0-flash-001`) is outdated — 2.5 Flash is available
- `src/config/environment.ts` is missing ~15 fields that exist in the repo's `.env.example`
- No clear "copy one command and it works" experience in README

Additionally, no formal analysis exists of which ML/LLM models are optimal for each Guardian task.

---

## 2. Fixes (Immediate)

### 2.1 Gemini Model Update

| Location | Old | New |
|----------|-----|-----|
| `src/config/environment.ts` | `gemini-2.0-flash-001` | `gemini-2.5-flash` |
| `.env.example` | `gemini-2.0-flash-001` | `gemini-2.5-flash` |
| Server `.env` | `gemini-2.0-flash-001` | `gemini-2.5-flash` |

### 2.2 Healthcheck Fix

`docker-compose.yml` healthcheck:
```yaml
# Before (broken — curl not in Alpine)
test: ["CMD", "curl", "-f", "http://localhost:3334/health"]

# After (wget is available in Alpine)
test: ["CMD", "wget", "-q", "--spider", "http://localhost:3334/health"]
```

### 2.3 Environment Config Sync

Add missing fields to `src/config/environment.ts`:
- `AI_PROVIDER` (enum: gemini | openai | claude | ollama | auto)
- `OPENAI_API_KEY`, `OPENAI_MODEL`
- `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`
- `CVE_MONITOR_ENABLED`, `CVE_MONITOR_MIN_CVSS`, `CVE_MONITOR_INTERVAL_HOURS`
- `TRUSTED_IPS`, `TRUSTED_FINGERPRINTS`
- `GUARDIAN_DOMAIN`, `GUARDIAN_DB_PASSWORD`
- `SSH_KNOWN_HOSTS`
- `DISCORD_WEBHOOK_URL`, `SLACK_WEBHOOK_URL`
- `NTFY_SERVER`, `NTFY_TOPIC`
- `WEBHOOK_URL`, `WEBHOOK_SECRET`
- `WHATSAPP_API_URL`, `WHATSAPP_INSTANCE`, `WHATSAPP_NUMBER`

---

## 3. Install.sh — "One-Curl Magic"

### 3.1 Philosophy

A complete beginner should:
1. Run ONE command
2. Answer 2 questions (Telegram token + Chat ID)
3. Have a working Guardian monitoring their server in under 2 minutes

### 3.2 Current State (what's already good)

The existing `install.sh` (895 lines) already:
- Detects OS and installs Docker if missing
- Auto-detects Traefik and generates routing
- Generates SSH keys
- Creates `.env` and `docker-compose.yml`
- Supports `--uninstall`
- Supports non-interactive mode via env vars

### 3.3 Improvements Needed

| Issue | Fix |
|-------|-----|
| Healthcheck in generated compose uses `curl` | Switch to `wget` |
| Model hardcoded as `gemini-2.0-flash-001` | Use `gemini-2.5-flash` |
| No post-install validation | Add health + Telegram test |
| Generated compose differs from repo compose | Unify strategy |
| No `--upgrade` flag | Add in-place upgrade path |
| Error messages are generic | Add specific remediation steps |

### 3.4 Post-Install Validation Steps

After `docker compose up -d`, the script should:
1. Wait for container health (max 60s with spinner)
2. Hit `/health` endpoint to confirm app is running
3. Send a test Telegram message to confirm bot token works
4. Test SSH to localhost to confirm server monitoring works
5. Print a clear success summary with dashboard URL

### 3.5 Upgrade Flow

```bash
bash <(curl -fsSL .../install.sh) --upgrade
```

This should:
1. Pull latest image
2. Preserve `.env` and `keys/`
3. `docker compose up -d` with new image
4. Verify health

---

## 4. README One-Liner

Add to top of README.md:

```markdown
## Quick Start (< 2 minutes)

\`\`\`bash
bash <(curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh)
\`\`\`

You'll need: a Telegram bot token (@BotFather) and your chat ID (@userinfobot).
Guardian handles the rest — Docker, database, SSH keys, HTTPS.
```

---

## 5. ML Models Study — Deep Analysis

### 5.1 Guardian's Analysis Tasks

| # | Task | Type | Current | Frequency |
|---|------|------|---------|-----------|
| 1 | SSH log analysis (brute force, suspicious login) | Classification | Gemini 2.0 Flash | Every 2min |
| 2 | IP block decision (autonomous response) | Decision/Reasoning | Gemini 2.0 Flash | Per event |
| 3 | SOC Analyst (interactive chat) | Conversational | Gemini 2.0 Flash | On demand |
| 4 | CVE relevance scoring | NER + Scoring | Static rules | Every 6h |
| 5 | Daily security report | Summarization | Gemini 2.0 Flash | Daily |
| 6 | Threat intelligence correlation | RAG/Analysis | Gemini 2.0 Flash | Every 1h |
| 7 | File integrity monitoring (FIM) | Anomaly Detection | Deterministic diff | Every 4h |

### 5.2 Model Categories to Evaluate

#### A) Cloud LLMs — Primary (fast, cheap)
- **Gemini 2.5 Flash** — Best free tier, good reasoning, 1M context
- **GPT-4o-mini** — Strong at structured output, cheap
- **Claude Haiku 3.5** — Fast, good at security domain

#### B) Cloud LLMs — Deep Analysis (complex reasoning)
- **Gemini 2.5 Pro** — Extended thinking, best for complex correlation
- **GPT-4o** — Strong general reasoning
- **Claude Sonnet 4.6** — Excellent at security analysis

#### C) Local LLMs — Offline Fallback
- **Qwen3 4B** — Current fallback, good multilingual
- **Llama 3.2 3B** — Meta's efficient small model
- **Phi-4 Mini 3.8B** — Microsoft, strong reasoning for size
- **Mistral 7B** — Proven reliability
- **Gemma 2 9B** — Google, strong at structured tasks

#### D) ML Clássico — Ultra-fast Detection
- **Isolation Forest** — Anomaly detection without labels
- **XGBoost** — Classification with feature engineering
- **LSTM/GRU** — Sequential log pattern recognition
- **Autoencoders** — Behavioral baseline deviation

#### E) Embeddings + RAG
- **Nomic Embed v1.5** — Open source, runs locally
- **BGE-M3** — Multilingual, good for log similarity
- **Gemini Embedding** — API-based, high quality
- **text-embedding-3-small** — OpenAI, cheap and fast

### 5.3 Evaluation Criteria

For each model × task combination:
1. **Accuracy** — Correct threat identification rate (precision/recall)
2. **Latency** — Time from input to decision (p50, p95)
3. **Cost** — USD per 1000 analyses
4. **Privacy** — Does data leave the server?
5. **Availability** — Works offline? Free tier limits?
6. **Context window** — Can it handle large log batches?

### 5.4 Recommended Architecture (hypothesis to validate)

```
┌─────────────────────────────────────────────────────────┐
│                    Guardian AI Pipeline                   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Layer 1: Fast Filter (< 10ms)                          │
│  ├── Regex rules (known patterns)                       │
│  ├── IP reputation cache                                │
│  └── Isolation Forest (anomaly score)                   │
│                                                          │
│  Layer 2: Local LLM (< 2s, if Layer 1 uncertain)       │
│  ├── Qwen3 4B / Phi-4 Mini                             │
│  └── Structured output: {threat: bool, confidence: N}   │
│                                                          │
│  Layer 3: Cloud LLM (< 5s, if Layer 2 low confidence)  │
│  ├── Gemini 2.5 Flash (primary)                         │
│  ├── GPT-4o-mini (fallback)                             │
│  └── Full reasoning + recommendation                    │
│                                                          │
│  Layer 4: Deep Analysis (on-demand)                     │
│  ├── Gemini 2.5 Pro / Claude Sonnet                    │
│  └── Used for: SOC chat, complex correlation            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### 5.5 Deliverable

A document `docs/ml-models-study.md` containing:
- Benchmark results for each model × task
- Cost analysis (per 1000 events at different volumes)
- Latency measurements
- Recommendation per task
- Implementation roadmap (short/medium/long term)
- Migration path from current single-model to multi-layer

### 5.6 Roadmap

| Phase | Timeline | What |
|-------|----------|------|
| **Now** | Immediate | Switch to Gemini 2.5 Flash |
| **Short** | 1-2 weeks | Add AI_PROVIDER auto-fallback chain |
| **Medium** | 1 month | Add Layer 1 (regex + Isolation Forest for fast filter) |
| **Long** | 2-3 months | Full 4-layer pipeline with local LLM |

---

## 6. Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `src/config/environment.ts` | Modify | Add missing env vars |
| `.env.example` | Modify | Update model to 2.5-flash |
| `docker-compose.yml` | Modify | Fix healthcheck |
| `install.sh` | Modify | Improve UX, fix model, add --upgrade |
| `README.md` | Modify | Add one-liner quick start |
| `docs/ml-models-study.md` | Create | Full ML analysis document |

---

## 7. Success Criteria

- [ ] A user with zero Docker knowledge can install Guardian in < 2 minutes
- [ ] `gemini-2.5-flash` is the default model everywhere
- [ ] Healthcheck reports `healthy` without needing manual fixes
- [ ] `environment.ts` validates all fields from `.env.example`
- [ ] ML study document is comprehensive enough to guide next 3 months of AI development
