# Guardian Blue Team — AI/ML Models Study

**Date:** 2025-05-05  
**Purpose:** Deep analysis of AI/ML models for Guardian's security analysis pipeline  
**Current State:** Single-provider (Gemini 2.0 Flash) with Ollama fallback  
**Target State:** Multi-layer intelligent pipeline optimized for cost, latency, and accuracy

---

## Executive Summary

Guardian currently uses Gemini 2.0 Flash (now upgraded to 2.5 Flash) for ALL AI tasks — from simple log classification to complex threat correlation. This is effective but sub-optimal: we pay cloud API costs for trivial decisions that could be handled locally, and we lack the deep reasoning capabilities needed for complex incident correlation.

**Key Recommendation:** Implement a 4-layer cascade architecture where 80%+ of events are handled by fast local rules (Layer 1), 15% by a local LLM (Layer 2), and only 5% reach cloud APIs (Layer 3/4). This reduces costs by ~90% while improving response time for common threats.

**Immediate wins:**
1. Gemini 2.5 Flash (done) — better reasoning, same cost
2. Add GPT-4o-mini as failover — resilience against single-provider outages
3. Isolation Forest for anomaly pre-scoring — eliminates 80% of false-positive AI calls

---

## 1. Guardian's AI Tasks

| # | Task | Type | Frequency | Latency Req. | Complexity | Current Provider |
|---|------|------|-----------|-------------|-----------|-----------------|
| 1 | SSH brute force detection | Classification | Every 2 min | < 5s | Low | Gemini Flash |
| 2 | Unauthorized login analysis | Classification + Decision | Per event | < 3s | Medium | Gemini Flash |
| 3 | IP block decision (autonomous) | Reasoning + Action | Per threat | < 10s | High | Gemini Flash |
| 4 | SOC Analyst (interactive chat) | Conversational | On demand | < 15s | High | Gemini Flash |
| 5 | Daily security report | Summarization | Daily | < 60s | Medium | Gemini Flash |
| 6 | CVE relevance scoring | NER + Scoring | Every 6h | < 30s | Low | Static rules |
| 7 | Threat intel correlation | RAG + Analysis | Every 1h | < 30s | High | Gemini Flash |
| 8 | Anomaly detection (baseline) | Statistical | Every 5 min | < 1s | Low | Deterministic |
| 9 | Resource exhaustion prediction | Regression | Every 1h | < 5s | Low | Linear regression |
| 10 | Playbook action generation | Planning | Per incident | < 20s | High | Gemini Flash |

### Observations:
- Tasks 1, 2, 6, 8, 9 are **low complexity** — deterministic rules or simple ML can handle them
- Tasks 3, 4, 7, 10 are **high complexity** — genuinely need LLM reasoning
- Task 5 is **medium** — needs language generation but context is structured

---

## 2. Model Evaluation

### 2.1 Cloud LLMs — Fast Tier

These are the "workhorse" models for real-time threat analysis.

| Model | Input Cost | Output Cost | Context | Latency (p50) | Strengths | Weaknesses |
|-------|-----------|-------------|---------|--------------|-----------|-----------|
| **Gemini 2.5 Flash** | $0.075/1M | $0.30/1M | 1M tokens | ~800ms | Native thinking, huge context, structured JSON, free tier (1500/day) | Google-only ecosystem |
| **GPT-4o-mini** | $0.15/1M | $0.60/1M | 128K | ~600ms | Fastest structured output, reliable JSON mode | Smaller context, no free tier |
| **Claude Haiku 3.5** | $0.80/1M | $4.00/1M | 200K | ~900ms | Strong at security domain, nuanced reasoning | 5-10x more expensive |

**Winner for Guardian: Gemini 2.5 Flash** (primary) + GPT-4o-mini (failover)

**Rationale:**
- Free tier covers most small deployments entirely (1500 req/day ≈ 1 req/min)
- 1M context window allows sending large log batches in single request
- Native "thinking" mode improves decision quality for security analysis
- GPT-4o-mini as failover ensures zero downtime during provider outages

### 2.2 Cloud LLMs — Deep Analysis

For complex cases: incident correlation, SOC analyst chat, playbook generation.

| Model | Input Cost | Output Cost | Context | Latency (p50) | Best For |
|-------|-----------|-------------|---------|--------------|----------|
| **Gemini 2.5 Pro** | $1.25/1M | $10.00/1M | 1M tokens | ~3s | Complex multi-event correlation, large context reasoning |
| **GPT-4o** | $2.50/1M | $10.00/1M | 128K | ~2s | Structured planning, playbook generation |
| **Claude Sonnet 4.6** | $3.00/1M | $15.00/1M | 200K | ~2.5s | Nuanced security analysis, fewer hallucinations |

**Winner for Guardian: Gemini 2.5 Pro** (deep analysis)

**Rationale:**
- Same API/SDK as Flash — zero additional integration work
- 1M context matches Flash — can escalate without re-chunking
- "Extended thinking" mode for complex correlation
- Only used for ~5% of events (cost manageable)

**When to escalate to Deep tier:**
- Confidence < 60% from Flash
- Multi-source correlation needed (3+ data points)
- SOC analyst conversation with complex questions
- Novel attack pattern not seen before

### 2.3 Local LLMs — Offline Fallback

For air-gapped deployments, provider outages, or cost-conscious users.

| Model | Size | RAM Required | VRAM | Quality (0-10) | Speed (tok/s on CPU) | Best For |
|-------|------|-------------|------|----------------|---------------------|----------|
| **Qwen3 4B** | 2.5GB | 4GB | 3GB | 7/10 | ~30 tok/s | Current fallback, good multilingual |
| **Phi-4 Mini 3.8B** | 2.3GB | 4GB | 3GB | 7.5/10 | ~35 tok/s | Reasoning-heavy tasks, structured output |
| **Llama 3.2 3B** | 2.0GB | 3GB | 2.5GB | 6.5/10 | ~40 tok/s | Simple classification, fast |
| **Mistral 7B** | 4.1GB | 8GB | 6GB | 8/10 | ~15 tok/s | Best quality/size ratio, proven |
| **Gemma 2 9B** | 5.4GB | 10GB | 8GB | 8.5/10 | ~10 tok/s | Structured tasks, Google-aligned |
| **Qwen3 0.6B** | 0.4GB | 1GB | 0.5GB | 5/10 | ~80 tok/s | Ultra-fast chat, current chat model |

**Recommended Stack:**
- **Analysis model:** Phi-4 Mini 3.8B (best reasoning at 4B tier, excellent structured output)
- **Chat model:** Qwen3 0.6B (current, adequate for simple responses)
- **Upgrade path:** Mistral 7B when server has 8GB+ free RAM

**Key Insight:** For Guardian's use case (JSON classification output), smaller models perform surprisingly well because:
1. Output format is constrained (we tell it exactly what JSON to produce)
2. Context is structured (log lines, not free-form text)
3. Decision space is finite (block/allow/monitor/escalate)

### 2.4 Classical ML — Ultra-Fast Detection (Layer 1)

These models process events in <10ms without any API call.

| Algorithm | Use Case | Training Data | Accuracy | Latency |
|-----------|----------|--------------|----------|---------|
| **Isolation Forest** | Anomaly scoring | Historical metrics baselines | ~85% | <1ms |
| **XGBoost** | Brute force classification | Labeled SSH logs | ~92% | <1ms |
| **LSTM/GRU** | Sequential pattern detection | Time-series log sequences | ~88% | ~5ms |
| **One-Class SVM** | Normal behavior profiling | Clean baseline period | ~80% | <1ms |
| **Autoencoder** | Behavioral deviation | Network/process baselines | ~83% | ~3ms |

**Recommended for Guardian:**

1. **Isolation Forest** — Anomaly scoring for network metrics
   - Training: Run for 7 days on clean baseline, auto-builds normal profile
   - Use: Score every 2-min metric collection. Score > threshold → send to LLM
   - Implementation: scikit-learn model serialized as ONNX, run in Node.js via `onnxruntime-node`

2. **XGBoost** — SSH log classification
   - Features: `failed_attempts_5min`, `unique_usernames`, `geo_distance`, `time_of_day`, `ip_reputation_score`
   - Training: Labeled dataset from AbuseIPDB + historical Guardian decisions
   - Use: Pre-classify SSH events before sending to LLM. High-confidence → auto-block

3. **Rule-Based Cascade** (already partially implemented)
   - Regex patterns for known attack signatures
   - IP reputation cache (AbuseIPDB scores)
   - Rate limiting thresholds

**Why not deep learning for everything?**
- Guardian runs on minimal infrastructure (50MB RAM target)
- Most threats follow known patterns (brute force = 80% of alerts)
- ML gives deterministic, explainable scores (important for audit)
- LLMs are for the 20% of novel/complex threats

### 2.5 Embeddings & RAG

For correlating events across time and sources.

| Model | Dimensions | Size | Throughput | Best For |
|-------|-----------|------|-----------|----------|
| **Nomic Embed v1.5** | 768 | 137MB | ~500 doc/s | Local embedding, runs on CPU |
| **BGE-M3** | 1024 | 568MB | ~200 doc/s | Multilingual (PT-BR logs), hybrid search |
| **Gemini Embedding** | 768 | API | ~1000 doc/s | High quality, integrates with Gemini |
| **text-embedding-3-small** | 1536 | API | ~2000 doc/s | Cheap, fast, good for similarity |

**Recommended for Guardian:**
- **Phase 1 (now):** No RAG needed — structured queries suffice
- **Phase 2 (3-6 months):** Nomic Embed v1.5 for local threat intel correlation
  - Embed all security events
  - On new event, find similar historical events (cosine similarity)
  - "This login pattern matches 3 events from last week that turned out to be legitimate"
- **Phase 3 (6-12 months):** Full RAG pipeline with vector DB
  - SQLite + sqlite-vss (zero additional infrastructure)
  - Store embeddings alongside events in existing DB
  - Enable natural language queries: "show me all lateral movement attempts this month"

---

## 3. Cost Analysis

Monthly cost estimates per volume tier:

### Scenario: Small Deployment (1 server, ~1000 events/month)

| Strategy | Cost/Month | Notes |
|----------|-----------|-------|
| **Current (all Gemini Flash)** | $0 | Free tier covers entirely (1500/day) |
| **Recommended 4-layer** | $0 | Free tier + local rules |
| **All GPT-4o-mini** | ~$0.50 | 1000 × ~500 tokens avg |

### Scenario: Medium Deployment (5 servers, ~10,000 events/month)

| Strategy | Cost/Month | Notes |
|----------|-----------|-------|
| **Current (all Gemini Flash)** | ~$2.50 | Exceeds free tier some days |
| **Recommended 4-layer** | ~$0.30 | Only 5% hits cloud (500 events) |
| **All GPT-4o-mini** | ~$5.00 | No free tier |

### Scenario: Large Deployment (20 servers, ~100,000 events/month)

| Strategy | Cost/Month | Notes |
|----------|-----------|-------|
| **Current (all Gemini Flash)** | ~$25 | Most events hit API |
| **Recommended 4-layer** | ~$3.00 | 5000 events to cloud only |
| **All GPT-4o-mini** | ~$50 | Every event costs |
| **All Claude Haiku** | ~$200 | Too expensive at scale |

**The 4-layer approach saves 88-94% at scale.**

---

## 4. Recommended Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 Guardian AI Analysis Pipeline                     │
│                                                                   │
│  ┌─── Layer 1: Fast Filter ──────────────────────────── <1ms ─┐  │
│  │  • Regex rules (known attack signatures)                    │  │
│  │  • IP reputation cache (AbuseIPDB scores cached 24h)        │  │
│  │  • Rate limit thresholds (>5 failed SSH in 5min)            │  │
│  │  • Isolation Forest anomaly score                           │  │
│  │                                                             │  │
│  │  Output: BLOCK (auto) | SAFE (skip) | UNCERTAIN (→ L2)     │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                          │ ~20% pass through                      │
│                          ▼                                        │
│  ┌─── Layer 2: Local LLM ──────────────────────────── <2s ───┐  │
│  │  • Phi-4 Mini 3.8B (via Ollama)                            │  │
│  │  • Structured JSON output only                              │  │
│  │  • Context: event + 5-min window + baseline stats           │  │
│  │                                                             │  │
│  │  Output: {threat: bool, confidence: 0-100, action: ...}     │  │
│  │  If confidence >= 80 → execute action                       │  │
│  │  If confidence < 80 → escalate to Layer 3                   │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                          │ ~25% of L2 events (5% total)           │
│                          ▼                                        │
│  ┌─── Layer 3: Cloud LLM (Fast) ─────────────────── <5s ────┐  │
│  │  • Gemini 2.5 Flash (primary)                              │  │
│  │  • GPT-4o-mini (failover)                                   │  │
│  │  • Full context: event + history + profile + threat intel    │  │
│  │  • Thinking mode enabled for better reasoning               │  │
│  │                                                             │  │
│  │  Output: Full analysis + recommended action + reasoning      │  │
│  │  If confidence >= 70 → execute (with approval if critical)   │  │
│  │  If confidence < 70 or novel pattern → escalate to Layer 4   │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                          │ ~10% of L3 events (0.5% total)         │
│                          ▼                                        │
│  ┌─── Layer 4: Cloud LLM (Deep) ─────────────────── <30s ───┐  │
│  │  • Gemini 2.5 Pro (extended thinking)                      │  │
│  │  • Used for: complex correlation, SOC chat, novel attacks   │  │
│  │  • Multi-step reasoning with evidence chain                 │  │
│  │                                                             │  │
│  │  Output: Detailed report + confidence + action + evidence    │  │
│  │  Always requires human approval for critical actions         │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Decision Flow Per Event

```
Event received
    │
    ├── Known malicious IP (cached)? → AUTO-BLOCK (Layer 1)
    ├── Known safe IP (trusted)? → SKIP (Layer 1)
    ├── Rate limit exceeded? → AUTO-BLOCK (Layer 1)
    ├── Anomaly score < 0.3? → SAFE, log only (Layer 1)
    │
    ├── Anomaly score 0.3-0.7? → Local LLM (Layer 2)
    │   ├── Confidence >= 80%? → Execute action
    │   └── Confidence < 80%? → Cloud LLM (Layer 3)
    │
    └── Anomaly score > 0.7? → Cloud LLM (Layer 3)
        ├── Confidence >= 70%? → Execute (with approval if destructive)
        └── Novel pattern? → Deep Analysis (Layer 4)
```

---

## 5. Implementation Roadmap

### Phase 1: Immediate (Done)
- [x] Upgrade to Gemini 2.5 Flash
- [x] Add `AI_PROVIDER` configuration (auto/gemini/openai/claude/ollama)
- [x] Provider fallback chain (gemini → openai → ollama)

### Phase 2: Short-term (1-2 weeks)
- [ ] Add GPT-4o-mini as failover provider
- [ ] Implement provider health tracking (auto-switch on 3 consecutive failures)
- [ ] Add response quality scoring (did the JSON parse? was confidence reasonable?)
- [ ] Cache AI decisions for identical event patterns (dedup)

### Phase 3: Medium-term (1 month)
- [ ] Implement Layer 1 pre-filter
  - Isolation Forest trained on first 7 days of clean metrics
  - IP reputation cache with 24h TTL
  - Rate limit rules (configurable thresholds)
- [ ] Upgrade local LLM to Phi-4 Mini (better structured output)
- [ ] Add Gemini 2.5 Pro for SOC analyst deep queries
- [ ] Implement confidence-based escalation (L2 → L3 → L4)

### Phase 4: Long-term (2-3 months)
- [ ] XGBoost model for SSH event classification
  - Train on labeled historical data (Guardian decisions + AbuseIPDB)
  - Feature engineering: time patterns, geo, reputation, username entropy
- [ ] Embedding-based event correlation (Nomic Embed v1.5)
  - "Similar events" query for incident investigation
  - Automatic incident grouping
- [ ] A/B testing framework for model evaluation
  - Run new model in shadow mode alongside production
  - Compare decisions, measure false positive/negative rates
- [ ] Dashboard for AI decision metrics
  - Which layer handled each event
  - Cost per day/week/month
  - False positive rate by layer

### Phase 5: Future (6+ months)
- [ ] Fine-tune Phi-4 Mini on Guardian's historical decisions
- [ ] RAG pipeline for threat intel correlation
- [ ] Multi-server cross-correlation (attack patterns spanning servers)
- [ ] Automated model retraining pipeline

---

## 6. Appendix: Benchmark Methodology

### How to evaluate models for Guardian

**Test Dataset:** Create a labeled set of 200 events:
- 50 true positives (confirmed attacks from historical incidents)
- 50 true negatives (normal operations)
- 50 ambiguous cases (legitimate high-resource usage)
- 50 novel patterns (attacks not in training data)

**Metrics:**
- **Precision:** Of events flagged as threats, how many actually were?
- **Recall:** Of actual threats, how many were caught?
- **F1 Score:** Harmonic mean of precision and recall
- **Latency (p50, p95):** Time from input to decision
- **Cost per 1000 events:** Total API cost at evaluation volume
- **Structured output reliability:** % of responses that parse as valid JSON

**Testing Protocol:**
1. Send same 200 events to each model
2. Compare decisions against ground truth labels
3. Measure latency and cost
4. Calculate metrics above
5. Repeat 3x for statistical significance

**Acceptance Criteria for Production:**
- Precision >= 90% (minimize false positives — don't block legitimate users)
- Recall >= 85% (catch most threats — some misses acceptable for novel patterns)
- JSON parse rate >= 98%
- Latency p95 < 10s (Flash tier) or < 30s (Deep tier)

### Running Benchmarks

```bash
# Future: automated benchmark script
cd guardian
npm run benchmark:ai -- --dataset tests/fixtures/labeled-events.json --models gemini-2.5-flash,gpt-4o-mini,phi4-mini
```

This script (to be implemented in Phase 4) will:
1. Load labeled events from JSON fixture
2. Send each event to each configured model
3. Collect responses and timing
4. Generate comparison report in `docs/benchmark-results/`

---

## 7. Appendix: Model Configuration Examples

### Adding GPT-4o-mini as failover

```env
AI_PROVIDER=auto
GEMINI_API_KEY=your-gemini-key
OPENAI_API_KEY=your-openai-key
# auto will try: gemini → openai → ollama
```

### Running Phi-4 Mini locally via Ollama

```bash
# On the Guardian server:
ollama pull phi4-mini
# In .env:
OLLAMA_MODEL=phi4-mini
OLLAMA_CHAT_MODEL=qwen3:0.6b
```

### Configuring confidence thresholds

```env
# Lower = more sensitive (more events escalated to cloud)
# Higher = more local decisions (less cloud cost, more risk)
ABUSE_CONFIDENCE_THRESHOLD=70
```
