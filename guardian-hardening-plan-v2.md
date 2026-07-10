# Guardian Blue Team — Plano de Hardening v2 (Deep Research)
**Data:** 2026-05-20
**Versão atual auditada:** 2.1.0 (`/tmp/guardian-src-new`, deployed em `/root/.guardian` no Hetzner)
**Stack:** TypeScript + Node.js (ESM) + PostgreSQL + Drizzle ORM + Express + Ollama (qwen3) + node-cron
**Histórico:** v1 cobriu auditoria + bugs + Falco/AIDE como visão geral. v2 incorpora pesquisa profunda (vuln scanning, RAG, ML) com versões verificadas em maio/2026 e prioridade unificada.

---

## 0. Sumário executivo

Três frentes de pesquisa convergem para o mesmo princípio: **TypeScript fica no hot-path, Python entra como sidecar**, com ONNX servindo de ponte. O caminho de maior payoff por sprint é:

1. **Sprint 1 (low-hanging fruit, sem novas deps):** Bugs do v1 + EPSS + CISA KEV + STL substituindo σ-threshold + DGA n-gram via ONNX + bge-m3 como embedder. Tudo entrega valor em <2 semanas.
2. **Sprint 2 (1 container novo):** Trivy/Syft pipeline substitui docker-audit; cross-encoder reranker via TEI sidecar; ml-worker Python sobe com Isolation Forest por servidor.
3. **Sprint 3 (gap raiz):** Falco modern_ebpf nos 4 hosts — fecha o gap que deixou XMRig escapar em maio.
4. **Sprint 4 (qualidade):** OSQuery + Lynis + Langfuse + RAGAS + drift monitoring.
5. **Sprint 5 (escala/condicional):** CrowdSec, Suricata/Zeek (apenas Hetzner), Apache AGE para grafo IP↔ASN↔incidentes.

### Mapa de prioridade unificada (todas as frentes)

| Prioridade | Item | Domínio | Esforço | Justificativa |
|------------|------|---------|---------|---------------|
| 🔴 P0 | Self-detection bug `process-collector.ts:46` | Bug | 2h | 298 FPs/24h, ainda ativo |
| 🔴 P0 | Schema audit_logs (operation→action, status→result) | Bug | 1h | Queries silenciosamente quebradas |
| 🔴 P0 | Dedup containerId em `container_crypto_process` | Bug | 4h | Amplia FPs do bug acima |
| 🟠 P1 | EPSS API enricher | Vuln intel | 1d | Reduz alert fatigue 50%+ |
| 🟠 P1 | CISA KEV daily feed | Vuln intel | ½d | Sinal binário "explorado in-the-wild" |
| 🟠 P1 | bge-m3 embedder (substitui Ollama default) | RAG | 1d | +20–40% recall em retrieval |
| 🟠 P1 | STL + z-score residual (memória) | ML | 2-3d | Substitui σ-threshold ingênuo |
| 🟠 P1 | Threat intel gate (TI + AI consensus) | Política | 3d | Previne bans falsos do AI sozinho |
| 🟡 P2 | Trivy + Syft pipeline (substitui docker-audit) | Vuln scan | 2d + 1d | Cobertura multi-distro/lockfiles |
| 🟡 P2 | BGE-Reranker-v2-m3 via TEI sidecar | RAG | 1d | +10–20pp precisão top-3 |
| 🟡 P2 | Falco modern_ebpf nos 4 hosts | Container | 5d | Fecha gap raiz do XMRig |
| 🟡 P2 | Isolation Forest por servidor (ml-worker) | ML | 5-7d | Anomaly em SSH login features |
| 🟡 P2 | Markov user profile (pure SQL) | ML | 3-5d | Comportamento sudo+comando |
| 🟡 P2 | DGA classifier n-gram via ONNX | ML | 3-4d | Substitui entropia ingênua |
| 🟢 P3 | ReAct agent com tools de segurança (Vercel AI SDK) | RAG/Agent | 3-5d | LLM raciocina como SOC analyst |
| 🟢 P3 | OSQuery TLS endpoint nos hosts | Telemetry | 5-7d | Inventário in-band, YARA process scan |
| 🟢 P3 | Lynis worker semanal | Audit | 2d | Hardening score por host |
| 🟢 P3 | Dockle no container-image-collector | Image lint | 1d | Hygiene preventiva |
| 🟢 P3 | DBSCAN scan-campaign clustering | ML | 4-5d | Detecta campanhas que regras perdem |
| 🟢 P3 | Langfuse + RAGAS eval harness | Observability | 2-3d | Para de editar prompt no escuro |
| 🟢 P3 | pgvectorscale + memory TTL/compaction | RAG infra | 4-5d | Latência flat com crescimento |
| 🔵 P4 | CrowdSec agent + bouncer | Threat intel | 5-7d | Crowd-sourced IPs maliciosos |
| 🔵 P4 | docker-bench CIS scoring | Audit | 2d | CIS benchmark periódico |
| 🔵 P4 | Suricata + Zeek (Hetzner only) | Network | 15d | DPI / NIDS — overkill em VPS pequena |
| 🔵 P4 | Apache AGE knowledge graph | Graph RAG | 1-2 sem | IP→ASN→Incident multi-hop |
| 🔵 P4 | Calibrated P(FP) classifier antes de ban | ML | 1-2 sem | Reduz bans incorretos |
| 🔵 P4 | Prophet predictions em `server_metrics` | ML | 1 sprint | Early warning saturação |

---

## 1. Bugs imediatos (carregados de v1)

Repete §2 do v1. Todos parte de Sprint 1.

### 1.1 Self-detection — `src/collectors/process-collector.ts:46`

```typescript
// Antes:
ps aux 2>/dev/null | grep -i '${grepPattern}' | grep -v grep
// Depois: parsear comm field (não args), ignora self-PID
ps -eo pid,user,pcpu,pmem,comm,args --no-headers 2>/dev/null |
  awk -v pat='${grepPattern}' -v self=$$ '$1 != self && tolower($5) ~ pat { print }'
```

### 1.2 Schema migration

`grep -rn "audit_logs.*\(operation\|status\)" src/` e renomear para `action` / `result`.

### 1.3 Dedup `container_crypto_process` — janela de 30min por containerId.

---

## 2. Vulnerability Intelligence (P1, Sprint 1)

### 2.1 EPSS API enricher

Worker semanal que enriquece `vulnerabilities`:

```typescript
// /api/first.org/data/v1/epss?cve=CVE-...,CVE-... (até 100 por request)
const epss = await fetch(`https://api.first.org/data/v1/epss?cve=${batch.join(',')}`);
// upsert epss_score float, epss_percentile float em vulnerabilities
```

### 2.2 CISA KEV feed

Cron diário, baixar `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, upsert em `cve_kev` table; flag `is_kev=true` em vulnerabilities.

### 2.3 Critical alert query

```sql
-- Nova lógica de alerta crítico:
SELECT * FROM vulnerabilities
WHERE is_kev = true
   OR (cvss_score >= 7 AND epss_score >= 0.5)
   OR (cvss_score >= 9 AND epss_percentile >= 0.95);
```

Schema additions:
```sql
ALTER TABLE vulnerabilities ADD COLUMN epss_score real;
ALTER TABLE vulnerabilities ADD COLUMN epss_percentile real;
ALTER TABLE vulnerabilities ADD COLUMN is_kev boolean DEFAULT false;
CREATE INDEX idx_vuln_priority ON vulnerabilities (is_kev, epss_score, cvss_score);
```

---

## 3. Vulnerability Scanning Pipeline (P2, Sprint 2)

### 3.1 Trivy como backbone (substitui docker-audit)

- v0.70.0 (Apr 2026), Apache 2.0, footprint 200-500MB durante scan
- DB atualiza a cada 6h via OCI registry (multi-source: NVD, GHSA, OVAL, distro feeds)
- Operação preferida: `trivy server` em container dedicado, Guardian bate via HTTP
  ```bash
  trivy server --listen 0.0.0.0:8080 --token-header "X-Trivy-Token"
  # Cliente:
  trivy image --server http://trivy:8080 --token <token> --format json --severity HIGH,CRITICAL <image>
  ```

### 3.2 Syft para SBOM persistente

- v1.44.0, gera CycloneDX/SPDX, alimenta Trivy/Grype sem repuxar imagem
- Pipeline: pull image → `syft <image> -o cyclonedx-json` → store em `image_sboms` table → `grype sbom:./sbom.json` para revalidar quando KEV/EPSS muda

### 3.3 Grype como segunda opinião (opcional)

- v0.112.0, Apache 2.0
- Dual-scan strategy: CVE em ambos = altíssima confiança; só num = revisar
- Útil onde o cobre Trivy reporta FPs em pacotes Debian back-portados

### 3.4 Dockle (image hygiene preventiva)

- v0.4.15 (Jan 2025), CIS Docker Image Benchmark
- Integrar no `container-image-collector` existente: `dockle -f json <image>` em cada pull

### Descartados explicitamente

- **Clair:** Postgres dedicado + microserviços, overkill
- **Docker Scout:** login Docker Hub obrigatório, recursos pagos
- **Wazuh stack completo:** manager + indexer requerem 8GB+ dedicados, overlap com Guardian. Considerar só agentes apontando para collector minimalista próprio (futuro distante)

---

## 4. Container Runtime Visibility — Falco (P2, Sprint 3)

Este é o **gap raiz** do incidente XMRig de maio. Sem mudar nada mais, Falco resolve ~80% do problema.

### 4.1 Deploy

- Falco v0.43.1 (Apr 2026), Apache 2.0
- **Usar modern_ebpf (CO-RE)** — não requer headers do kernel, mais leve que legacy probe (que está sendo deprecado em v0.43)
- Footprint: 200-400MB RAM, 3-5% CPU em VPS 4GB

```yaml
# docker-compose snippet por host monitorado
falco:
  image: falcosecurity/falco-no-driver:0.43.1
  privileged: true
  pid: host
  environment:
    - FALCO_BPF_PROBE=  # vazio = modern_ebpf
    - HOST_ROOT=/host
  volumes:
    - /var/run/docker.sock:/host/var/run/docker.sock
    - /dev:/host/dev
    - /proc:/host/proc:ro
    - /etc:/host/etc:ro
    - /usr:/host/usr:ro
    - /sys/kernel/debug:/sys/kernel/debug
  command:
    - /usr/bin/falco
    - --modern-bpf
    - -o
    - http_output.enabled=true
    - -o
    - http_output.url=https://guardian.host/falco/events
    - -o
    - http_output.user_agent=falco-${HOST}
```

### 4.2 Endpoint Express

```typescript
// src/api/routes/falco.ts
router.post('/falco/events', verifyHmac, async (req, res) => {
  const event = req.body;
  await db.insert(falcoAlerts).values({
    serverId: req.serverId,  // from HMAC token
    rule: event.rule,
    priority: event.priority,
    output: event.output,
    fields: event.output_fields,
    occurredAt: new Date(event.time),
  });
  await pipeline.ingest({ source: 'falco', ...event });
  res.status(204).end();
});
```

### 4.3 Regras críticas (CRS Falco padrão + custom)

- `Mining cryptocurrency` (built-in) — teria pegado XMRig em <30s
- `Outbound to mining pool` (custom, pool list)
- `Write below /etc` (built-in)
- `Run shell untrusted` (built-in)
- `Container privilege escalation` (built-in)

---

## 5. RAG Modernization (Sprint 1-3 distribuído)

### 5.1 BGE-M3 embedder (P1, Sprint 1) — HIGHEST RAG ROI

- BAAI/bge-m3, MIT, 568M params, 1024 dim, 8192 tokens, 100+ idiomas (incl. PT-BR)
- **Disponível no Ollama** (`ollama pull bge-m3`)
- Outputs dense + sparse + ColBERT vectors **simultaneamente** — habilita hybrid search sem libs extras
- Esforço: trocar config Ollama, re-embed `incident_memory` (1× batch), atualizar query função
- Impacto esperado: **+20–40% recall** em retrieval onde termos exatos (CVE-IDs, IPs, error codes) importam tanto quanto semântica

### 5.2 Cross-encoder reranking (P2, Sprint 2)

- BGE-Reranker-v2-m3, Apache 2.0, 568M params
- Deploy via HuggingFace `text-embeddings-inference` Docker:
  ```bash
  docker run -p 8081:80 \
    -v /var/lib/tei:/data \
    ghcr.io/huggingface/text-embeddings-inference:cpu-1.5 \
    --model-id BAAI/bge-reranker-v2-m3
  ```
- Footprint: ~1-2GB RAM fp16, sem GPU para QPS baixa
- Pipeline: top-K=20 vetorial → rerank → top-5 ao LLM
- Impacto: +10–20pp precisão top-3

### 5.3 ParadeDB pg_search (BM25 nativo no Postgres)

- AGPL-3.0 (OK para self-hosted privado)
- Tantivy/Rust extension, índice BM25 inside Postgres
- Combina com pgvector via RRF (Reciprocal Rank Fusion) em ~50 LOC TS:
  ```typescript
  const rrfScore = (rank: number, k = 60) => 1 / (k + rank);
  const fused = mergeRanked([vectorResults, bm25Results], rrfScore);
  ```

### 5.4 ReAct agent + Vercel AI SDK (P3, Sprint 3-4)

- LlamaIndex.TS está **DEPRECATED em Apr 30, 2026** — não adotar
- LangChain.js: heavy abstractions, evitar exceto LangGraph para casos específicos
- Vercel AI SDK: lightweight, tool-calling nativo, Ollama provider
- Refactor `AIBlockAdvisor` de single-shot para multi-step ReAct:
  ```typescript
  await generateText({
    model: ollama('qwen3:4b'),
    tools: {
      search_incident_history: { ... },
      lookup_cve: { ... },
      get_asn_info: { ... },
      find_similar_playbook_outcomes: { ... },
    },
    maxSteps: 5,
    prompt: socAnalystPrompt,
  });
  ```
- Esse é o **maior salto qualitativo** do AI advisor — raciocínio multi-passo igual a SOC analyst humano

### 5.5 pgvectorscale + memory compaction (P3, Sprint 4)

- pgvectorscale 0.9.0 (Nov 2025), drop-in PG extension
- StreamingDiskANN + Statistical Binary Quantization → **28× lower p95 latency vs Pinecone @ 50M vetores**
- Compaction worker noturno: incidentes >90d sem retrieval recente → LLM summariza cluster relacionado em "lessons learned" → deleta originais

### 5.6 Langfuse + RAGAS (P3, Sprint 4)

- Langfuse self-hosted (MIT core, +Postgres + ClickHouse)
- Instrumenta toda chamada LLM/retrieval/embedding
- RAGAS eval harness em Python: 50–100 incidentes históricos com ground truth (decisão humana real) → metrics faithfulness/context-precision/recall
- Trigger automático em CI quando prompt muda

### Descartados explicitamente

- **Mastra:** TS-native agentic, 24k stars, mas v2 ainda não estável → adiar
- **Microsoft GraphRAG:** batch reindex caro, não cabe modelo incremental
- **LightRAG/HippoRAG:** Python-only, HTTP overhead, complexidade não justifica para grafo pequeno (~10k-100k nós) — usar Apache AGE direto se for o caso

---

## 6. Machine Learning (Sprint 1-3 distribuído)

### 6.1 Princípios de design (ratificados na pesquisa)

1. **Hot path em Node** via ONNX Runtime — decisões críticas (DGA, P(FP)) sem RTT HTTP
2. **Cold path em Python** (`ml-worker` FastAPI) — treino + modelos heavy (iForest, Prophet, DBSCAN)
3. **Modelo sempre versionado** em `model_registry` Postgres antes de promover
4. **Toda predição loga** em `ml_predictions` (audit trail + ground truth retroativo)
5. **NÃO retrain automático silencioso** — drift dispara alerta, não retrain. Human-in-the-loop.
6. **NÃO LogBERT/transformers** sem GPU — ROI negativo. Resista.

### 6.2 Sprint 1 — TS-only (sem ml-worker ainda)

#### STL + z-score residual (memória) — substitui σ-threshold
```typescript
// Em src/services/anomaly/memory-detector.ts
import { decompose } from 'simple-statistics-stl';  // ou impl manual
// 7d window, period=24h
// trend + seasonal + residual; z-score do residual com MAD
const residualZ = (x - median(R)) / (1.4826 * mad(R));
if (residualZ > 5) alert(severity: 'high');
else if (residualZ > 3) alert(severity: 'low');
```

#### DGA classifier n-gram (ONNX) — substitui entropia ingênua
- Treinar em Python offline: bigrams/trigrams sobre Tranco top-1M (benigno) + DGArchive (malicioso)
- Logistic regression → `skl2onnx` → arquivo .onnx
- Inference em Node: `onnxruntime-node` carrega no startup, ~5MB
- Impacto: ~95% accuracy vs ~70% do entropy threshold atual

#### Markov user behavior (pure SQL) — `behavior_profiles` já existe!
```sql
-- Matriz de transição materializada por usuário
CREATE MATERIALIZED VIEW user_command_transitions AS
SELECT user_id, prev_cmd, curr_cmd, count(*) as n,
       count(*)::float / sum(count(*)) OVER (PARTITION BY user_id, prev_cmd) as p
FROM (SELECT user_id, command as curr_cmd,
             lag(command) OVER (PARTITION BY user_id ORDER BY ts) as prev_cmd
      FROM sudo_events WHERE ts > now() - interval '90 days') x
GROUP BY user_id, prev_cmd, curr_cmd;
-- Score de uma nova sequência: -log P(transição), threshold por percentil 99
```

### 6.3 Sprint 2 — Sobe `guardian-ml-worker` (Python container)

```yaml
ml-worker:
  build: ./ml-worker
  environment:
    - DATABASE_URL=${POSTGRES_URL}
  volumes:
    - ml-models:/var/lib/guardian/models
  ports:
    - "127.0.0.1:8090:8090"
```

#### Isolation Forest por servidor (PyOD)
- Features: `(hour_sin, hour_cos, src_asn_id, src_country_code, ssh_user_freq_30d, failed_attempts_5min, geo_distance_km_from_last_login)`
- Treino noturno (cron interno worker), **um modelo por servidor** (cardinalidade baixa permite)
- Export ONNX via skl2onnx → serve via `/score/ssh` (Python) E carrega em Node para hot-path
- Validação: AUC contra CICIDS-2018 + MAWILab antes de promover

#### DBSCAN scan campaigns (batch 4h)
- Features: `(asn_id, country, user_agent_hash, path_pattern_hash)` em window 24h
- eps=0.3, min_samples=10
- Output: `attacker_clusters` table com `cluster_id, ip_count, first_seen, last_seen, signature`

### 6.4 Sprint 3 — Loop de qualidade

#### Prophet predictions em `server_metrics`
- Por servidor + métrica (CPU, mem, disk)
- Daily forecast 24-72h ahead com intervalo 95%
- Alarme se actual cai fora do intervalo por >15min

#### Calibrated P(FP) classifier
- Treina em histórico de bans + manual unbans/whitelists
- Logistic regression + Platt scaling
- Decisão: se P(FP) > 0.3 → degrade ban automático para alerta humano

#### Drift monitoring (PSI/KS daily)
- PSI por feature, alerta se > 0.2
- Trigger retrain manual (não auto)

### 6.5 Schemas novos

```sql
CREATE TABLE model_registry (
  id serial PRIMARY KEY,
  name text NOT NULL,
  version text NOT NULL,
  algorithm text NOT NULL,
  artifact_path text NOT NULL,
  artifact_sha256 text NOT NULL,
  metrics jsonb NOT NULL,
  trained_at timestamptz NOT NULL,
  is_active boolean DEFAULT false,
  UNIQUE (name, version)
);

CREATE TABLE feature_snapshots (
  entity_type text NOT NULL,
  entity_id text NOT NULL,
  feature_set_version text NOT NULL,
  features jsonb NOT NULL,
  computed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (entity_type, entity_id, feature_set_version, computed_at)
);

CREATE TABLE ml_predictions (
  id bigserial PRIMARY KEY,
  model_name text NOT NULL,
  model_version text NOT NULL,
  entity_id text,
  features_hash text NOT NULL,
  prediction jsonb NOT NULL,
  confidence real,
  ground_truth_label text,  -- preenchido a posteriori quando humano confirma
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE attacker_clusters (
  id serial PRIMARY KEY,
  signature_hash text UNIQUE NOT NULL,
  asn_ids integer[],
  country_codes text[],
  ip_count integer NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  ips inet[],
  metadata jsonb
);
```

### 6.6 Datasets para validação

- **CICIDS-2018** + **MAWILab** para benchmark interno (AUC vs regras existentes)
- **LogPAI HDFS/BGL** se Drain3+iForest virar prioridade
- KDD'99/NSL-KDD: **evitar** (distribuição irrealista)

---

## 7. Threat Intel & Network (Sprint 4-5)

### 7.1 Threat intel gate (P1, Sprint 1)

Política de duas chaves antes de `block_permanent` (já em v1, mantida):

```typescript
async function shouldBlock(ip: string, eventCtx) {
  const ti = await ThreatIntelManager.lookupIP(ip);
  const ai = await AIBlockAdvisor.getRecommendation(ctx, eventCtx);

  if (ti?.score >= 75) return { action: 'block_permanent', source: 'ti_high' };
  if (ti?.score >= 30 && ai.action === 'block_permanent' && ai.confidence >= 70)
    return { action: 'block_permanent', source: 'ti_ai_consensus' };
  if (!ti && ai.confidence < 85) return { action: 'monitor', source: 'no_ti_low_conf' };
  return ai;
}
```

### 7.2 CrowdSec (P4, Sprint 5)

- v1.7.8, MIT/AGPL, 100-250MB RAM
- Crowd-sourced threat intel (Central API): IPs banidos por outros usuários ficam disponíveis
- Bouncer customizado escreve em Postgres do Guardian
- Complementa block-ip existente

### 7.3 Suricata + Zeek (P4, Hetzner only)

- Suricata 8.0.5 (NIDS, EVE JSON output) — 0.5-1.5GB RAM
- Zeek v8.2.0 (network analysis, JSON logs) — 1-2GB RAM
- **Inviável em VPS 4GB**, só Hetzner dedicado
- Tail logs JSON via `chokidar`/`node-tail`, parse line-by-line, ingest pipeline

---

## 8. Host Security & Audit (Sprint 4)

### 8.1 OSQuery (P3)

- v5.23.0, daemon ~80-150MB RAM por host
- Features 2026: YARA process memory scan, certificate table Linux, header-based auth
- Deploy em cada host SSH-monitorado, configurar `tls_logger` apontando para Guardian
- Schedules: `listening_ports`, `processes`, `suid_bin`, `kernel_modules`, `shell_history`

### 8.2 Lynis (P3)

- v3.1.6 (Out 2025), GPLv3, sem daemon
- Worker mensal/semanal: `ssh host "lynis audit system --cronjob --report-file -" | parser`
- Output `key=value` por linha — parse trivial
- Gera `hardening_index` por host (métrica acionável longo prazo)

### 8.3 docker-bench (P4)

- CIS Docker Benchmark scoring
- Subprocess via SSH, parse JSON, gravar em `cis_benchmark_runs`

### 8.4 AIDE (P3, herdado de v1)

- FIM com baseline assinado (resolve gap "primeira execução vira ground truth")
- Daily `aide --check` no host, Guardian SSH lê report
- Telegram `/fim_trust <server>` para attestation manual

### Descartados

- **chkrootkit / rkhunter:** assinaturas envelhecidas, FPs em systemd/snap. Coberto por Falco+AIDE+OSQuery
- **ntopng / Arkime:** overlap com Zeek; Arkime precisa TB de storage
- **Coraza WAF:** não-nativo Node, integração via logs externos não justifica vs CrowdSec

---

## 9. Self-hardening do Guardian (P3, Sprint 3-4)

(Carregado de v1 §5 — escopo inalterado)

### 9.1 Container security
- Read-only rootfs + tmpfs para `/tmp`, volume separado para `/data`
- `no-new-privileges` + cap_drop ALL + caps mínimas
- SSH key com `command=` restriction em `authorized_keys` (whitelist por hash)
- AppArmor/SELinux profile customizado
- Secrets via Docker Swarm secrets, NÃO env vars

### 9.2 Anti-evasion
- Heartbeat por servidor: `lastEventAt` > 5min antigo → alerta crítico
- Self-integrity: Guardian verifica próprio binário hash hourly
- Out-of-band notification: alertas críticos vão para Pushover/Discord também (não só Telegram)

### 9.3 Observability
- OpenTelemetry tracing (`@opentelemetry/sdk-node`) — pipeline 6-stage precisa de traces
- Prometheus metrics (`prom-client`) — counters por source/severity
- `/health` profundo: DB, Ollama, AbuseIPDB circuit, Falco endpoint

---

## 10. Roadmap final consolidado

### Sprint 1 (semana 1-2) — Quick wins, sem novas deps
- [ ] Bugs P0: self-detection, schema, dedup, calibração unusual_hour
- [ ] EPSS enricher worker
- [ ] CISA KEV daily feed worker
- [ ] Schema vulnerabilities: epss_score, epss_percentile, is_kev
- [ ] Threat intel gate em ai-block-advisor
- [ ] bge-m3 como Ollama embedder default
- [ ] STL + z-score residual (memória) em TS puro
- [ ] DGA classifier ONNX (treina Python offline, infere Node)
- [ ] Markov user behavior em Postgres puro
- [ ] **KPI saída:** FPs reduzidos ≥30% em 7d reais; alertas críticos = (KEV ∪ alta-EPSS)

### Sprint 2 (semana 3-4) — Container scanning + ml-worker + reranker
- [ ] Subir Trivy server container
- [ ] Substituir docker-audit no `vuln-scanner.worker`
- [ ] Adicionar Syft → `image_sboms` table
- [ ] Subir TEI sidecar com BGE-Reranker-v2-m3
- [ ] Pipeline RAG: top-20 vetorial → rerank → top-5 LLM
- [ ] Subir `guardian-ml-worker` Python container
- [ ] Isolation Forest por servidor (PyOD), validar contra CICIDS-2018
- [ ] DBSCAN scan campaigns batch 4h
- [ ] Schemas novos: model_registry, feature_snapshots, ml_predictions, attacker_clusters
- [ ] **KPI saída:** Trivy detecta CVE em imagens que docker-audit não detectava; ML detecta ≥3 campanhas no histórico que regras perderam

### Sprint 3 (semana 5-6) — Falco + ReAct agent
- [ ] Deploy Falco modern_ebpf nos 4 hosts
- [ ] Endpoint `/falco/events` HMAC-validated
- [ ] Regras: crypto mining, outbound mining pool, write /etc, shell untrusted
- [ ] Replay logs Maio/2026 do XMRig — confirmar que Falco teria pegado
- [ ] Refactor AIBlockAdvisor → ReAct agent via Vercel AI SDK
- [ ] Tools: search_incident_history, lookup_cve, get_asn_info, find_similar_playbook
- [ ] **KPI saída:** Container syscall events visíveis em Postgres; AI advisor produz reasoning chain auditável

### Sprint 4 (semana 7-8) — Telemetry + Observability + ML quality
- [ ] OSQuery TLS endpoint + schedules
- [ ] Lynis worker mensal
- [ ] AIDE integration via SSH collector
- [ ] Self-host Langfuse (Postgres + ClickHouse)
- [ ] Instrumentar todo retrieval/LLM/embedding
- [ ] RAGAS eval harness Python (50 incidentes históricos)
- [ ] pgvectorscale + DiskANN índice em incident_memory
- [ ] Memory compaction worker (90d threshold)
- [ ] Drift monitoring (PSI/KS) daily worker
- [ ] Calibrated P(FP) classifier
- [ ] Prophet em server_metrics
- [ ] **KPI saída:** RAGAS context-precision ≥0.8 em eval set; 0 bans incorretos em 14d

### Sprint 5 (semana 9-10) — Network + threat intel + scale
- [ ] CrowdSec agent + bouncer
- [ ] docker-bench CIS scoring
- [ ] OpenTelemetry tracing
- [ ] Prometheus metrics
- [ ] Heartbeat + self-integrity + out-of-band alerts
- [ ] (Hetzner-only) Suricata + Zeek
- [ ] (Condicional) Apache AGE knowledge graph
- [ ] **KPI saída:** Hardening completo, métricas exportáveis, observability end-to-end

---

## 11. Bibliotecas externas finais (consolidado)

### Adicionar
| Lib | Versão | Uso | Sprint |
|-----|--------|-----|--------|
| **EPSS API** | live | Vuln intel priority | 1 |
| **CISA KEV feed** | live | Vuln intel binary signal | 1 |
| `bge-m3` (Ollama) | latest | RAG embedder | 1 |
| `simple-statistics-stl` | npm | Memory anomaly | 1 |
| `onnxruntime-node` | 1.18+ | DGA + future hot-path ML | 1 |
| **Trivy** binary | v0.70.0 | Vuln scanner | 2 |
| **Syft** binary | v1.44.0 | SBOM | 2 |
| **TEI** Docker | 1.5+ | BGE-Reranker sidecar | 2 |
| ParadeDB pg_search | 0.23.4 | BM25 hybrid search | 2 |
| **PyOD** (Python) | 1.x | Isolation Forest, ECOD | 2 |
| **River** (Python) | latest | Streaming online ML | 2 (opcional) |
| **scikit-learn** + skl2onnx | 1.x | Treino + ONNX export | 2 |
| **Falco** binary | v0.43.1 | eBPF container runtime | 3 |
| **Vercel AI SDK** | latest | ReAct agent layer | 3 |
| **OSQuery** | v5.23.0 | Host telemetry | 4 |
| **Lynis** | v3.1.6 | Host audit | 4 |
| **AIDE** | latest | FIM signed baseline | 4 |
| **Langfuse** | self-host | LLM observability | 4 |
| **RAGAS** (Python) | v0.4.3 | RAG eval | 4 |
| **pgvectorscale** | 0.9.0 | DiskANN index | 4 |
| **Prophet** (Python) | latest | Time-series forecast | 4 |
| `@opentelemetry/sdk-node` | 1.x | Tracing | 5 |
| `prom-client` | 15.x | Prometheus metrics | 5 |
| **CrowdSec** | v1.7.8 | Crowd-sourced threat intel | 5 |
| **docker-bench-security** | latest | CIS scoring | 5 |
| **Drain3** (Python) | latest | Log template mining | 5 (opcional) |
| **hmmlearn** (Python) | latest | HMM behavioral | 5 (opcional) |
| **Apache AGE** | v1.7.0 | Graph in Postgres | 5 (condicional) |
| **Suricata** | 8.0.5 | NIDS (Hetzner only) | 5 |
| **Zeek** | v8.2.0 | Network analysis (Hetzner only) | 5 |

### Manter (escolhas excelentes, não trocar)
`dockerode`, `drizzle-orm`, `pg`, `pino`, `node-cron`, `zod`, `pgvector` (manter junto com pgvectorscale)

### Descartados explicitamente
- **Wazuh stack completo** — overlap com Guardian, footprint inviável
- **Clair** — Postgres dedicado, microserviços, overhead
- **Docker Scout** — login DH, recursos pagos
- **chkrootkit / rkhunter** — assinaturas envelhecidas, FPs
- **Coraza WAF** — não-nativo Node, integração indireta
- **ntopng / Arkime** — overlap, storage hungry
- **LlamaIndex.TS** — DEPRECATED Apr 30, 2026
- **LangChain.js** (heavy mode) — só LangGraph se necessário
- **Mastra** — adiar, v2 não estável
- **Microsoft GraphRAG** — batch reindex caro
- **LightRAG / HippoRAG** — Python-only, complexity não justifica
- **LogBERT / DeepLog** — sem GPU, ROI negativo
- **Snyk DB / VulnDB** — pagos, TOS restritivos
- **MLflow / Feast** — overkill cedo, Postgres `model_registry` resolve

---

## 12. Riscos e armadilhas

1. **Cold start ML (14-30 dias):** Modelos por servidor têm dados insuficientes inicialmente. Manter as 22 regras como **fallback obrigatório** — ML é aditivo, não substituto.
2. **Adversarial drift:** Atacante pode aprender modelo. Mitigar com ensemble (regra OR ML) + adversarial samples sintéticos no treino.
3. **Auto-retrain silencioso:** Atacante envenena baseline; modelo "esquece" a anomalia. PSI + sanity tests obrigatórios; **drift dispara alerta, não retrain**.
4. **LogBERT armadilha:** Literatura tentadora, ROI em VPS sem GPU é negativo. **Resista**.
5. **Falco gRPC depreciado em v0.43:** Usar `http_output` (não gRPC) — alinhar com novo padrão.
6. **LlamaIndex.TS DEPRECATED Apr 30, 2026:** Não adotar; migrar se já em uso.
7. **Wazuh agent isolado:** Tentação de "só agentes"; em prática, agentes assumem manager. Skip completo.
8. **CrowdSec Central API rate limit:** Free tier limitado, monitorar uso.
9. **Trivy DB pulls:** Cada cliente sem `trivy server` puxa DB completo a cada scan (~300MB). Server mode obrigatório.
10. **TEI reranker no CPU:** OK para QPS baixa, mas thresholds: 1-2 GB RAM, ~200ms p99 por rerank de 20 docs.

---

## 13. KPIs e métricas

| Métrica | Baseline atual | Meta após Sprint 5 |
|---------|----------------|---------------------|
| FPs por dia (`container_crypto_process`) | 298 | <5 |
| Detecção de XMRig in-container | 0% (escapou em maio) | 100% via Falco |
| RAGAS context-precision | n/a | ≥0.8 |
| RAGAS faithfulness | n/a | ≥0.85 |
| Bans incorretos por mês | n/a | 0 (com P(FP) gate) |
| Hardening score (Lynis) por host | desconhecido | ≥75 |
| CVE com is_kev=true detectados em <24h | n/a | 100% |
| ML model drift detectado | n/a | <24h após PSI > 0.2 |
| p95 latency retrieval (incident_memory) | desconhecido | <100ms |
| AI advisor reasoning steps | 1 (single-shot) | 3-5 (ReAct) |

---

## 14. Notas finais

Guardian já é mais sofisticado que muitos SOAR comerciais entry-level. As três frentes pesquisadas (vuln scanning, RAG, ML) convergem para o mesmo princípio arquitetural: **TS no hot-path, Python no sidecar, ONNX como ponte**, mantendo Postgres como single source of truth.

O ataque XMRig de maio aconteceu porque não havia visibilidade dentro do container — esse é o gap nº1 a fechar. **Falco resolve ~80% disso por conta própria.** O resto do roadmap é: reduzir alert fatigue (EPSS+KEV+ML), melhorar qualidade de decisão (RAG hybrid+rerank+ReAct), e instrumentar para parar de editar prompts no escuro (Langfuse+RAGAS).

Comece **TS-only no Sprint 1** para entregar valor sem mudar arquitetura. Suba o **ml-worker e Trivy server no Sprint 2** quando o ROI dos quick wins já estiver provado e financiando politicamente os novos containers. **Falco no Sprint 3** fecha o gap raiz. Tudo o mais é incremento.
