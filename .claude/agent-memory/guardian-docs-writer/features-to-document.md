# Features pendentes de documentação

Última atualização: 2026-05-29

A partir do `git log` recente e leitura do código, estas features existem no Guardian mas **não estão no README atual** ou estão mal documentadas. Ordem por valor pro leitor.

## 1. Noise reduction (4 camadas) — v3.1.0

**Status no código:** implementado, deployado em prod 2026-05-29
**Onde está:** `src/playbooks/`, `src/correlator/`, lógica de supressão em vários workers
**Por que importa:** É a "mágica" que o usuário menciona. Sem isso, Telegram fica inundado.
**O que documentar:**
- Camada 1: dedup por (IP, categoria) na correlação
- Camada 2: suppression window por incidente
- Camada 3: rate-limit do notifier
- Camada 4: AI summary que junta múltiplos eventos relacionados

## 2. IP threat scoring com ONNX

**Status:** treinado e em prod (commits eff4f64, 03b75b2)
**Onde:** `src/intelligence/ip-threat-classifier.ts` (provável), `scripts/train-*` para treino
**O que documentar:**
- Modelo ONNX classifica IP como malicioso (score 0-1)
- Mapa de ataques no dashboard exibe enriquecido
- Trade-off: requer `onnxruntime-node` (optional dep), Alpine quebra
- Como retreinar (em `docs/pt/avancado/04-treinar-ml.md`)

## 3. Container security detail + AI analysis

**Status:** em prod (commit cddf772)
**Onde:** `src/dashboard/pages/container-detail.html` + endpoint correspondente
**O que documentar:**
- Página individual de incidente de container
- Análise IA mostra explicação em linguagem natural
- Como interpretar o output da IA

## 4. Threat hunter worker

**Status:** em prod
**Onde:** `src/workers/threat-hunter.worker.ts`
**Intervalo:** 4h
**O que documentar:**
- Worker proativo: pede análise IA do estado atual sem evento gatilho
- Detecta padrões que regras estáticas não veem
- Output vira incidente se confiança suficiente

## 5. DGA classifier

**Status:** treinado e em prod
**Onde:** `src/intelligence/dga-classifier.ts`
**O que documentar:**
- 11 features (bigram log-likelihood, entropia, length, etc)
- Logistic regression em ONNX
- Fallback heurístico se onnxruntime ausente
- Como retreinar com `npm run train-dga`

## 6. Markov user profiles

**Status:** em prod
**Onde:** `src/intelligence/markov-user-profile.service.ts`
**O que documentar:**
- Modela transições de comando sudo por usuário
- View materializada `user_command_transitions` (PG only)
- Detecta sequência incomum (login → curl → bash → ...)

## 7. STL anomaly detection

**Status:** em prod
**Onde:** `src/intelligence/anomaly-detector.ts`
**O que documentar:**
- Decomposição: trend + seasonal + residual
- Fallback z-score se sem periodicidade
- Aplicado a métricas de servidor (CPU, conexões, etc)

## 8. CVE feeds: EPSS + CISA KEV

**Status:** em prod
**Onde:** `src/workers/cve-intel-feeds.worker.ts`, `src/threat-intel/`
**O que documentar:**
- EPSS: probabilidade de exploit (0-1) por CVE
- CISA KEV: catálogo de vulnerabilidades sendo exploradas ATIVAMENTE
- Como Guardian usa pra priorizar alertas de vuln

## 9. Block propagation worker

**Status:** em prod
**Onde:** `src/workers/block-propagation.worker.ts`
**O que documentar:**
- Fila de bloqueios com retry exponencial
- Garante que bloqueio chega em todos servidores mesmo com falha temporária
- Backoff 1s → 2s → 4s → ... até 5min

## 10. Block reconcile worker

**Status:** em prod (refatorado 2026-05-29 — verifyBlock signature)
**Onde:** `src/workers/block-reconcile.worker.ts`
**O que documentar:**
- Verifica periodicamente se bloqueio AINDA está ativo no servidor
- Se foi removido manualmente, reaplica
- Auto-corrige drift entre DB e estado real

## 11. Re-discovery baseline DB-backed

**Status:** em prod (commit 2026-05-29)
**Onde:** `src/workers/discovery.worker.ts`, tabela `discovery_baselines`
**O que documentar:**
- Detecta mudanças em servidor (serviços novos, portas novas, arquitetura mudou)
- Persistência em DB (substitui Map em memória — bug de container restart)
- Alerta no Telegram quando há mudança real

## 12. Multi-provider AI cascade

**Status:** em prod
**Onde:** `src/services/ai-provider.ts`
**O que documentar:**
- Ordem default (`AI_STRATEGY=auto`): Ollama → Gemini → OpenAI → Claude
- Modos: `local-only` (só Ollama), `api-only` (skip Ollama)
- Timeouts por provider
- Fallback rule-based se todos falham

## 13. Modelo de instalação seguro (guardian-shell)

**Status:** APROVADO, NÃO IMPLEMENTADO
**Onde:** ainda não existe — Tier 0 do roadmap
**O que documentar:** quando implementado:
- Usuário `guardian` em vez de root
- Allowlist regex
- Bootstrap via `curl|bash`
- Heartbeat
- **Não documentar antes da implementação** (ou marca `status: planejado`)

## Features que JÁ estão no README (não precisa adicionar)

- Pipeline básico (collectors → ... → playbook)
- Telegram bot
- Dashboard SSR
- AI básico (foi adicionado mas pode estar desatualizado — verificar)
- Detecção de ataques SSH

## Como atualizar este arquivo

- Quando documenta uma feature: move pra "Documentadas" no fim com link pra arquivo
- Quando feature nova é shipping: adiciona no topo como "🆕 não documentado"
- Quando feature é deprecada: move pra "Histórico" + nota
