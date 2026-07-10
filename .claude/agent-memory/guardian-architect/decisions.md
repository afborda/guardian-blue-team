# Decisões arquiteturais (ADR-style)

## ADR-001: Cascata multi-provider de AI
**Data:** já existente antes deste log
**Decisão:** Ollama (local, 120s timeout) → Gemini → OpenAI → Claude. Controlado por `AI_STRATEGY=auto|local-only|api-only`.
**Por quê:** local-first reduz custo e latência; APIs externas como fallback evitam single point of failure; rule-based fallback final garante que Guardian nunca trava.

## ADR-002: DDL-in-code, sem migration runner
**Data:** já existente
**Decisão:** Schema usa `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` em `src/database/connection.ts`. Sem migration tool.
**Por quê:** Guardian é single-tenant self-hosted, schema evolui devagar, e migration runners adicionam complexidade desnecessária. Idempotência preserva safety.
**Trade-off:** Não suporta downgrades. Para mudanças destrutivas (DROP COLUMN), exige script manual.

## ADR-003: PG vs SQLite com helpers de compat
**Data:** já existente
**Decisão:** `dbTrue`/`dbFalse`, `dbDate(d)`, `dbNow()` abstraem diferenças. Detecção automática via `DATABASE_URL`.
**Por quê:** SQLite pra dev/no-infra. PG pra prod com features avançadas (jsonb, materialized views, FTS).

## ADR-004: Materialized views só em PG
**Data:** já existente
**Decisão:** `user_command_transitions`, `user_command_thresholds` existem só em PG. IntelligenceWorker faz REFRESH manual.
**Por quê:** SQLite não tem MV nativo, e o ML de Markov user profile precisa de queries pesadas que MV otimiza muito.
**Trade-off:** Em SQLite, esses recursos rodam em fallback mais lento.

## ADR-005: verifyBlock retorna {verified, method}
**Data:** 2026-05-29
**Decisão:** `verifyBlock(target, ip, method)` retorna `Promise<{verified: boolean; method: 'fail2ban'|'ufw'|null}>` em vez de `Promise<boolean>`.
**Por quê:** Precisava descobrir o método real quando armazenado é null. Retornar o método permite persistir a descoberta.
**Implicação:** Quando `method=null`, probe UFW primeiro (pq `enforceBlocks()` usa UFW por padrão), fail2ban como fallback.
**Arquivos:** `src/playbooks/actions/block-ip.ts`, `src/workers/block-reconcile.worker.ts`, `src/workers/block-propagation.worker.ts`.

## ADR-006: discovery_baselines DB-backed
**Data:** 2026-05-29
**Decisão:** Substitui Map em memória por tabela `discovery_baselines` com upsert via `onConflictDoUpdate`.
**Por quê:** Container restart perdia estado, gerando alertas false-positive de "Re-Discovery: changes detected" toda vez. Persistência elimina o problema.
**Schema:** `server_name PK`, `services JSONB`, `ports JSONB`, `architecture VARCHAR`, `known_containers JSONB`, `captured_at TIMESTAMP`.
**Arquivo:** `src/workers/discovery.worker.ts`.

## ADR-007: Noise reduction com 4 camadas (v3.1.0)
**Data:** 2026-05-29
**Decisão:** Cadeia de supressão de notificações em 4 níveis. (Detalhes em `.claude/projects/.../memory/guardian_noise_layers.md` do user-level memory.)
**Por quê:** Volume de alertas Telegram tornava o canal inútil. 4 camadas cortam ~90% sem perder sinal real.

## ADR-008: ESM-only, .js extension nos imports
**Data:** já existente
**Decisão:** TypeScript compila pra ESM. Todos imports usam `.js` extension mesmo em arquivos `.ts`.
**Por quê:** Node ESM exige resolution explícita; tsup bundle preserva.

## ADR-009: Modelo de instalação guardian-shell (planejado)
**Data:** 2026-05-29 — aprovado pelo usuário, não implementado
**Decisão:** Novos servidores monitorados usam usuário dedicado `guardian` + Python wrapper com allowlist regex + sudoers de 1 linha + authorized_keys com `command=` restrição + fingerprint pinned + heartbeat worker.
**Por quê:** Modelo atual (root + chave sem passphrase + NOPASSWD ALL) tem blast radius de root na frota inteira. Allowlist limita o que SSH consegue fazer mesmo se chave vazar.
**Não implementado ainda:** rsyslog push real-time (v2), append-only PG triggers (v2), migração automática de servidores legacy (v2).

## ADR-010: Multi-agente persistente em .claude/agents/
**Data:** 2026-05-29
**Decisão:** 4 agentes versionados no repo: guardian-architect (opus, orquestrador), guardian-security-installer (opus, install seguro), guardian-docs-writer (sonnet, docs PT+EN), guardian-code-reviewer (opus, read-only review). Cada um com `memory: project` em `.claude/agent-memory/<nome>/`.
**Por quê:** Roadmap do Guardian é longo (4 tiers de auditoria + docs completas + install seguro). Memória persistente evita re-explicar contexto a cada sessão. Project scope (vs user) permite que cada checkout do repo tenha o mesmo time de agentes.
**Trade-off:** 4 system prompts separados pra manter atualizados. Mitigado por delegação clara — cada agente sabe quando passar pro outro.
