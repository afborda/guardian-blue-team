# Guardian Blue Team — Plano de Hardening
**Data:** 2026-05-20
**Versão atual auditada:** 2.1.0 (`/tmp/guardian-src-new`, deployed em `/root/.guardian` no Hetzner)
**Stack:** TypeScript + Node.js + PostgreSQL + Ollama (qwen3) + Drizzle ORM + Express

---

## 1. Sumário executivo

Guardian é um SOAR caseiro maduro: 14 workers, 22 regras de detecção, pipeline de eventos de 6 estágios (ingestor → normalizer → correlator → enricher → detector → score-calculator), threat intelligence com AbuseIPDB+VirusTotal+circuit breaker, FIM com baseline em DB, RAG via `incident_memory`, AI block advisor, playbooks com aprovação Telegram, dashboard Express, e CLI rico. **A arquitetura está sólida.** Os problemas observados são bugs específicos e gaps de visibilidade, não falhas de design.

### Principais achados

| # | Issue | Severidade | Esforço |
|---|-------|-----------|---------|
| 1 | **Self-detection bug** em `process-collector.ts` — Guardian detecta a si mesmo como minerador a cada 4 min | 🔴 Alta | 2h |
| 2 | **Sem visibilidade dentro de containers** — incidente cryptominer de maio escapou (memória) | 🔴 Alta | 1-2 sem |
| 3 | **FIM detecta mudança mas não tem baseline confiável** — primeira execução vira "verdade" mesmo se servidor já comprometido | 🟡 Média | 3-5 dias |
| 4 | **Threat intel não é gate de bloqueio** — AI advisor decide sozinho, sem cross-check com feeds externos antes de banir | 🟡 Média | 2-3 dias |
| 5 | **Schema confusion** — `audit_logs` usa `event_type/action/result` mas alguns lugares chamam `operation/status` | 🟢 Baixa | 1h |
| 6 | **synthfin estava enabled** apesar de decommissionado — gerava failures de coleta a cada 2 min | 🟢 Baixa | ✅ Resolvido |
| 7 | **Sem deduplicação por containerId** na regra `container_crypto_process` | 🟡 Média | 4h |
| 8 | **`incident_memory` (RAG) usa similarity por embedding mas sem reranking** — pode trazer contexto irrelevante para o LLM | 🟢 Baixa | 1 sem |

---

## 2. Bugs concretos (correções imediatas)

### 2.1 Self-detection do crypto miner

**Arquivo:** `src/collectors/process-collector.ts:46`
**Arquivo correlato:** `src/collectors/container-runtime-collector.ts` (mesmo padrão)

**Bug:**
```typescript
// Linha atual:
ps aux 2>/dev/null | grep -i '${grepPattern}' | grep -v grep || echo ''
```
Quando Guardian executa este comando via SSH, a linha do *próprio comando ssh* aparece em `ps aux` no host alvo. O argumento contém literalmente `xmrig|minerd|cpuminer|...`, e o `grep -v grep` filtra apenas linhas com a palavra `grep`, não com `ssh`. Resultado: 298 false positives nas últimas 24h só no Hetzner.

**Fix recomendado (defensivo):**
```typescript
// Filtrar comm field (process name) ao invés de cmdline completo
const cmd =
  `ps -eo pid,user,pcpu,pmem,comm,args --no-headers 2>/dev/null | ` +
  // comm field é o nome do executável, não os args — não tem o padrão do grep
  `awk -v pat='${grepPattern}' 'tolower($5) ~ pat { print }' || echo ''`;
```
Alternativa mais robusta: usar `pgrep -f` + `ps -p $PIDS -o ...`, com `--ignore` da PID atual do coletor.

**Validação:** Após deploy, rodar 1h e verificar que `SELECT COUNT(*) FROM security_events WHERE event_type='container_crypto_process'` permanece em 0.

### 2.2 Schema audit_logs

**Onde aparece:** o user mencionou "0 IPs" no daily report e queries antigas que falham. Consultas em código que ainda usem `operation`/`status` precisam ser migradas para `action`/`result`.

**Fix:** `grep -rn "audit_logs.*operation\|audit_logs.*status" src/` no projeto e renomear para o schema atual. Drizzle vai pegar isso em build se você adicionar `as const` nos selects.

### 2.3 Dedup por container

**Arquivo:** `src/pipeline/detector.ts` regra `container_crypto_process`

```typescript
// Após confirmar match, suprimir se já alertou no mesmo containerId nos últimos 30 min
condition: (events, current) => {
  if (current.source !== 'container_process') return false;
  if (!CONSTANTS.cryptoMiningPatterns.test(current.rawLog)) return false;

  const containerId = current.metadata?.containerId as string | undefined;
  if (!containerId) return false;

  // Dedup: se mesmo containerId já gerou alerta nos últimos 30 min, suprimir
  const recentSame = events.filter(e =>
    e.eventType === 'container_crypto_process' &&
    e.metadata?.containerId === containerId &&
    e.timestamp.getTime() > Date.now() - 30 * 60 * 1000
  ).length;

  return recentSame === 0;
},
```

---

## 3. Gaps de visibilidade — onde o miner de maio passou

### 3.1 In-container runtime visibility

**Problema:** o XMRig em containers do synthfin escapou porque Guardian só observa **fora** dos containers (via `ps aux` no host vê processos containerizados, mas só do host point-of-view; events do Docker daemon; container snapshots a cada 2 min). Não há tracing do **comportamento dentro** do container.

**Solução: integrar Falco** — eBPF-based runtime security monitor.

#### Por que Falco
- Padrão de fato em K8s/Docker security
- eBPF: visibilidade kernel-level sem agent dentro do container
- Detecta: `Mining cryptocurrency`, `Outbound to mining pool`, `Write below etc`, `Run shell untrusted`
- Output em JSON via gRPC ou stdout/syslog → fácil consumir no pipeline existente

#### Arquitetura proposta
```
Falco daemon (host) → JSON output → Guardian collector → normalizer → existing pipeline
```

**Implementação:**
1. Deploy Falco como container privilegiado em cada servidor monitorado:
   ```yaml
   falco:
     image: falcosecurity/falco-no-driver:latest
     privileged: true
     pid: host
     volumes:
       - /var/run/docker.sock:/host/var/run/docker.sock
       - /dev:/host/dev
       - /proc:/host/proc:ro
       - /boot:/host/boot:ro
       - /lib/modules:/host/lib/modules:ro
       - /usr:/host/usr:ro
       - /etc:/host/etc:ro
   ```
2. Criar `src/collectors/falco-collector.ts` — lê via SSH `journalctl -u falco -f --output=json`
3. Mapear eventos Falco → `NormalizedEvent` no `normalizer.ts`
4. Adicionar regras no `detector.ts` para event types Falco (`falco_crypto_mining`, `falco_unexpected_outbound`, `falco_write_below_etc`)

**Esforço:** 1-2 semanas (deploy + collector + 6-8 novas regras)

**ROI:** este é o investimento de maior payoff. Falco teria alertado sobre o XMRig em <30s ao invés de descoberta tardia.

### 3.2 FIM com baseline confiável (AIDE pattern)

**Problema atual:** `fim.worker.ts` linha 96-107 faz `if (isFirstRun) { upsert all; return }`. Isso quer dizer: se o servidor *já* estava comprometido na primeira execução, o malware vira parte do baseline. Tampering posterior é detectado, mas o estado inicial não é validado.

**Solução híbrida:**

1. **Curto prazo:** integrar [AIDE](https://aide.github.io/) como fonte adicional. AIDE tem hashes assinados e configuração baseada em policy.
   ```bash
   # No host: AIDE roda diariamente, gera /var/lib/aide/aide.db
   # Guardian SSH: lê o report do AIDE
   sudo aide --check --config=/etc/aide/aide.conf
   ```
2. **Longo prazo:** suporte para "trusted baseline manual" — operador pode marcar via Telegram `/fim_trust <server>` somente após attestation visual; até lá, o servidor fica em modo "all changes are alerts".

**Esforço:** 3-5 dias (collector + parser de output AIDE + storage de baseline assinado)

### 3.3 OSQuery para endpoint forensics on-demand

OSQuery transforma o sistema operacional em base SQL. Útil para forenses ad-hoc via Telegram:
```
/query SELECT name, path, hash FROM startup_items WHERE source != 'systemd';
```

**Implementação leve:** SSH-based, não precisa daemon. Comando: `osqueryi --json "SELECT ..."`. Adicionar `src/services/osquery.service.ts` com queries pré-aprovadas.

**Esforço:** 2-3 dias

---

## 4. Threat intel como gate de bloqueio

### Estado atual
`AIBlockAdvisor.getRecommendation` passa o IP para o LLM (qwen3) que retorna ação. Não há cross-check obrigatório com AbuseIPDB antes de banir, embora `ThreatIntelManager.lookupIP` exista. RAG injeta histórico de incidentes mas não score de feeds externos.

### Proposta: política de duas chaves

```typescript
// Antes de qualquer block_permanent:
async function shouldBlock(ip: string, eventCtx): Promise<Decision> {
  const ti = await ThreatIntelManager.lookupIP(ip);
  const ai = await AIBlockAdvisor.getRecommendation(ctx, eventCtx);

  // Política:
  // - Se TI score >= 75 OU 3+ "malicious" no VT → block_permanent (auto)
  // - Se TI score 30-74 → respeita AI advisor mas exige confidence >= 70
  // - Se TI score < 30 → max ação = rate_limit (nunca permanent sem human)
  // - Se TI indisponível → AI sozinho, mas exige confidence >= 85

  if (ti && ti.score >= 75) return { action: 'block_permanent', source: 'ti_high_score' };
  if (ti && ti.score >= 30 && ai.action === 'block_permanent' && ai.confidence >= 70)
    return { action: 'block_permanent', source: 'ti_ai_consensus' };
  if (!ti && ai.confidence < 85) return { action: 'monitor', source: 'no_ti_low_confidence' };
  return ai;
}
```

### Adicionar feeds extras

| Feed | Custo | Cobertura | Vale a pena? |
|------|-------|-----------|--------------|
| AbuseIPDB | grátis (1k/dia) | reports de honeypots | ✅ já existe |
| VirusTotal | grátis (4 req/min) | malware/phishing | ✅ já existe |
| **CrowdSec CTI** | grátis (limited) | comportamental, comunidade | 🟢 adicionar (boa cobertura BR) |
| **AlienVault OTX** | grátis | pulses de threat hunters | 🟢 adicionar |
| Spamhaus DROP | grátis | redes confirmadas hostis | 🟢 lista estática, importar em init |
| GreyNoise | grátis (community) | distingue scanner massivo de targeted | 🟢 reduz noise |

**Esforço:** 2-3 dias (adicionar 2 clientes na pasta `threat-intel/`, integrar no `manager.ts`)

---

## 5. Hardening do Guardian em si

### 5.1 Container security do Guardian

**Auditoria atual:**
- `guardian` container roda como ? (verificar)
- Acessa `/var/run/docker.sock` (verificar) — vetor de escape
- Tem chave SSH privada (`/data/guardian_ed25519`) com root em todos os servidores monitorados → **se Guardian for comprometido, é game over**

**Recomendações:**
1. **Read-only rootfs** com `tmpfs` para `/tmp`, `/data` em volume separado
2. **`no-new-privileges` + cap_drop ALL** + adicionar só caps necessárias
3. **Chave SSH com `command=` restriction** em `authorized_keys`:
   ```
   command="/usr/local/bin/guardian-allowed-commands.sh",no-port-forwarding,no-X11-forwarding ssh-ed25519 AAAA...
   ```
   Onde o script só permite comandos do Guardian (whitelist por hash do comando).
4. **AppArmor/SELinux profile** customizado para o container
5. **Secrets via Docker Swarm secrets ou external file**, não env vars — `docker inspect` vaza env vars facilmente

### 5.2 Resilience / observability

| Adicionar | Lib | Por quê |
|-----------|-----|---------|
| Distributed tracing | `@opentelemetry/sdk-node` | Pipeline tem 6 estágios, debug é difícil sem traces |
| Métricas Prometheus | `prom-client` | Já tem `/metrics` endpoint? Se não, expor counters de eventos por source/severity |
| Health checks profundos | next-app `pino`-aware | `/health` que verifica DB, Ollama, AbuseIPDB circuit, Redis (se houver) |
| Structured alerting | já tem `pino` | Adicionar `pino-loki` ou `pino-elasticsearch` para central log |

### 5.3 Anti-evasion

Cenário: atacante toma um servidor. Primeira ação: parar Guardian collectors ou matar conexão SSH. **Como detectar?**

1. **Heartbeat por servidor:** se `lastEventAt` em `soc_servers` ficar > 5 min antigo → alerta crítico (pode ser server down OU coletor sabotado)
2. **Self-integrity:** Guardian verifica seu próprio binário hash a cada hora; se mudou (sem update legítimo via deploy), kill switch
3. **Out-of-band notification:** alertas críticos vão *também* para canal externo (e.g. Pushover, Discord), não só Telegram (caso atacante comprometa o token Telegram)

---

## 6. Tuning e calibração

### 6.1 Regras com false positive rate alto

Baseado em queries no DB (24h):

| Regra | Eventos | Provável fator |
|-------|---------|----------------|
| `container_crypto_process` | 298 | Bug self-detection (§2.1) |
| `crypto_mining` | ? | Mesma família — auditar |
| `unauthorized_login` | ? | Adicionar trustedFingerprints é manual; mover para discovery automático |
| `unusual_hour_login` | ? | BRT 00-06h é cedo para ops oficial mas operador remoto pode logar — calibrar por servidor |

### 6.2 Auto-trust learning

`trusted_entities` table existe (vi no `\dt`) mas não foi vista em uso no código auditado. Sugestão:
- Após 30 dias sem incidente, login fingerprint X em servidor Y vira "auto-trusted"
- IP que apareceu como `ssh_login_success` 50+ vezes sem evento adverso → auto-trusted
- Operador pode revogar via Telegram

### 6.3 Memory anomaly detector

Memória 4.6σ no Hetzner foi alarme legítimo. Verificar:
- Janela de baseline (idealmente 7d ao invés de 24h para suavizar weekly patterns)
- Threshold sigma — 3σ para low-severity, 5σ para high
- Suprimir quando coincidir com janela conhecida de heavy job (e.g. `vuln-scanner.worker` rodando)

---

## 7. Roadmap sugerido

### Sprint 1 (esta semana)
- [ ] Fix self-detection bug em process-collector.ts (§2.1) — **2h**
- [ ] Fix audit_logs schema queries (§2.2) — **1h**
- [ ] Adicionar dedup por containerId em `container_crypto_process` (§2.3) — **4h**
- [ ] ✅ Synthfin disabled (já feito)
- [ ] Calibrar `unusual_hour_login` para excluir `ubuntu`/`root` em janela 06-07h (deploy time) — **30min**

### Sprint 2 (próximas 2 semanas)
- [ ] Threat intel como gate de bloqueio (§4) — **3 dias**
- [ ] CrowdSec + GreyNoise + Spamhaus DROP feeds (§4) — **2 dias**
- [ ] AIDE integração via SSH collector (§3.2) — **3 dias**

### Sprint 3 (mês seguinte)
- [ ] Falco deployment + collector + regras (§3.1) — **2 semanas**
- [ ] OSQuery service + Telegram queries (§3.3) — **3 dias**
- [ ] Container hardening do próprio Guardian (§5.1) — **3 dias**

### Sprint 4 (consolidação)
- [ ] OpenTelemetry tracing + Prometheus metrics (§5.2) — **1 semana**
- [ ] Anti-evasion: heartbeat + self-integrity + out-of-band alerts (§5.3) — **1 semana**
- [ ] Auto-trust learning (§6.2) — **3 dias**

---

## 8. Bibliotecas externas recomendadas

| Lib | Uso | Substituí algo? |
|-----|-----|-----------------|
| **falco** (binary) | eBPF runtime security | Cobre gap, não substitui |
| **aide** (binary) | FIM com baseline assinado | Reforça `fim.worker.ts` |
| **osquery** (binary) | OS forensics SQL | Adiciona capability nova |
| `@opentelemetry/sdk-node` | Distributed tracing | Adiciona observability |
| `prom-client` | Métricas Prometheus | Adiciona observability |
| `@crowdsec/lib-crowdsec` (community) | Threat intel | Adiciona feed |
| `@alienvault/otx-sdk` (não-oficial, pode usar HTTP direto) | Threat intel | Adiciona feed |
| `pino-loki` | Log shipping | Centraliza logs |
| `node-rdkafka` ou `bullmq` | Queue resiliente | **Substituiria** processamento in-memory atual no pipeline — útil se volume crescer |
| `prom-client` + `node-statsd` | Metrics | Adiciona métricas |

**Atenção a NÃO trocar à toa:** `dockerode`, `drizzle-orm`, `pg`, `pino`, `node-cron`, `zod` — todas excelentes escolhas, manter.

---

## 9. Notas finais

Guardian já é **mais sofisticado que muitos SOAR comerciais entry-level** — tem RAG, AI advisor, circuit breakers, threat intel cache, FIM, container security, vuln scanning, daily reports, Telegram approval flow. Os investimentos abaixo aumentam a capacidade real de detecção (Falco, AIDE) e reduzem o ruído operacional (dedup, threat intel gate, auto-trust).

O ataque XMRig de maio aconteceu porque **não havia visibilidade dentro do container** — esse é o gap nº1 a fechar. Falco resolve ~80% disso por conta própria.
