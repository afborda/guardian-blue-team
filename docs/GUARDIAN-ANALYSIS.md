# Guardian — Análise Completa de Funcionalidades, ML e IA

> Documento gerado em 2026-05-31. Reflete o estado do código na versão v3.1.1.

---

## Sumário

1. [O que é o Guardian](#1-o-que-é-o-guardian)
2. [Pipeline de Segurança](#2-pipeline-de-segurança)
3. [Regras de Detecção](#3-regras-de-detecção-30-regras)
4. [Machine Learning](#4-machine-learning)
5. [Inteligência Artificial Generativa](#5-inteligência-artificial-generativa)
6. [Workers](#6-workers-17-jobs-recorrentes)
7. [Playbooks — Resposta Automatizada](#7-playbooks--resposta-automatizada)
8. [Dashboard e Telegram](#8-dashboard-e-telegram)
9. [Banco de Dados](#9-banco-de-dados)
10. [Arquitetura de Segurança do Próprio Guardian](#10-arquitetura-de-segurança-do-próprio-guardian)

---

## 1. O que é o Guardian

O Guardian é um **SIEM/SOAR agentless**: monitora servidores remotos via SSH puro (sem agente instalado), detecta ameaças em tempo real através de um pipeline de 6 etapas, e responde automaticamente com playbooks (bloqueio de IP, isolamento de container, kill de processo). Usa ML local (ONNX) e IA generativa (Ollama → Gemini → OpenAI → Claude) para enriquecer a análise.

```
Servidores monitorados (SSH) → Pipeline → Playbooks → Telegram/Dashboard
```

**Stack:** Node.js + TypeScript + Drizzle ORM + PostgreSQL/SQLite + Ollama (local AI)  
**Porta:** 3334 (configurável via `PORT`)  
**Entry point:** `src/index.ts`

---

## 2. Pipeline de Segurança

Cada evento percorre 6 etapas em sequência:

```
Collectors (SSH)
      ↓
  Normalizer          — padroniza log bruto em NormalizedEvent
      ↓
DGA/Markov Enricher   — ML pré-classificação (roda ANTES do Detector)
      ↓
   Detector           — 30 regras síncronas em buffer circular
      ↓
   Enricher           — Threat Intelligence + SSH Behavior Score
      ↓
  Correlator          — agrupa eventos em incidentes
      ↓
   Ingestor           — persiste em DB, dispara playbooks
```

### 2.1 Collectors — 20 fontes de dados

O `EventCollectorWorker` roda a cada **2 minutos** e aciona todos os collectors em paralelo via SSH.

| Collector | Fonte no servidor remoto | O que extrai |
|-----------|--------------------------|--------------|
| `auth-collector` | `/var/log/auth.log` ou `journalctl -u ssh` | SSH failed, invalid user, login success |
| `ufw-collector` | `/var/log/ufw.log` | Firewall BLOCK (filtra: replies DNS/HTTP/NTP, IPs CGNAT) |
| `docker-collector` | `docker events` | Container die, kill, exec, start |
| `process-collector` | `ps aux` | Processos suspeitos (mineração, shells reversos) |
| `network-collector` | `netstat -tupn` / `ss` | HIGH_CONN, SYN_FLOOD, BANDWIDTH_SPIKE |
| `sudo-collector` | `journalctl -u sudo` | Comandos sudo com usuário e TTY |
| `dns-collector` | `journalctl -u systemd-resolved` | DNS queries (domínio + IP de origem) |
| `syslog-collector` | `/var/log/syslog` | OOM kills, segfaults, erros de hardware |
| `proxy-collector` | Logs HAProxy/nginx | Path traversal, scanners HTTP |
| `package-collector` | `/var/log/dpkg.log` | Instalação de ferramentas ofensivas (nmap, hydra, etc.) |
| `systemd-collector` | `systemctl --failed` | Unidades com falha, restart loops |
| `audit-collector` | `journalctl -o short` | Criação/remoção de usuários, falhas de autenticação |
| `fim-collector` | Hash SHA256 de arquivos críticos | Modificações em /etc/passwd, /etc/sshd_config, etc. |
| `ssh-keys-collector` | `~/.ssh/authorized_keys` | Chaves SSH adicionadas/removidas |
| `cron-collector` | `crontab -l` | Cron jobs novos (persistência) |
| `container-process` | `docker exec <container> ps` | Processos dentro de containers |
| `container-network` | `docker exec <container> netstat` | Conexões de saída de containers |
| `container-filesystem` | Diferença de layers do container | Arquivos novos/alterados em containers |
| `container-config` | `docker inspect <container>` | Segurança: ReadOnly, CapDrop, no-new-privs |
| `container-image-cve` | Trivy + OSV | CVEs em imagens de container (CVSS, pacote afetado) |

**Otimização SSH:** `ControlMaster` com cache de 180s — reutiliza a conexão SSH entre collectors do mesmo servidor para reduzir latência.

### 2.2 Normalizer

Converte cada log bruto em um `NormalizedEvent` com campos padronizados:

```typescript
{
  serverId, timestamp, source, category, severity,
  eventType,       // ex: 'ssh_failed_password', 'firewall_block'
  sourceIp,        // IP de origem extraído do log
  destinationPort,
  userName,
  processName,
  rawLog,          // linha original
  metadata         // campos extras específicos do evento
}
}
```

### 2.3 DGA/Markov Pre-Enricher

Roda **antes** do Detector porque os modelos de ML são assíncronos e o Detector é síncrono. Adiciona metadados ao evento antes que as regras o avaliem.

- **DNS queries** → modelo DGA classifica o domínio (ver seção 4.1)
- **sudo_command** → Markov calcula surprisal da transição (ver seção 4.5)

### 2.4 Enricher (pós-Detector)

Após a detecção, enriquece os eventos detectados com:

1. **Supressão de IPs já bloqueados** — eventos de IPs ativos na lista de bloqueio são rebaixados para `info` (reduz ruído)
2. **False Positive Filter** — modelo de aprendizado de FPs históricos; rebaixa se confiança > threshold
3. **Threat Intelligence** — consulta AbuseIPDB e VirusTotal; se score >= 90 sobe 2 níveis de severidade, >= 50 sobe 1
4. **SSH Behavior Score** — perfil histórico de login do usuário; se score >= 0.7 sobe para `high`

### 2.5 Correlator

Agrupa eventos relacionados em incidentes:

| Tipo de incidente | Trigger | Janela | Threshold |
|-------------------|---------|--------|-----------|
| Brute Force | `ssh_failed_password` / `ssh_invalid_user` | 10 min | >= 10 eventos mesma IP |
| Port Scan | `firewall_block` | 30 min | >= 10 portas distintas mesma IP |
| Unauthorized Access | `unauthorized_login`, `lateral_movement` | — | 1 evento |
| DDoS | `syn_flood`, `connection_rate_spike`, `bandwidth_spike` | — | 1 evento por servidor |

---

## 3. Regras de Detecção (30 regras)

O Detector mantém um **buffer circular de 2000 eventos** e aplica todas as regras sincronamente a cada novo evento.

| # | Regra | Trigger | Severidade |
|---|-------|---------|------------|
| 1 | `crypto_mining` | Processo com padrão xmrig/minerd/cpuminer/kinsing | critical |
| 2 | `ssh_brute_force_burst` | 20+ falhas SSH da mesma IP no buffer | high |
| 3 | `suspicious_binary` | Execução de /tmp/, /dev/shm/, diretório oculto | high |
| 4 | `lateral_movement` | Login SSH bem-sucedido após brute force da mesma IP | critical |
| 5 | `container_escape_attempt` | 5+ container die/restart do mesmo container em 10 min | high |
| 6 | `high_connection_flood` | Evento HIGH_CONN_COUNT do network collector | medium |
| 7 | `syn_flood_detected` | Evento SYN_FLOOD (> 50 half-open) | critical |
| 8 | `bandwidth_spike` | Evento BANDWIDTH_SPIKE (anomaly detection) | high |
| 9 | `connection_rate_spike` | > 100 novas conexões/seg | high |
| 10 | `unauthorized_login` | Login SSH de IP não-confiável com fingerprint desconhecido | high |
| 11 | `password_login` | Login SSH com senha em vez de chave | high |
| 12 | `unusual_hour_login` | Login SSH entre 00:00–06:00 BRT de IP não-confiável | medium |
| 13 | `critical_file_modified` | Modificação em /etc/passwd, /etc/shadow, /etc/sudoers, sshd_config | critical |
| 14 | `sudo_suspicious_command` | sudo com curl, wget, chmod 777, bash -c, /tmp/, etc. | high |
| 15 | `sudo_unusual_sequence` | Transição de comando sudo com Markov surprisal > p99 do usuário | medium |
| 16 | `suspicious_cron_added` | Cron job novo com curl/wget/bash -c//tmp/ | high |
| 17 | `unauthorized_ssh_key` | Nova chave em authorized_keys | high |
| 18 | `dns_dga_detected` | Domínio classificado como DGA pelo modelo ONNX | high |
| 19 | `dns_suspicious_tld` | Query para .tk, .ml, .ga, .cf, .top, .xyz, .pw, .cc | medium |
| 20 | `proxy_path_traversal` | Path com ../ ou %2e%2e em requisição proxy | high |
| 21 | `proxy_scanner_burst` | 10+ requisições scanner da mesma IP no buffer | medium |
| 22 | `systemd_restart_loop` | 3+ falhas da mesma unidade systemd no buffer | high |
| 23 | `package_suspicious_install` | Instalação de nmap, hydra, hashcat, metasploit, etc. | high |
| 24 | `oom_kill_repeated` | 2+ OOM kills no buffer | high |
| 25 | `container_crypto_process` | Processo de mineração dentro de container | critical |
| 26 | `container_suspicious_exec` | Execução de /tmp/ ou /dev/shm/ dentro de container | high |
| 27 | `container_mining_network` | Container conectando em porta de mining pool (3333, 4444, 5555, 8888...) | critical |
| 28 | `container_fs_tampering` | Arquivo executável novo em /tmp/ ou /dev/shm/ de container | high |
| 29 | `container_critical_cve` | CVE com CVSS >= 9.0 em imagem de container | critical |
| 30 | `oom_kill_repeated` | 2+ OOM kills em período | high |

**Cooldown:** Regras como `systemd_restart_loop` e `container_fs_tampering` têm cooldown de 30 min por (servidor, regra, unidade) para evitar spam de alertas em problemas persistentes.

---

## 4. Machine Learning

O Guardian tem **6 modelos de ML** organizados em duas categorias:

- **Modelos ONNX** (LogisticRegression, exportados do scikit-learn): DGA Classifier, IP Threat Classifier
- **Modelos probabilísticos em memória**: Markov Chain, SSH Behavior Profiler, Container Behavior Profiler
- **Decomposição estatística**: STL (Seasonal-Trend Decomposition) + Sigma para anomalia de métricas

### 4.1 DGA Classifier (ONNX)

**Objetivo:** Identificar domínios gerados por algoritmo (Domain Generation Algorithm), usados por malware para comunicação C2.

**Arquivo:** `src/intelligence/dga-classifier.ts` + `dga-features.ts`  
**Modelo:** `models/dga.onnx` + `models/dga.meta.json`  
**Treinamento:** `python3 scripts/train_dga.py`

**Features (16):**
- Frequência de caracteres (a–z, 0–9, símbolos)
- Log-probabilidades de bigramas (tabela 27×27 pré-calculada)
- Comprimento do domínio

**Fluxo:**
```
DNS query → extractFeatures(domain) → tensor float32[1,16]
         → ONNX inference → P(DGA) → isDga = score >= threshold
```

**Fallback (sem onnxruntime):** Entropia de Shannon pura
- Se entropy > 3.5 **E** comprimento >= 20 → isDga = true

**Output adicionado ao metadata do evento:**
```json
{ "dgaIsDga": true, "dgaScore": 0.87, "dgaSource": "model" }
```

---

### 4.2 IP Threat Classifier (ONNX)

**Objetivo:** Classificar IPs como perigosos com base no histórico de comportamento no próprio Guardian.

**Arquivo:** `src/intelligence/ip-classifier.ts` + `ip-features.ts`  
**Modelo:** `models/ip_classifier.onnx`  
**Roda a cada:** 2h (via `IpThreatScorerWorker`)

**Features (11):**

| Feature | Descrição |
|---------|-----------|
| `ratioHighCritical` | % de eventos high/critical |
| `hasBruteForce` | Teve tentativa de brute force |
| `hasLateralMovement` | Teve movimento lateral |
| `hasCryptoMining` | Associado a mineração |
| `hasProxyScanner` | Scanner HTTP detectado |
| `hadSuccess` | Teve login bem-sucedido |
| `wasEscalated` | Foi escalado por alguma regra |
| `distinctServers` | Número de servidores afetados |
| `maxIncidentSeverity` | Severidade máxima (0–4) |
| `abuseScore` | Score do AbuseIPDB (0–100) |
| `vtMalicious` | Vendors VirusTotal marcando como malicioso |

**Threshold:** 0.6 (acima = perigoso)

**Fallback (sem ONNX):** Score heurístico ponderado (mesmo conjunto de features, combinação linear com pesos manuais).

---

### 4.3 Anomaly Detector — STL + Sigma

**Objetivo:** Detectar anomalias em métricas de saúde do servidor (CPU, memória, erros de kernel, disco).

**Arquivo:** `src/intelligence/anomaly-detector.ts` + `stl.ts`  
**Roda a cada:** 1h (via `IntelligenceWorker`)

#### Método Sigma (z-score clássico)
- Lookback: 7 dias
- Thresholds: 2.5σ = warning, 4σ = critical
- Métricas: `load_ratio`, `mem_used_percent`, `kernel_errors`, `journal_errors`, `disk_max_percent`

#### Método STL (decomposição sazonal)
Aplicado quando há padrão diário detectável:

```
y(t) = trend(t) + seasonal(t) + residual(t)
```

- **Trend:** Média móvel centrada (janela = período)
- **Seasonal:** Média por fase (hora do dia), centrada
- **Residual:** Diferença após remover trend + seasonal

Scoring via **MAD (Median Absolute Deviation)** — robusto a outliers:
```
z = |residual - median(residuals)| / MAD
z >= 3 → warning
z >= 5 → critical
```

**Rejeita STL se:**
- Menos de 4 amostras/dia (cadência irregular)
- Gaps > 2h na série (desalinhamento de fase)

---

### 4.4 SSH Behavior Profiler

**Objetivo:** Detectar logins SSH anômalos baseado no histórico do usuário.

**Arquivo:** `src/intelligence/ssh-behavior.ts`  
**Roda a cada:** 1h (perfil rebuiltado com 30 dias de histórico)

**Perfil por usuário:**
- Distribuição de horas de login (array[24])
- Top 20 IPs por frequência
- Fingerprints SSH conhecidas (até 10)
- Média de logins por dia

**Scoring de um login:**
```
score = 0
+ 0.30  se IP desconhecido
+ 0.30  se hora com <5% frequência histórica ("unusual hour")
+ 0.15  se hora com <10% frequência ("rare hour")
+ 0.20  se fingerprint desconhecida
+ 0.20  se taxa de login atual > 3× média diária

score >= 0.85 → critical
score >= 0.70 → high
score >= 0.50 → medium
score >= 0.30 → low
```

---

### 4.5 Markov Chain — Sequências de Sudo

**Objetivo:** Detectar comandos sudo incomuns com base nas transições históricas do usuário.

**Arquivo:** `src/intelligence/markov-user-profile.service.ts` + `markov-enricher.ts`  
**Atualização:** Diária (90 dias de histórico)

**Modelo:** Cadeia de Markov de primeira ordem
- Estado = comando sudo (ex: `apt`, `systemctl`, `nano`)
- Transição = P(comando_atual | comando_anterior)

**Cálculo de Surprisal:**
```
surprisal = -log2( P(cmd_atual | cmd_anterior) )

threshold = percentil 99 do histórico de surprisals do usuário
isAnomaly = surprisal > threshold
```

**Output adicionado ao metadata:**
```json
{ "markovSurprisal": 8.2, "markovThreshold": 5.1, "markovIsAnomaly": true }
```

---

### 4.6 Trend Predictor

**Objetivo:** Prever esgotamento de recursos (disco, memória) com base em regressão linear.

**Arquivo:** `src/intelligence/trend-predictor.ts`

```
Se slope > 0 (crescimento):
  daysUntil90% = (90 - current%) / daily_growth_rate
  Se daysUntil90 < 14 dias → alerta com confidence = R²
```

---

## 5. Inteligência Artificial Generativa

### 5.1 Cascade de Provedores

**Arquivo:** `src/services/ai-provider.ts`

O Guardian usa IA generativa com estratégia **local-first** para minimizar custo e latência:

```
Ollama (local, 180s timeout)
    → Google Gemini
        → OpenAI
            → Anthropic Claude
                → Fallback: regra heurística
```

**Estratégias configuráveis (`AI_STRATEGY`):**
- `auto` (default): cascata completa
- `local-only`: só Ollama
- `api-only`: pula Ollama, vai direto para cloud

**Warm-up:** Na startup, faz uma chamada trivial ao Ollama com `keep_alive: 10m` para pré-carregar o modelo na RAM.

### 5.2 Onde a IA é Usada

| Função | Worker | Frequência | O que analisa | Output |
|--------|--------|-----------|---------------|--------|
| **Threat Hunting** | `ThreatHunterWorker` | 4h | 500 eventos das últimas 6h — busca padrões coordenados, APT slow-roll, movimento lateral, scanning distribuído | JSON: `findings[]`, `overallRisk`, `summary` |
| **Advisory de Bloqueio** | `EventCollectorWorker` | Por evento crítico | "Dado este IP e contexto TI, devo bloquear, monitorar ou rate-limit?" | `{ action, confidence, reasoning }` |
| **Remediação de CVE** | `CveRemediationService` | Por CVE nova | "CVE X afeta app Y na versão Z — como remediar?" | Texto de recomendações |
| **RAG de Incidentes** | `IncidentMemoryService` | Por incidente | Histórico de incidentes similares como contexto | Resumo de padrões passados |
| **SOC Analyst** | `SocAnalystService` | On-demand (Telegram `/ask`) | Pergunta livre do operador | Análise em texto |

### 5.3 Threat Hunter em Detalhe

O `ThreatHunterWorker` é o único componente totalmente proativo — não reage a um evento específico, mas analisa o conjunto:

1. Carrega os **500 eventos mais recentes** das últimas 6h de todos os servidores
2. Constrói um prompt estruturado com: servidor, timestamp, tipo, severidade, IP, usuário
3. Pede à IA para identificar: correlações temporais, padrões de IP, sequências de ataque em múltiplas fases
4. Recebe JSON com findings classificados por severidade
5. Salva em `threat_hunt_findings` e notifica via Telegram se severity = high ou critical

---

## 6. Workers — 17 Jobs Recorrentes

Todos os workers implementam `start()` / `stop()` e são iniciados em sequência no `src/index.ts`. O graceful shutdown usa `Promise.allSettled` para parar todos antes de sair.

| Worker | Intervalo | Função principal |
|--------|-----------|-----------------|
| `EventCollectorWorker` | **2 min** | Loop principal: coleta → pipeline → playbooks |
| `ScoreCalculatorWorker` | 5 min (métricas) / 1h (scores) | CPU, RAM, disco, scores compostos de saúde/segurança |
| `DDoSEscalationWorker` | **2 min** | IPs em rate-limit que reataquerem em 10 min → block permanente |
| `IntelligenceWorker` | **1h** (Markov: 24h) | Anomalia STL/sigma, trend, SSH/container behavior profiles |
| `FIMWorker` | **4h** | File Integrity Monitoring — SHA256 de arquivos críticos |
| `ThreatHunterWorker` | **4h** | Análise proativa com IA — caça padrões em 500 eventos |
| `CVEMonitorWorker` | **6h** | Consulta NVD/OSV por CVEs novas nos pacotes instalados |
| `CVEIntelFeedsWorker` | Diário (03:17 UTC) | Atualiza feeds EPSS + CISA KEV |
| `VulnScannerWorker` | Semanal (Sáb 09:00 BRT) | Trivy, port scan, SSL check, docker audit |
| `DailyReportWorker` | Diário (08:00 BRT) | Relatório de segurança do dia anterior via Telegram |
| `BlockCleanupWorker` | **5 min** | Remove bloqueios temporários expirados |
| `BlockPropagationWorker` | **2 min** | Sincroniza bloqueios novos para UFW/iptables de todos os servidores |
| `BlockReconcileWorker` | **15 min** | Verifica divergência entre DB e estado real UFW/iptables |
| `DiscoveryWorker` | On-demand (CLI) | Probe remoto: detecta serviços, containers, gera config |
| `ContainerSecurityWorker` | 2/5/30/60 min | Processos, rede, FS e config de containers |
| `IpThreatScorerWorker` | **2h** | Reclassifica IPs ativas com IP Classifier ONNX |
| `MetricsRetentionWorker` | Diário | Deleta métricas > 90 dias |

---

## 7. Playbooks — Resposta Automatizada

**Arquivo:** `src/playbooks/registry.ts` + `engine.ts`

O `PlaybookEngine` executa uma lista de steps sequenciais com condições opcionais. Playbooks marcados como `requiresApproval: true` criam um botão inline no Telegram para aprovação manual antes de executar.

**Deduplicação:** Mesmo playbook + mesma IP não dispara 2x em 5 min.

### 7.1 Playbooks Definidos

| Playbook | Trigger | Ações | Aprovação |
|----------|---------|-------|-----------|
| `ssh-brute-force` | 10+ falhas SSH | enrich-ip → block-ip permanente → notify | Não |
| `port-scan-response` | 10+ portas distintas | enrich-ip → block-ip permanente → notify | Não |
| `crypto-mining-response` | crypto_mining | kill-process → block-ip → notify (critical) | Não |
| `lateral-movement-response` | lateral_movement | enrich-ip → block-ip → notify (critical) | Não |
| `container-escape-response` | container_escape | pause-container → disconnect-container → notify | **Sim** |
| `ddos-syn-flood-response` | syn_flood | enrich-ip → rate-limit (10/s burst 20) → notify | Não |
| `connection-flood-response` | high_conn_flood | enrich-ip → block-ip → notify | Não |
| `file-integrity-response` | critical_file_modified | notify (critical, "investigate now") | **Sim** |
| `cron-persistence-response` | cron_persistence | notify (high, "persistence detected") | **Sim** |
| `ssh-key-response` | unauthorized_ssh_key | notify (high, "new key added") | **Sim** |
| `container-crypto-response` | container_crypto | kill-process → disconnect → restart → notify | Não |
| `container-mining-network-response` | mining_port conn | disconnect → restart → notify | Não |
| `container-auto-update` | CVE CVSS >= 9.0 | pull-image → recreate-container → notify | **Sim** |
| `dns-c2-response` | dns_dga | notify (high, "C2 communication") | Não |
| `sudo-suspicious-response` | sudo_suspicious | notify (high) | Não |

### 7.2 Ações Registradas

| Ação | O que faz |
|------|-----------|
| `block-ip` | Adiciona IP em UFW, iptables (GUARDIAN-INPUT chain) ou fail2ban via SSH. Persiste em `blocked_ips`. |
| `unblock-ip` | Remove regra UFW/iptables, marca inativo no DB. |
| `rate-limit` | Insere regra iptables de rate-limit na chain GUARDIAN-INPUT. |
| `kill-process` | SSH: `pkill -f <pattern>` no processo alvo. |
| `pause-container` | `docker pause <container>`. |
| `disconnect-container` | `docker network disconnect` — isola o container. |
| `kill-container-process` | `docker exec <container> killall <process>`. |
| `restart-container` | `docker restart <container>`. |
| `pull-container-image` | `docker pull <image>:latest`. |
| `recreate-container` | `docker rm` + `docker run` com opções originais. |
| `enrich-ip` | Consulta AbuseIPDB + VirusTotal, atualiza metadata do evento. |
| `notify` | Envia notificação via Telegram/Slack/Discord/Email/ntfy/Webhook. |

---

## 8. Dashboard e Telegram

### 8.1 Dashboard

Renderizado server-side com HTMX. Acessível em `/dashboard`.

**Autenticação:** Token único (`DASHBOARD_TOKEN`) ou multi-usuário (`DASHBOARD_USERS=user:token:role;...`). Rate limit: 60 req/min por IP.

**Páginas:**
- Overview — servidores ativos, incidentes abertos, scores
- Incidents — detalhes e ações
- Events — log de eventos com filtros
- Vulnerabilities — CVEs por servidor

**API JSON:** `/api/dashboard/servers`, `/api/dashboard/incidents`, `/api/dashboard/events`, `/api/dashboard/scores`

### 8.2 Telegram

**Rate limit:** 10 comandos/min por chat

| Comando | Função |
|---------|--------|
| `/status` | Resumo de todos os servidores |
| `/incidents` | Incidentes abertos com ações inline |
| `/events` | Últimos eventos de segurança |
| `/health` | CPU, RAM, disco por servidor |
| `/scores` | Scores compostos de segurança |
| `/threat <ip>` | Investigar reputação de IP |
| `/block <ip>` | Bloquear IP no firewall |
| `/ask <pergunta>` | Pergunta livre à IA |
| `/report` | Relatório de segurança on-demand |
| `/vulns` | CVEs abertas |
| `/versions` | Versões de runtimes nos servidores |
| `/dashboard` | Gera token temporário + URL |

**Callbacks inline:**
- ✅ Aprovar / ❌ Rejeitar playbook
- 🚨 False Positive — aprende e suprime
- ✓ Resolvido — fecha incidente

---

## 9. Banco de Dados

**Suporte:** PostgreSQL (produção) e SQLite (dev). Seleção automática via `DATABASE_URL`.

**Schema:** DDL-in-code via `CREATE TABLE IF NOT EXISTS` — sem migration runner.

**Tabelas principais:**

| Tabela | Conteúdo |
|--------|---------|
| `servers` | Hosts monitorados (host, SSH config, enabled) |
| `security_events` | Todos os eventos detectados pelo pipeline |
| `soc_incidents` | Incidentes correlacionados (status: open/resolved/acknowledged) |
| `blocked_ips` | IPs bloqueados com método (ufw/iptables/fail2ban) e expiração |
| `server_metrics` | Métricas de saúde (CPU, RAM, disco, erros) — retenção 90 dias |
| `server_scores` | Scores compostos por período (health, security, quality, waste, vuln) |
| `cve_alerts` | CVEs encontradas por servidor |
| `playbook_executions` | Histórico de execução de playbooks com steps |
| `threat_hunt_findings` | Achados do Threat Hunter (IA) |
| `behavior_profiles` | Perfis SSH e container por usuário/container |
| `markov_profiles` | Matrizes de transição Markov por usuário |
| `trusted_entities` | IPs e fingerprints confiáveis (whitelist) |
| `incident_memory` | Feedback histórico (FP, resolved) para aprendizado |
| `discovery_baselines` | Estado de serviços/containers para diff de descoberta |

---

## 10. Arquitetura de Segurança do Próprio Guardian

O Guardian implementa proteções no seu próprio código:

- **GUARDIAN-INPUT chain:** Regras de firewall são criadas em chain dedicada — `iptables -F INPUT` de um operador não apaga mais as regras do Guardian
- **`isPrivateIp()` centralizado:** Cobre RFC1918 + loopback + link-local + IPv6 ULA (fe80::/10) — substitui comparações frágeis com `startsWith('172.')`
- **Webhook Telegram fail-closed:** Sem `TELEGRAM_WEBHOOK_SECRET` → responde 503 (rejeita POSTs anônimos)
- **`/health` sem version leak:** Versão da aplicação removida da resposta pública
- **SYN flood sem escalação:** SYN srcIP é spoofável — Guardian não bane IPs por SYN flood (evita ser usado para banir DNS público como 8.8.8.8)
- **SSH ControlMaster:** Reutiliza conexões, não mantém sessão root aberta desnecessariamente
- **Noise reduction em 4 camadas:** Cooldown, false positive filter, supressão de IPs já bloqueados, deduplicação cruzada
