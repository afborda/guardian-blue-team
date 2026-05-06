# ML — Estado Atual do Guardian

**Data:** 2026-05-06  
**Versão:** Guardian v1.4.0

---

## 1. O Que Existe Hoje

### 1.1 Anomaly Detector (Z-Score)

**Arquivo:** `src/intelligence/anomaly-detector.ts`

O Guardian usa detecção estatística básica com Z-score sobre 5 métricas:

| Métrica | Cálculo | Threshold |
|---------|---------|-----------|
| `load_ratio` | load1 / cpuCount | Z >= 2.5 |
| `mem_used_percent` | memUsed / memTotal * 100 | Z >= 2.5 |
| `kernel_errors` | contagem raw | Z >= 2.5 |
| `journal_errors` | contagem raw | Z >= 2.5 |
| `disk_max_percent` | max uso disco entre mounts | Z >= 2.5 |

**Lookback:** 7 dias  
**Severidade:** >= 4σ = critical, >= 2.5σ = warning  
**Mínimo de pontos:** 10 (se < 5, ignora)

### 1.2 Trend Predictor (Regressão Linear)

**Arquivo:** `src/intelligence/trend-predictor.ts`

Prediz quando disco/memória atingirão 90% usando regressão linear simples:
- Alerta se days_until_90 < 30 E slope > 0
- R² > 0.3 para considerar significativo
- Lookback: 7 dias

### 1.3 Detection Rules (Determinísticas)

**Arquivo:** `src/pipeline/detector.ts`

16 regras binárias (sim/não), sem probabilidade:
- `ssh_brute_force_burst` (>= 20 falhas do mesmo IP)
- `crypto_mining` (pattern match em nomes de processos)
- `lateral_movement` (login SSH após falhas prévias)
- `unauthorized_login` (IP + fingerprint não confiáveis)
- etc.

### 1.4 Scoring System

**Arquivo:** `src/pipeline/score-calculator.ts`

7 dimensões com pesos fixos, cálculo horário:
- Health (20%), Security (25%), Quality (15%), Waste (10%), Vulnerability (20%), Availability (10%)
- Penalidades hardcoded (ex: cada incidente aberto = -15pts em Security)

---

## 2. Dados Disponíveis Para ML

### 2.1 Eventos de Segurança

Coletados a cada 2 minutos, normalizados pelo pipeline:

```
ssh_failed_password, ssh_invalid_user, ssh_login_success
firewall_block, firewall_allow
docker_die, docker_kill, docker_start, docker_restart
file_modified, file_created, file_deleted, file_permissions_changed
sudo_command
cron_added, cron_removed
dns_query
ssh_key_added, ssh_key_removed
```

**Volume típico:** 40-50 eventos por ciclo de 2min (em servidor ativo com brute force)

### 2.2 Métricas de Infraestrutura

Coletadas a cada 5 minutos:

```
load1, load5, load15, cpuCount
memTotalBytes, memUsedBytes, swapTotalBytes, swapUsedBytes
disks[] (mount, totalBytes, usedBytes, usedPercent)
diskIo[] (device, readsPerSec, writesPerSec, readBytesPerSec, writeBytesPerSec)
networkIo[] (interface, rxBytesPerSec, txBytesPerSec, rxPacketsPerSec, txPacketsPerSec)
failedUnits[], kernelErrors, journalErrors, uptimeSeconds
```

### 2.3 Dados de Contexto

- **Threat Intel:** AbuseIPDB scores cacheados (24h TTL)
- **Blocked IPs:** Histórico com razão, tempo, incidentId
- **Playbook Executions:** Qual playbook rodou, sucesso/falha
- **SOC Incidents:** Incidentes correlacionados com status

### 2.4 Retenção

- Eventos: Sem política de retenção definida (acumula indefinidamente)
- Métricas: Workers de retenção existem mas configuração não é clara
- Scores: Horários, acumulam

---

## 3. Limitações Críticas do Sistema Atual

### 3.1 Sem Aprendizado

O sistema **nunca aprende**. Thresholds são fixos:
- 20 falhas SSH = brute force (sempre, independente do servidor)
- Z >= 2.5 = anomalia (mesmo que o servidor tenha picos regulares)
- IP de RFC 1918 = confiável (sem contexto de rede interna)

### 3.2 Sem Baseline Per-Server

Todos os servidores são tratados igualmente:
- Servidor de CI/CD com CPU spikes regulares gera falsos alertas
- Servidor de banco com disco 80% é "normal" mas gera warning

### 3.3 Sem Correlação Multivariada

Métricas são avaliadas isoladamente:
- Alta CPU + alto disco I/O + processo novo = possível mineração
- Mas o detector só vê "CPU alta" e "disco alto" separadamente

### 3.4 Sem Feedback Loop

- Não há mecanismo para marcar falso positivo
- Não há ajuste de threshold baseado em histórico
- Não há tracking de precisão/recall das detecções

### 3.5 Sem Sazonalidade

- Picos de tráfego em horário comercial = "anomalia" todo dia às 9h
- Backups noturnos = "anomalia" toda noite às 3h

---

## 4. Feature Space Disponível

Dado o que é coletado, estas features poderiam alimentar modelos ML:

### Per-IP (janela de 15 min):
1. `ssh_failed_count` — falhas SSH
2. `ssh_success_count` — logins OK
3. `unique_users_targeted` — usernames distintos tentados
4. `port_scan_count` — bloqueios de firewall de portas distintas
5. `hour_of_day` — 0-23 (normalizado)
6. `is_known_ip` — 0 ou 1 (baseado em histórico)
7. `abuse_score` — score AbuseIPDB (0-100)
8. `event_velocity` — eventos/minuto (aceleração)
9. `geo_country_risk` — score de risco do país (calculável)
10. `connection_diversity` — destinos únicos

### Per-Server (janela de 1 hora):
1. `load_ratio` — load1/cpuCount
2. `mem_percent` — uso de memória
3. `disk_io_rate` — bytes/s lidos+escritos
4. `net_io_rate` — bytes/s rx+tx
5. `event_count_by_type` — distribuição de event types
6. `failed_units` — services com falha
7. `container_restart_count` — containers reiniciados
8. `new_processes` — processos nunca vistos antes
9. `dns_entropy_avg` — entropia média de domínios consultados
10. `ssh_session_count` — sessões SSH ativas

### Per-User (janela de 24h):
1. `login_hours_distribution` — histograma de horas de login
2. `ip_diversity` — IPs distintos usados
3. `fingerprint_known` — 0 ou 1
4. `commands_per_session` — média de comandos sudo
5. `file_modifications` — arquivos alterados

---

## 5. Conclusão do Estado Atual

O Guardian tem uma **excelente infraestrutura de coleta de dados** (coletores maduros, pipeline normalizado, esquema bem definido) mas uma **detecção primitiva** (regras estáticas, sem aprendizado, sem adaptação).

A oportunidade para ML é clara: os dados já estão lá, estruturados e indexados. O que falta é transformar esses dados em inteligência adaptativa.

**Prontidão para ML:**
- ✅ Dados ricos e multifonte (15+ event types)
- ✅ Pipeline maduro (normalização → detecção → correlação → enriquecimento)
- ✅ PostgreSQL 16 (suporta pgvector)
- ✅ Métricas temporais com granularidade de 5 min
- ❌ Sem labels (nenhum evento marcado como "verdadeiro positivo" ou "falso positivo")
- ❌ Sem baseline de "comportamento normal" per-server
- ❌ Sem mecanismo de feedback do operador
- ❌ Sem tracking de eficácia das decisões
