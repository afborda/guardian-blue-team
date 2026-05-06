# ML — Proposta: Statistical Baselines (Fase 1)

**Data:** 2026-05-06  
**Complexidade:** Média  
**Dependências Externas:** Nenhuma (pure TypeScript)  
**Impacto Estimado:** -40-60% falsos positivos

---

## 1. O Que É

Baselines comportamentais por servidor e por usuário que aprendem o que é "normal" ao longo do tempo. Em vez de thresholds fixos globais (Z >= 2.5 para todos), cada servidor e cada usuário tem seu próprio perfil de normalidade.

## 2. Por Que Implementar

### Problema Concreto

**Cenário real no hetzner-prod (servidor do usuário):**

Hoje o Guardian dispara alerta quando:
- CPU sobe acima de 2.5 desvios padrão da média de 7 dias
- SSH falha 20x do mesmo IP

Problemas:
1. **Backups noturnos** (3am) causam spike de disco + CPU → alerta falso todo dia
2. **Admin faz login de IP novo** quando viaja → alerta "unauthorized_login"
3. **Servidor de CI** tem CPU alta em horários de deploy → alerta contínuo
4. **Bots SSH** mandam 15 tentativas (abaixo de 20) e param → nunca detectado

### Solução

Baselines aprendem que:
- "CPU alta às 3am neste servidor = backup (normal)"
- "Login do admin de IP .br em horário comercial = normal, login de IP .ru às 4am = suspeito"
- "Este servidor tem picos de CPU entre 9h-12h = normal"
- "Este IP mandou 5 tentativas ontem, 8 hoje, 12 agora = tendência (alerta cumulativo)"

## 3. Arquitetura Proposta

```
src/intelligence/
├── anomaly-detector.ts       # EXISTENTE → manter como fallback
├── baselines/
│   ├── server-baseline.ts    # NOVO: perfil per-server
│   ├── user-baseline.ts      # NOVO: perfil per-user SSH
│   ├── ip-reputation.ts      # NOVO: scoring cumulativo de IPs
│   └── time-patterns.ts      # NOVO: detecção de sazonalidade
└── scoring-engine.ts         # NOVO: combina scores de todas fontes
```

### 3.1 Server Baseline

```typescript
interface ServerProfile {
  serverId: number;
  metrics: {
    [metricName: string]: {
      hourlyMeans: number[];     // 24 posições (média por hora do dia)
      hourlyStdDevs: number[];   // 24 posições (desvio por hora)
      weekdayFactor: number[];   // 7 posições (multiplicador por dia da semana)
      lastUpdated: Date;
    }
  };
  events: {
    [eventType: string]: {
      normalRatePerHour: number;
      peakHour: number;
      quietHours: number[];     // horas onde taxa < 10% do pico
    }
  };
}
```

**Como funciona:**
1. **Warm-up (7 dias):** Coleta dados sem alertar, constrói perfil
2. **Operação:** Compara nova métrica com `hourlyMeans[hora_atual]` ± `hourlyStdDevs[hora_atual] * threshold`
3. **Atualização:** Exponential Moving Average (EMA) com α=0.1 — incorpora dados recentes gradualmente

**Vantagem sobre Z-score global:** CPU alta às 3am num servidor que faz backup às 3am = score 0.1. CPU alta às 3am num servidor que normalmente está idle = score 0.9.

### 3.2 User Baseline (SSH)

```typescript
interface UserProfile {
  username: string;
  serverId: number;
  loginHours: Map<number, number>;  // hora → frequência normalizada
  knownIPs: string[];               // top 10 IPs mais frequentes (decaying)
  knownFingerprints: string[];      // chaves SSH conhecidas
  avgLoginsPerDay: number;
  typicalSessionDuration: number;   // minutos
  lastSeen: Date;
  daysSinceFirstSeen: number;
}
```

**Scoring (0.0 a 1.0):**

| Fator | Contribuição |
|-------|-------------|
| Login fora do horário habitual | +0.25 |
| IP nunca visto antes | +0.30 |
| Fingerprint nova (primeira vez) | +0.20 |
| Após múltiplas falhas prévias | +0.25 |
| País diferente do habitual | +0.20 |
| Hora entre 00-06 (sem histórico) | +0.15 |

**Threshold de alerta:** Score > 0.65 = WARNING, > 0.80 = HIGH

**Exemplo real:**
- Admin faz login do mesmo IP às 10am todo dia = score 0.0
- Admin faz login de IP novo mas mesmo país, horário normal = score 0.30 (log, sem alerta)
- Login de IP russo às 4am com fingerprint nova após 5 falhas = score 0.95 (CRITICAL)

### 3.3 IP Reputation (Cumulativo)

```typescript
interface IPReputation {
  ip: string;
  firstSeen: Date;
  totalEvents: number;
  failedSSH: number;
  firewallBlocks: number;
  successfulLogins: number;
  targetedUsernames: Set<string>;
  lastActivity: Date;
  decayingScore: number;  // decai 10% por dia sem atividade
  wasBlocked: boolean;
  blockCount: number;
}
```

**Diferença do sistema atual:** Hoje o detector olha apenas a janela atual (20 falhas = bloqueia). O novo sistema acumula: IP que mandou 5 tentativas/dia por 4 dias = 20 tentativas, score crescente, alerta antes de atingir o threshold fixo.

### 3.4 Time Patterns (Sazonalidade)

```typescript
interface TimePattern {
  serverId: number;
  dayOfWeek: number;
  hourOfDay: number;
  expectedMetric: number;
  variance: number;
  sampleCount: number;
}
```

**Resolve:** Backups, crons, CI/CD pipelines. Detecta que "CPU alta às 3am de terça = normal neste servidor" após 3 ocorrências.

## 4. Scoring Engine

O scoring engine combina TODOS os sinais em um score final:

```typescript
interface ThreatScore {
  overall: number;         // 0.0 - 1.0
  components: {
    zScore: number;        // anomalia estatística (existente)
    baseline: number;      // desvio do perfil do servidor
    userBehavior: number;  // desvio do perfil do usuário
    ipReputation: number;  // reputação acumulada do IP
    timingAnomaly: number; // fora do padrão temporal
    velocity: number;      // aceleração de eventos
  };
  explanation: string;     // "CPU 85% is normal for this server at 3am (backup window)"
  confidence: number;      // quão confiante é o score (baseado em quantidade de dados)
}
```

**Fórmula de combinação:**
```
overall = max(components) * 0.4 + weightedAvg(components) * 0.6
```

Usar `max` garante que um sinal muito forte (IP com 100% abuse score) não é diluído pela média de outros sinais normais.

## 5. Armazenamento

### Opção A: Em memória + serialização periódica

Baselines vivem em RAM, serializados para JSON a cada hora:

```
/data/baselines/
├── server-1-profile.json
├── user-profiles.json
└── ip-reputations.json
```

**Prós:** Zero dependências, rápido, simples  
**Contras:** Perde dados se crashar entre persistências, não escala para muitos servidores

### Opção B: PostgreSQL (tabelas dedicadas)

```sql
CREATE TABLE server_baselines (
  server_id INT REFERENCES soc_servers(id),
  metric_name VARCHAR(50),
  hourly_means FLOAT[24],
  hourly_std_devs FLOAT[24],
  weekday_factors FLOAT[7],
  sample_count INT,
  updated_at TIMESTAMP,
  PRIMARY KEY (server_id, metric_name)
);

CREATE TABLE user_baselines (
  username VARCHAR(100),
  server_id INT REFERENCES soc_servers(id),
  login_hours JSONB,
  known_ips TEXT[],
  known_fingerprints TEXT[],
  avg_logins_per_day FLOAT,
  last_seen TIMESTAMP,
  PRIMARY KEY (username, server_id)
);

CREATE TABLE ip_reputations (
  ip INET PRIMARY KEY,
  first_seen TIMESTAMP,
  total_events INT,
  failed_ssh INT,
  firewall_blocks INT,
  successful_logins INT,
  targeted_usernames TEXT[],
  decaying_score FLOAT,
  was_blocked BOOLEAN,
  block_count INT,
  last_activity TIMESTAMP
);
```

**Prós:** Persistente, queryable, já temos PostgreSQL  
**Contras:** Latência de query (mitigável com cache em memória)

### Recomendação: Opção B com cache em memória

Perfis carregados em RAM no startup, atualizados incrementalmente, flush para DB a cada 5 min. Melhor dos dois mundos.

## 6. Implementação Step-by-Step

### Semana 1: Server Baseline
1. Tabela `server_baselines` + migração
2. `ServerBaseline` class que calcula hourly means/stddevs
3. Worker que atualiza baselines a cada hora
4. Integração com anomaly-detector: se baseline disponível, usar em vez de Z-score global

### Semana 2: User Baseline + IP Reputation
1. Tabela `user_baselines` + migração
2. `UserBaseline` class que pontua logins SSH
3. `IPReputation` class que acumula scores
4. Integração com detector: scoring composto em vez de threshold fixo

### Semana 3: Scoring Engine + Time Patterns
1. `ScoringEngine` que combina todos os sinais
2. Time pattern detection (sazonalidade)
3. Dashboard mostra "por que alertou" com breakdown de scores
4. Telegram mostra score + explicação em alertas

## 7. Métricas de Sucesso

Antes de implementar, definir como medir se funcionou:

| Métrica | Antes (Estimativa) | Meta |
|---------|-------|------|
| Falsos positivos SSH por semana | ~5-10 | < 2 |
| Alertas de CPU/disco por dia (servidor com cron) | ~2-4 | 0 |
| Tempo para detectar brute force gradual | Nunca (< 20/janela) | < 2h (cumulativo) |
| Alertas com explicação clara | 0% | 100% |

## 8. Riscos

| Risco | Probabilidade | Mitigação |
|-------|--------------|-----------|
| Baselines envenenadas (ataque durante warm-up) | Baixa | Período de warm-up isolado, validação manual |
| Falso negativo (ataque "parece normal" para baseline) | Média | Manter regras determinísticas como camada extra |
| Overhead de memória com muitos IPs | Baixa | Expiry de IPs inativos após 30 dias |
| Complexidade de debugging | Média | Log detalhado de scores + explicações |

## 9. Valor Para o Operador

**Sem baselines (hoje):**
```
⚠️ [HIGH] SSH brute force detected: 20 failed attempts from 5.6.7.8
```

**Com baselines:**
```
⚠️ [HIGH] SSH brute force detected
  Score: 0.87 (IP reputation: 0.9, timing: 0.7, velocity: 0.95)
  Context: IP seen 3 times this week (5, 8, 20 attempts). 
  Pattern: Escalating attack from AS15169 (Google Cloud).
  Baseline: This server normally sees 2 failed SSH/hour; currently 20/hour.
  Similar: 4 incidents from this subnet in last 30 days, all auto-blocked successfully.
  Action: Auto-blocked for 7 days (longer than default 24h due to repeat behavior).
```

O operador agora entende POR QUE o alerta disparou e tem confiança na decisão.
