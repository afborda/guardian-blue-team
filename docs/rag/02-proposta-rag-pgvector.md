# RAG — Proposta: Implementação com pgvector

**Data:** 2026-05-06  
**Complexidade:** Alta  
**Dependências:** pgvector (extensão PostgreSQL), modelo de embeddings  
**Impacto Estimado:** Decisões 60-80% mais precisas após 30 dias de dados

---

## 1. Por Que pgvector (e Não Qdrant/Pinecone/Chroma)

### Comparação

| Aspecto | pgvector | Qdrant | Pinecone | Chroma |
|---------|----------|--------|----------|--------|
| Infraestrutura nova | Nenhuma (extensão PG) | +1 container (100MB) | Cloud only | +1 container |
| Latência busca (10k vectors) | ~5ms | ~2ms | ~10ms | ~8ms |
| Latência busca (100k vectors) | ~15ms | ~5ms | ~10ms | ~20ms |
| Integração com dados existentes | SQL joins nativos | REST API | REST API | Python SDK |
| Manutenção | Zero (PG já gerenciado) | Backup, updates | Gerenciado | Backup |
| Custo | $0 | $0 (self-hosted) | $70/mo | $0 |
| Transações ACID | Sim | Não | Não | Não |
| Filtros combinados | SQL WHERE + vector | Payload filter | Metadata filter | Metadata filter |

### Decisão: pgvector

**Razões:**
1. **Zero infraestrutura nova** — já temos PostgreSQL 16, basta `CREATE EXTENSION vector`
2. **SQL joins** — buscar vetores similares E fazer join com `soc_incidents`, `blocked_ips` numa query só
3. **Transações** — inserir evento + embedding na mesma transação (consistência)
4. **Backup unificado** — pg_dump captura tudo (dados + vetores)
5. **Performance suficiente** — para <100k vetores (cenário Guardian), pgvector é rápido o bastante

**Quando pgvector NÃO seria suficiente:**
- >1M vetores (precisaria HNSW com hardware dedicado)
- Busca em <1ms (realtime streaming) — Guardian não precisa disso

---

## 2. Arquitetura RAG Proposta

```
┌─────────────────────────────────────────────────────────────────┐
│                    Guardian RAG Pipeline                          │
│                                                                   │
│  ┌─── Ingestion (Write Path) ────────────────────────────────┐  │
│  │                                                            │  │
│  │  Incidente Resolvido                                       │  │
│  │       ↓                                                    │  │
│  │  [Case Builder] → Monta texto descritivo do caso           │  │
│  │       ↓                                                    │  │
│  │  [Embedding Service] → Gera vetor (768d)                   │  │
│  │       ↓                                                    │  │
│  │  INSERT INTO rag_cases (text, embedding, metadata)         │  │
│  │                                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌─── Retrieval (Read Path) ─────────────────────────────────┐  │
│  │                                                            │  │
│  │  Novo Incidente                                            │  │
│  │       ↓                                                    │  │
│  │  [Query Builder] → Monta texto de busca                    │  │
│  │       ↓                                                    │  │
│  │  [Embedding Service] → Gera vetor da query                 │  │
│  │       ↓                                                    │  │
│  │  SELECT * FROM rag_cases                                   │  │
│  │  WHERE server_id = $1                                      │  │
│  │  ORDER BY embedding <=> query_embedding                    │  │
│  │  LIMIT 5;                                                  │  │
│  │       ↓                                                    │  │
│  │  [Context Assembler] → Monta contexto para o AI            │  │
│  │       ↓                                                    │  │
│  │  [SOC Analyst] → Análise com contexto histórico            │  │
│  │                                                            │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Schema pgvector

```sql
-- Extensão
CREATE EXTENSION IF NOT EXISTS vector;

-- Casos de incidentes (principal collection RAG)
CREATE TABLE rag_cases (
  id SERIAL PRIMARY KEY,
  server_id INT REFERENCES soc_servers(id),
  incident_id INT REFERENCES soc_incidents(id),
  
  -- Texto descritivo (o que é buscado)
  case_text TEXT NOT NULL,
  
  -- Embedding do case_text
  embedding vector(768) NOT NULL,
  
  -- Metadata estruturada (para filtros)
  category VARCHAR(50) NOT NULL,         -- brute_force, port_scan, crypto_mining, etc.
  severity VARCHAR(20) NOT NULL,         -- critical, high, medium, low
  source_ips TEXT[],                     -- IPs envolvidos
  source_subnet VARCHAR(20),            -- /24 do IP principal
  
  -- Outcome (o que o RAG realmente quer saber)
  resolution TEXT,                       -- "Blocked /24 for 30 days"
  outcome VARCHAR(20),                   -- effective, partial, ineffective, false_positive
  time_to_contain_minutes INT,
  recurrence_within_days INT,            -- NULL se não recorreu
  
  -- Temporal
  occurred_at TIMESTAMP NOT NULL,
  resolved_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  
  -- Versioning (embeddings podem ser re-gerados com modelo melhor)
  embedding_model VARCHAR(100) NOT NULL,
  embedding_version INT DEFAULT 1
);

-- Index vetorial (IVFFlat para <100k registros, HNSW para mais)
CREATE INDEX rag_cases_embedding_idx 
ON rag_cases 
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 50);

-- Indexes para filtros combinados com busca vetorial
CREATE INDEX rag_cases_category_idx ON rag_cases(category);
CREATE INDEX rag_cases_server_idx ON rag_cases(server_id);
CREATE INDEX rag_cases_occurred_idx ON rag_cases(occurred_at);

-- Playbook outcomes (como RAG de ações)
CREATE TABLE rag_playbook_outcomes (
  id SERIAL PRIMARY KEY,
  playbook_name VARCHAR(100) NOT NULL,
  incident_category VARCHAR(50) NOT NULL,
  
  -- Contexto
  case_text TEXT NOT NULL,
  embedding vector(768) NOT NULL,
  
  -- Outcome
  was_effective BOOLEAN NOT NULL,
  execution_time_seconds INT,
  side_effects TEXT,                    -- "Blocked legitimate traffic for 2h"
  
  -- Stats cumulativas (atualizadas periodicamente)
  total_executions INT DEFAULT 1,
  success_rate FLOAT DEFAULT 1.0,
  
  occurred_at TIMESTAMP NOT NULL,
  embedding_model VARCHAR(100) NOT NULL
);

CREATE INDEX rag_playbook_embedding_idx 
ON rag_playbook_outcomes 
USING ivfflat (embedding vector_cosine_ops)
WITH (lists = 20);

-- Server behavior profiles (contexto do servidor para o AI)
CREATE TABLE rag_server_profiles (
  id SERIAL PRIMARY KEY,
  server_id INT REFERENCES soc_servers(id) UNIQUE,
  
  -- Descrição em linguagem natural (para RAG context)
  profile_text TEXT NOT NULL,
  embedding vector(768) NOT NULL,
  
  -- Metadata
  normal_services TEXT[],              -- ["n8n", "traefik", "postgres"]
  typical_incidents TEXT[],            -- ["ssh_brute_force 2-3x/week"]
  security_posture TEXT,               -- "UFW + fail2ban + key-only SSH"
  special_notes TEXT,                  -- "Evolution API opens many WebSocket connections"
  
  updated_at TIMESTAMP NOT NULL,
  embedding_model VARCHAR(100) NOT NULL
);
```

---

## 4. Serviço de RAG

### 4.1 Arquitetura de Classes

```
src/services/
├── rag.service.ts              # Orquestrador principal
├── embedding.service.ts        # Gera embeddings (abstração)
└── case-builder.service.ts     # Constrói textos descritivos

src/database/
└── rag-schema.ts              # Drizzle schema para tabelas RAG
```

### 4.2 RAG Service

```typescript
class RAGService {
  // Retrieval: buscar casos similares para um incidente
  async retrieveSimilarCases(incident: Incident, topK: number = 5): Promise<RAGCase[]>
  
  // Retrieval: buscar outcomes de playbook para um tipo de incidente
  async retrievePlaybookOutcomes(category: string, topK: number = 3): Promise<PlaybookOutcome[]>
  
  // Retrieval: contexto do servidor
  async getServerProfile(serverId: number): Promise<ServerProfile | null>
  
  // Ingestion: armazenar caso resolvido
  async storeCase(incident: Incident, resolution: string, outcome: string): Promise<void>
  
  // Ingestion: armazenar outcome de playbook
  async storePlaybookOutcome(execution: PlaybookExecution, effective: boolean): Promise<void>
  
  // Ingestion: atualizar perfil do servidor
  async updateServerProfile(serverId: number): Promise<void>
  
  // Context assembly: montar prompt RAG para o SOC Analyst
  async buildAugmentedContext(incident: Incident): Promise<string>
}
```

### 4.3 Case Builder

Transforma incidente + eventos em texto descritivo para embedding:

```typescript
function buildCaseText(incident: Incident, events: Event[]): string {
  return `
    ${incident.category} incident: ${incident.title}
    Severity: ${incident.severity}
    Source: ${incident.sourceIps.join(', ')} (${getSubnet(incident.sourceIps[0])})
    Duration: ${minutesBetween(incident.firstSeenAt, incident.lastSeenAt)} minutes
    Events: ${incident.eventCount} (${getTopEventTypes(events).join(', ')})
    Targets: ${getTargetedUsers(events).join(', ')}
    Patterns: ${describePatterns(events)}
  `.trim();
}
```

**Por que texto e não JSON?** Modelos de embedding performam melhor com linguagem natural. "SSH brute force targeting root from Russian subnet" tem melhor similaridade semântica que `{"category":"brute_force","user":"root","country":"RU"}`.

### 4.4 Integração com SOC Analyst

```typescript
// ANTES (sem RAG)
async analyzeIncident(incident: Incident): Promise<string> {
  const events = await getRecentEvents(incident.id, 50);
  const prompt = `Analyze: ${JSON.stringify({incident, events})}`;
  return AIProvider.chat(prompt, SOC_SYSTEM_PROMPT);
}

// DEPOIS (com RAG)
async analyzeIncident(incident: Incident): Promise<string> {
  const events = await getRecentEvents(incident.id, 50);
  
  // RAG retrieval
  const context = await ragService.buildAugmentedContext(incident);
  
  const prompt = `Analyze this incident WITH historical context:

${context}

CURRENT INCIDENT:
${JSON.stringify({incident, events})}

Based on historical patterns and outcomes, provide:
1. Analysis and threat assessment
2. Confidence level (how similar is this to known patterns?)
3. Recommended action (informed by what worked/didn't work before)
4. Expected effectiveness (based on similar past outcomes)`;

  return AIProvider.chat(prompt, SOC_SYSTEM_PROMPT);
}
```

---

## 5. Fluxo de Dados Completo

### 5.1 Write Path (Quando um incidente é resolvido)

```
Incidente resolvido/fechado
    ↓
[CaseBuilder] gera texto descritivo
    ↓
[EmbeddingService] gera vetor 768d
    ↓
INSERT INTO rag_cases (case_text, embedding, category, outcome, ...)
    ↓
Caso disponível para futuras buscas
```

### 5.2 Read Path (Quando um novo incidente aparece)

```
Novo incidente criado
    ↓
[CaseBuilder] gera texto de busca do novo incidente
    ↓
[EmbeddingService] gera vetor da query
    ↓
SELECT do pgvector: top 5 casos similares
    ↓
[ContextAssembler] formata contexto RAG
    ↓
SOC Analyst recebe: incidente + eventos + contexto histórico
    ↓
Decisão informada por experiência passada
```

### 5.3 Feedback Loop (Automático)

```
Cada 24h, worker verifica:
    ↓
Para cada blocked_ip com expiresAt no passado:
  - IP reapareceu em security_events?
  - Sim → marcar rag_case.outcome = 'partial' ou 'ineffective'
  - Não → marcar rag_case.outcome = 'effective'
    ↓
Para cada incidente resolvido > 72h sem novos eventos:
  - Marcar rag_case.outcome = 'effective'
  - rag_case.recurrence_within_days = NULL
```

---

## 6. Evolução do RAG ao Longo do Tempo

### Semana 1-4: Cold Start
- 0-10 casos armazenados
- RAG não é chamado (poucos dados)
- Guardian funciona como hoje (regras + AI sem contexto)
- Cada incidente resolvido = +1 caso no banco

### Mês 1-2: Early Learning
- 10-50 casos
- RAG começa a encontrar similares para ataques comuns (brute force)
- AI recebe contexto: "último brute force desse subnet foi bloqueado por 24h, voltou"
- Decisões começam a ser mais agressivas para reincidentes

### Mês 2-3: Pattern Recognition
- 50-200 casos
- RAG identifica campanhas: "5 IPs do mesmo /24 nas últimas 3 semanas"
- Playbook outcomes mostram: "block 7 dias tem 95% eficácia vs 70% de 24h"
- AI sugere: "block subnet /24 por 30 dias (baseado em padrão histórico)"

### Mês 3-6: Mature Intelligence
- 200-500 casos
- Falsos positivos drasticamente reduzidos ("já vimos 15x, sempre falso positivo")
- Decisões informadas por outcomes reais (não suposições)
- Novos tipos de ataque correlacionados com padrões conhecidos
- Server profiles ricos ("Este servidor tem picos normais de CPU às terças por deploy")

### 6+ Meses: Self-Improving
- 500+ casos
- Base de conhecimento rica o bastante para responder "o que está acontecendo?" com contexto real
- Tendências temporais visíveis (ataques sazonais, campanhas recorrentes)
- Decisões quase autônomas para padrões conhecidos (high confidence)

---

## 7. Queries Reais com pgvector

### 7.1 Buscar Incidentes Similares

```sql
-- Encontrar 5 casos mais similares ao vetor da query
SELECT 
  rc.case_text,
  rc.resolution,
  rc.outcome,
  rc.time_to_contain_minutes,
  rc.recurrence_within_days,
  rc.occurred_at,
  1 - (rc.embedding <=> $1::vector) as similarity
FROM rag_cases rc
WHERE rc.server_id = $2
  AND rc.occurred_at > NOW() - INTERVAL '90 days'
ORDER BY rc.embedding <=> $1::vector
LIMIT 5;
```

### 7.2 Buscar com Filtro de Categoria

```sql
-- Só casos de brute_force, para comparar outcomes
SELECT 
  rc.resolution,
  rc.outcome,
  rc.recurrence_within_days,
  COUNT(*) OVER () as total_similar
FROM rag_cases rc
WHERE rc.category = 'brute_force'
  AND rc.embedding <=> $1::vector < 0.3  -- threshold de similaridade
ORDER BY rc.embedding <=> $1::vector
LIMIT 3;
```

### 7.3 Stats de Playbook

```sql
-- Eficácia do playbook block_ip para brute_force
SELECT 
  playbook_name,
  COUNT(*) as executions,
  AVG(CASE WHEN was_effective THEN 1.0 ELSE 0.0 END) as success_rate,
  AVG(execution_time_seconds) as avg_time
FROM rag_playbook_outcomes
WHERE incident_category = 'brute_force'
GROUP BY playbook_name;
```

### 7.4 Histórico de IP/Subnet

```sql
-- Todos os casos envolvendo este subnet
SELECT 
  case_text, outcome, occurred_at
FROM rag_cases
WHERE source_subnet = '5.6.7.0/24'
ORDER BY occurred_at DESC
LIMIT 10;
```

---

## 8. Considerações de Performance

### Volume Esperado

| Período | Casos RAG | Vetores | Tamanho pgvector |
|---------|-----------|---------|------------------|
| 1 mês | ~20-50 | ~100 (com playbooks) | ~300KB |
| 6 meses | ~150-300 | ~500 | ~2MB |
| 1 ano | ~300-600 | ~1000 | ~4MB |
| 3 anos | ~1000-2000 | ~3000 | ~12MB |

**Conclusão:** pgvector é absurdamente over-provisioned para este volume. Performance será excelente sempre.

### Latência

| Operação | Tempo Esperado | Aceitável? |
|----------|---------------|------------|
| Gerar embedding (local) | 50-200ms | Sim (async) |
| Gerar embedding (API) | 100-500ms | Sim (async) |
| Busca pgvector (top 5) | 2-10ms | Sim |
| Montar contexto RAG | 5-20ms | Sim |
| Total read path | 150-700ms | Sim (dentro do budget de 5s do SOC) |

---

## 9. Docker Compose Atualizado

```yaml
guardian-db:
  image: pgvector/pgvector:pg16  # CHANGE: era postgres:16-alpine
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
```

**Única mudança:** `postgres:16-alpine` → `pgvector/pgvector:pg16`

A extensão precisa ser ativada uma vez:
```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

Pode ser na migração Drizzle ou no script de init do container.

---

## 10. Integração com ML (Sinergia)

O RAG e o ML propostos no estudo `/docs/ml/` se complementam:

| ML Produz | RAG Consome |
|-----------|-------------|
| Anomaly score (IF) | Busca casos com score similar |
| Baseline deviation | Contexto: "desvio normal para este servidor?" |
| IP reputation score | Histórico: "IP com score X — o que aconteceu da última vez?" |

| RAG Produz | ML Consome |
|-----------|-------------|
| Outcome de ações | Labels para retreino (effective = true positive) |
| Falsos positivos marcados | Ajuste de thresholds (baseline correction) |
| Padrões de campanha | Features para IF (subnet_attack_count) |

**pgvector serve ambos:** Feature vectors do ML e case embeddings do RAG vivem no mesmo banco.
