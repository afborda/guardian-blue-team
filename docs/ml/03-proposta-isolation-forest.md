# ML — Proposta: Isolation Forest com pgvector (Fase 2)

**Data:** 2026-05-06  
**Complexidade:** Alta  
**Dependências:** pgvector (extensão PostgreSQL), opcionalmente Python sidecar  
**Impacto Estimado:** Detecção de ataques coordenados invisíveis a regras isoladas

---

## 1. O Que É

Isolation Forest é um algoritmo de detecção de anomalias **não-supervisionado** (não precisa de labels). Funciona isolando pontos de dados: anomalias são mais fáceis de isolar porque estão longe do resto dos dados. Quanto menos "cortes" aleatórios são necessários para isolar um ponto, mais anômalo ele é.

### Diferença Fundamental das Regras Atuais

**Regras (hoje):** Cada métrica avaliada isoladamente
- SSH falhas > 20 → alerta
- CPU > 2.5σ → alerta  
- Port scan > 10 portas → alerta

**Isolation Forest:** Avalia COMBINAÇÕES de métricas
- SSH falhas = 8 + port scan = 4 + DNS queries estranhas = 3 → NENHUMA regra isolada dispara, mas a COMBINAÇÃO é altamente anômala (score 0.92)

**Isto é o que detecta ataques coordenados** — quando um atacante distribui atividade maliciosa entre múltiplos vetores para ficar abaixo de cada threshold individual.

## 2. Por Que Implementar

### Cenário Real: Ataque Low-and-Slow

Um atacante sofisticado faz:
1. 5 tentativas SSH (abaixo de 20, invisível ao detector)
2. 3 port scans (abaixo de 10, invisível)
3. 2 DNS queries para domínios .tk (abaixo de threshold DGA)
4. 1 download via curl no servidor vizinho (lateral)

**Sem Isolation Forest:** Nenhum alerta. Cada atividade está abaixo do threshold individual.

**Com Isolation Forest:** Score de anomalia 0.89 — esta COMBINAÇÃO nunca foi vista antes num período de 15 min. Alerta com explicação: "Atividade multi-vetor coordenada detectada de IP X".

### Cenário 2: Insider Threat

Admin legítimo faz:
1. Login em horário normal ✓
2. Mas de IP diferente 
3. Acessa 15 arquivos em /etc (mais que habitual)
4. Instala package não-padrão
5. Cria cron job com wget

**Sem IF:** Cada ação individualmente é permitida para um admin.

**Com IF:** A combinação de comportamentos é rara. Score 0.78. Alerta informativo (não bloqueia admin, mas avisa).

## 3. Abordagem Técnica

### 3.1 Por Que pgvector (e não Python Sidecar)

**Opção A: Python sidecar (scikit-learn)**
```yaml
guardian-ml:
  build: ./ml
  image: python:3.11-slim
  # scikit-learn IsolationForest
```

Prós: Biblioteca madura, treino eficiente
Contras: +1 container, +300MB RAM, comunicação HTTP entre serviços, latência de rede, outro runtime para manter

**Opção B: pgvector no PostgreSQL existente**

pgvector permite armazenar vetores (features) e calcular distâncias diretamente no banco:

```sql
CREATE EXTENSION vector;

CREATE TABLE feature_vectors (
  id SERIAL PRIMARY KEY,
  server_id INT,
  window_start TIMESTAMP,
  features vector(10),  -- 10 dimensões
  anomaly_score FLOAT,
  labels JSONB
);

-- Buscar vetores mais similares (vizinhos próximos)
SELECT * FROM feature_vectors 
ORDER BY features <-> '[0.5, 0.3, 0.8, ...]'::vector
LIMIT 5;
```

Prós: Zero infraestrutura nova, queries SQL, persistência automática
Contras: Isolation Forest em si não roda no PostgreSQL — precisa de lógica no Node

**Opção C: Hybrid (Recomendada)**

1. **Feature vectors** armazenados em pgvector (para busca de similaridade e histórico)
2. **Isolation Forest** implementado em TypeScript puro (treinamento + inferência)
3. **Sem containers adicionais** — tudo dentro do Guardian existente

### 3.2 Isolation Forest em TypeScript

O algoritmo é surpreendentemente simples de implementar:

```typescript
class IsolationTree {
  // Construção: seleciona feature aleatória, split aleatório
  // Recursão até isolar ponto ou atingir max depth
  // Score: path length médio para isolar o ponto
}

class IsolationForest {
  private trees: IsolationTree[];
  private numTrees = 100;
  private sampleSize = 256;
  
  train(data: number[][]): void {
    // Para cada árvore: subsample aleatório → construir
  }
  
  score(point: number[]): number {
    // Média de path lengths normalizada (0 = normal, 1 = anomalia)
  }
}
```

**Performance:** 100 árvores × 256 samples = treino em <1s. Inferência de 1 ponto em <1ms. Sem deps externas.

### 3.3 Feature Engineering

**Vector de features por IP (janela de 15 min):**

```typescript
const featureVector = [
  normalizedSSHFails,        // 0-1: ssh_failed / max_historical_ssh_failed
  normalizedPortScans,       // 0-1: firewall_blocks / max_historical
  normalizedDNSSuspicious,   // 0-1: dns_suspicious_count / max
  ipAbuseScore / 100,        // 0-1: AbuseIPDB score normalizado
  hourOfDay / 23,            // 0-1: hora normalizada
  uniqueUsersTargeted / 10,  // 0-1: usernames distintos (cap 10)
  eventVelocity / maxVelocity, // 0-1: eventos/min normalizado
  isKnownIP ? 0 : 1,        // 0 ou 1
  geoRiskScore / 100,        // 0-1: risco geográfico
  connectionDiversity / 20,  // 0-1: destinos únicos (cap 20)
];
```

**Vector de features por Servidor (janela de 1 hora):**

```typescript
const serverVector = [
  cpuLoadRatio,              // load1/cores (0-5 normalizado para 0-1)
  memPercent / 100,          // 0-1
  diskIoRate / maxHistorical, // 0-1
  netIoRate / maxHistorical,  // 0-1
  eventCountRatio,           // eventos_agora / média_histórica
  containerRestarts / 10,    // 0-1 (cap 10)
  failedUnitsCount / 5,     // 0-1 (cap 5)
  newProcesses / 20,        // 0-1 (cap 20)
  dnsEntropyAvg / 5,        // 0-1 (normalizado pela max entropia)
  sshSessionCount / 10,     // 0-1 (cap 10)
];
```

### 3.4 Treinamento e Retraining

```
Dia 1-7: Período de coleta (warm-up)
  → Acumula feature vectors (1 por IP por janela de 15min)
  → ~2000-5000 vetores na primeira semana

Dia 7: Primeiro treinamento
  → IsolationForest.train(vetores) 
  → Modelo pronto para inferência

A cada 7 dias: Re-treino automático
  → Usa últimos 7 dias como dados de treino
  → Contamination rate = 0.05 (assume 5% são anomalias)
  → Modelo novo substitui antigo
```

### 3.5 pgvector Para Busca de Similaridade

Além do Isolation Forest, pgvector habilita:

```sql
-- "Já vimos um ataque parecido com este?"
SELECT window_start, labels, anomaly_score
FROM feature_vectors
WHERE server_id = 1
ORDER BY features <-> $1::vector  -- cosine distance
LIMIT 5;

-- Resultado: 3 vetores similares com label "brute_force_botnet" de 2 semanas atrás
```

**Isto conecta ML com RAG:** Um incidente detectado pelo IF pode ser enriquecido com "incidentes similares do passado" via busca vetorial.

## 4. Integração com Pipeline Existente

```
Evento chega
    ↓
[Normalizer] (existente)
    ↓
[Detector Rules] (existente, mantido como camada 1)
    ↓
[Feature Extractor] (NOVO — extrai features do evento + contexto)
    ↓
[Isolation Forest] (NOVO — retorna anomaly_score)
    ↓
[Scoring Engine] (NOVO — combina rule score + IF score + baseline score)
    ↓
[Decision]
  Se overall_score > 0.85 → playbook automático
  Se 0.65 < score < 0.85 → alerta com contexto
  Se score < 0.65 → log apenas
```

**Importante:** As regras existentes NÃO são removidas. O IF é uma camada adicional que pega o que as regras perdem. A combinação reduz tanto falsos negativos (IF pega ataques coordenados) quanto falsos positivos (baseline reduz ruído).

## 5. pgvector: Setup e Considerações

### 5.1 Instalação

No `docker-compose.yml`, trocar imagem do PostgreSQL:

```yaml
guardian-db:
  image: pgvector/pgvector:pg16  # em vez de postgres:16-alpine
```

Ou instalar a extensão manualmente:
```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

**Nota:** A imagem `pgvector/pgvector:pg16` é baseada em `postgres:16` (Debian, não Alpine). Diferença de ~50MB no tamanho do container.

### 5.2 Schema

```sql
-- Vetores de features para treinamento e busca de similaridade
CREATE TABLE ml_feature_vectors (
  id SERIAL PRIMARY KEY,
  server_id INT NOT NULL,
  entity_type VARCHAR(10) NOT NULL,  -- 'ip' ou 'server'
  entity_id VARCHAR(100) NOT NULL,   -- IP address ou server name
  window_start TIMESTAMP NOT NULL,
  window_end TIMESTAMP NOT NULL,
  features vector(10) NOT NULL,
  anomaly_score FLOAT,
  was_threat BOOLEAN,                -- label retroativo (quando confirmado)
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Index para busca de vizinhos (IVFFlat é mais rápido para <100k vetores)
CREATE INDEX ml_features_ivfflat_idx 
ON ml_feature_vectors 
USING ivfflat (features vector_cosine_ops) 
WITH (lists = 100);

-- Index temporal para treinamento
CREATE INDEX ml_features_window_idx 
ON ml_feature_vectors (server_id, window_start);

-- Modelos treinados (serializado)
CREATE TABLE ml_models (
  id SERIAL PRIMARY KEY,
  model_type VARCHAR(50) NOT NULL,   -- 'isolation_forest_ip', 'isolation_forest_server'
  server_id INT,                     -- NULL = global model
  trained_at TIMESTAMP NOT NULL,
  training_samples INT NOT NULL,
  model_data JSONB NOT NULL,         -- árvores serializadas
  metrics JSONB,                     -- precision, recall, contamination
  active BOOLEAN DEFAULT TRUE
);
```

### 5.3 Performance

Para o cenário do Guardian (1 servidor, ~5000 vetores/semana):
- **Inserção:** <1ms por vetor
- **Busca KNN (5 vizinhos):** <5ms com IVFFlat index
- **Treino IF (5000 pontos, 100 árvores):** <500ms em TypeScript
- **Inferência IF (1 ponto):** <0.5ms

pgvector brilha quando o volume cresce (10+ servidores, 100k+ vetores).

## 6. Isolation Forest: Detalhes do Algoritmo

### 6.1 Construção de Árvore

```
function buildTree(data, depth, maxDepth):
  if len(data) <= 1 or depth >= maxDepth:
    return leaf(size=len(data))
  
  feature = randomChoice(0..numFeatures)
  min = min(data[feature])
  max = max(data[feature])
  splitValue = randomUniform(min, max)
  
  left = data.filter(x => x[feature] < splitValue)
  right = data.filter(x => x[feature] >= splitValue)
  
  return node(feature, splitValue, 
    left=buildTree(left, depth+1, maxDepth),
    right=buildTree(right, depth+1, maxDepth))
```

### 6.2 Scoring

```
function pathLength(point, tree, depth=0):
  if tree.isLeaf:
    return depth + averagePathLength(tree.size)
  
  if point[tree.feature] < tree.splitValue:
    return pathLength(point, tree.left, depth+1)
  else:
    return pathLength(point, tree.right, depth+1)

function anomalyScore(point, forest):
  avgPath = mean(pathLength(point, tree) for tree in forest.trees)
  normalized = 2 ** (-avgPath / averagePathLength(forest.sampleSize))
  return normalized  // 0 = normal, 1 = anomalia
```

### 6.3 Por Que Funciona Para Segurança

1. **Sem labels necessários** — não precisamos saber O QUE é um ataque, só que é DIFERENTE
2. **Escala linearmente** — O(n * numTrees * log(sampleSize))
3. **Explícável** — podemos dizer QUAIS features contribuíram mais para o score
4. **Robusto a ruído** — contamination parameter controla tolerância

## 7. Evolução: De IF para Ensemble

A longo prazo, o IF pode ser parte de um ensemble:

```
Score Final = w1*IsolationForest + w2*LOF + w3*ZScore + w4*Baseline
```

Onde:
- **Isolation Forest** — bom para anomalias globais
- **LOF (Local Outlier Factor)** — bom para anomalias em clusters densos
- **Z-Score** — bom para anomalias univariadas
- **Baseline** — bom para desvios comportamentais

Mas isso é futuro. IF sozinho já entrega 80% do valor.

## 8. Implementação Estimada

| Semana | Entrega |
|--------|---------|
| 1 | pgvector setup + feature extractor + tabelas |
| 2 | Isolation Forest TypeScript + treinamento automático |
| 3 | Integração com pipeline + scoring engine |
| 4 | Dashboard de anomalias + explicabilidade |

## 9. Riscos

| Risco | Severidade | Mitigação |
|-------|-----------|-----------|
| Modelo treinado com dados contaminados | Alta | Validação cruzada, contamination=0.05 |
| Drift do modelo (servidor muda de perfil) | Média | Re-treino semanal automático |
| Overhead de memória (modelos grandes) | Baixa | 100 árvores × 256 samples = ~5MB RAM |
| pgvector não disponível em hosting compartilhado | Média | Fallback para IF sem busca vetorial |
| Complexidade de debugging | Alta | Explicabilidade obrigatória em cada score |

## 10. Decisão: Implementar?

### A Favor
- Detecta ataques coordenados que regras isoladas perdem
- Zero infraestrutura adicional (pgvector no PG existente)
- Implementação TypeScript pura (~500 linhas de código)
- Melhora com o tempo (re-treino semanal)
- Conecta com RAG via busca vetorial

### Contra
- Período de warm-up (7 dias sem detecção ML)
- Complexidade de troubleshooting quando score é "errado"
- Sem labels, difícil medir precisão objetivamente
- Requer feature engineering cuidadoso (features ruins = modelo ruim)

### Pré-requisitos
- **Fase 1 (Statistical Baselines)** deve estar implementada primeiro — fornece features e contexto histórico que o IF usa
- Mínimo de 7 dias de dados coletados para primeiro treino
