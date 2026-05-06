# RAG — Análise de Valor, Riscos, e Decisão Go/No-Go

**Data:** 2026-05-06  
**Objetivo:** Decidir se RAG vale o investimento para o Guardian Blue Team

---

## 1. Resumo Executivo

O Guardian hoje faz análises pontuais com AI mas **não tem memória**. Cada incidente é analisado do zero, sem contexto de decisões passadas, outcomes de ações, ou padrões históricos.

RAG propõe dar memória ao Guardian: armazenar casos resolvidos como embeddings em pgvector e usar busca semântica para informar decisões futuras.

**A questão central:** O volume de incidentes justifica um sistema de memória? Ou bastaria um log estruturado com queries SQL?

---

## 2. Análise Honesta: RAG vs SQL Simples

### O Que SQL Já Pode Fazer

Sem RAG, queries SQL normais podem responder:
- "Quantas vezes este IP foi bloqueado?" → `SELECT COUNT(*) FROM blocked_ips WHERE ip = $1`
- "Qual a taxa de sucesso do playbook X?" → `SELECT AVG(status='completed') FROM playbook_executions WHERE playbook_name = $1`
- "Incidentes do mesmo tipo?" → `SELECT * FROM soc_incidents WHERE category = $1 ORDER BY created_at DESC LIMIT 5`

### O Que SQL NÃO Consegue Fazer

- "Incidentes PARECIDOS com este" (não exatos) → busca semântica
- "Ataques com PADRÃO similar" (timing, progressão) → embedding similarity
- "Contexto narrativo para o AI" (texto descritivo, não tabular) → case text + embedding

### Veredicto

Para 80% dos casos, **SQL simples resolve**. RAG resolve os outros 20% — que são justamente os casos complexos onde o AI mais precisa de contexto.

---

## 3. Cenários de Valor

### Cenário A: Servidor com Poucos Incidentes (1-2/semana)

| Com SQL | Com RAG |
|---------|---------|
| "IP bloqueado 2x antes" | Mesma info |
| Query: `WHERE ip = $1` | Overhead desnecessário |

**Veredicto:** RAG não justifica. SQL é suficiente.

### Cenário B: Servidor Ativo (5-10 incidentes/semana)

| Com SQL | Com RAG |
|---------|---------|
| "IP bloqueado antes" | "IP de subnet conhecida, padrão de campanha, block /24 é 3x mais efetivo que /32" |
| "Playbook X executou" | "Playbook X tem 90% sucesso para brute_force mas 40% para port_scan. Para este caso, usar Y." |
| Análise genérica do AI | "Similar ao incidente de 15/04 que era insider — verificar se é mesmo IP externo" |

**Veredicto:** RAG começa a agregar valor real.

### Cenário C: Multi-Servidor (10+ servidores)

| Com SQL | Com RAG |
|---------|---------|
| Incidentes isolados per-server | "Este IP atacou 3 servidores diferentes esta semana (campanha coordenada)" |
| Playbook genérico | "Para servidor tipo X, playbook Y é mais efetivo (baseado em 50 execuções)" |
| Sem cross-pollination | "Servidor A viu este ataque ontem, bloqueou com /24 — aplicar proativamente em B" |

**Veredicto:** RAG é high-value aqui.

---

## 4. Análise de Custo-Benefício

### Custo de Implementação

| Item | Esforço | Custo Recorrente |
|------|---------|-----------------|
| pgvector setup | 2h | $0 (mesma infra) |
| Schema + migrações | 4h | $0 |
| Embedding service | 8h | ~$0.01/mês (API) |
| RAG service | 16h | $0 |
| Integração SOC Analyst | 8h | $0 |
| Feedback loop automático | 8h | $0 |
| Feedback via Telegram | 4h | $0 |
| **Total** | **~50h (6-7 dias)** | **~$0.01/mês** |

### Custo de Manutenção

| Item | Frequência | Esforço |
|------|-----------|---------|
| Re-embedding (troca modelo) | ~1x/ano | 2h |
| Debugging de busca ruim | Ad-hoc | 1-2h |
| Schema evolution | Raro | 2h |
| Index rebuild | Nunca (volume baixo) | 0 |

### Valor Entregue

| Benefício | Quantificável? | Estimativa |
|-----------|---------------|-----------|
| Redução de tempo de análise | Sim | -30% (AI tem contexto pronto) |
| Decisões mais precisas | Parcial | +20-40% effectiveness |
| Redução de falsos positivos | Parcial | -10-20% (via "já vimos, era FP") |
| Detecção de campanhas | Parcial | Detecta padrões cross-temporal |
| Satisfação do operador | Subjetivo | "Alertas fazem mais sentido" |

---

## 5. Riscos

### 5.1 Riscos Técnicos

| Risco | Prob. | Impact | Mitigação |
|-------|-------|--------|-----------|
| Embedding quality ruim → busca retorna casos irrelevantes | 30% | Médio | Threshold de similaridade (não retornar se > 0.5 distance) |
| Cold start (poucos casos) → RAG inútil no início | 100% | Baixo | Bypass RAG se < 10 casos, funcionar como hoje |
| pgvector degrada com volume | <5% | Baixo | Volume do Guardian é tiny (<10k vetores em anos) |
| Modelo embedding descontinuado | 20% | Baixo | Abstração permite trocar modelo, re-embed é barato |
| Dados contaminados (caso com metadata errada) | 20% | Médio | Validação no ingestion, possibilidade de deletar caso |

### 5.2 Riscos de Produto

| Risco | Prob. | Impact | Mitigação |
|-------|-------|--------|-----------|
| AI alucina baseado em contexto RAG | 25% | Alto | System prompt: "contexto RAG é informativo, não definitivo" |
| Operador confia cegamente no RAG | 15% | Médio | Mostrar "confidence: 70% based on 3 similar cases" |
| RAG gera prompt muito longo (custo API) | 10% | Baixo | Limitar contexto a top 3 casos, < 500 tokens |
| Feedback loop não funciona (ninguém marca FP) | 50% | Médio | Feedback automático (reattack detection) como principal |

### 5.3 Over-Engineering Risk

**Este é o maior risco.** Para o cenário atual (1 servidor, ~5-10 incidentes/semana), RAG pode ser over-engineering. SQL com queries estruturadas resolveria 80% do problema com 20% do esforço.

**Mitigação:** Implementar em duas fases:
1. **Fase 0 (SQL Context):** Antes de RAG, adicionar queries SQL ao prompt do SOC Analyst (histórico de IP, playbook stats, incidentes recentes do mesmo tipo). ZERO infra nova.
2. **Fase 1 (RAG Completo):** Implementar pgvector + embeddings quando Fase 0 mostrar que contexto histórico melhora decisões.

---

## 6. Alternativa: "RAG Pobre" com SQL

Antes de investir em embeddings, pode-se simular 80% do valor com queries SQL:

```typescript
async function buildSQLContext(incident: Incident): Promise<string> {
  const ipHistory = await db.query(`
    SELECT reason, blocked_at, expires_at 
    FROM blocked_ips WHERE ip = ANY($1)
    ORDER BY blocked_at DESC LIMIT 5
  `, [incident.sourceIps]);
  
  const similarIncidents = await db.query(`
    SELECT title, severity, status, resolved_at, ai_summary
    FROM soc_incidents 
    WHERE category = $1 AND id != $2
    ORDER BY created_at DESC LIMIT 5
  `, [incident.category, incident.id]);
  
  const playbookStats = await db.query(`
    SELECT playbook_name, 
      COUNT(*) as total,
      COUNT(*) FILTER (WHERE status = 'completed') as success
    FROM playbook_executions
    WHERE incident_id IN (
      SELECT id FROM soc_incidents WHERE category = $1
    )
    GROUP BY playbook_name
  `, [incident.category]);
  
  return formatContext(ipHistory, similarIncidents, playbookStats);
}
```

**Prós:** Zero dependência nova, funciona imediatamente, sem warm-up  
**Contras:** Busca exata (não semântica), não encontra "parecidos" só "iguais"

---

## 7. Recomendação

### Fase 0: SQL Context (AGORA — 1-2 dias)

Implementar `buildSQLContext()` e injetar no prompt do SOC Analyst:
- Histórico do IP no sistema
- Incidentes recentes do mesmo tipo  
- Stats de playbook execution
- Timeline do servidor (últimos 10 incidentes)

**Valor:** Imediato, sem infra nova, valida se contexto histórico melhora AI.

### Fase 1: RAG Completo (APÓS 30 dias da Fase 0)

Se a Fase 0 mostrar que o AI faz melhores decisões com contexto:
1. Setup pgvector
2. Implementar embedding service
3. Migrar de SQL context para busca semântica
4. Adicionar feedback loop

**Gatilho para go:** Se nas primeiras 2 semanas da Fase 0, o AI usando SQL context produz análises visivelmente melhores (mais específicas, referencia histórico, sugere ações baseadas em outcomes passados).

### Fase 2: Learning Loop (APÓS 60 dias da Fase 1)

- Feedback automático (reattack detection)
- Feedback manual (Telegram buttons)
- Re-ranking baseado em outcomes
- Cross-server correlation

---

## 8. Métricas de Decisão

### Para Decidir se Fase 0 → Fase 1

| Pergunta | Como Medir | Threshold |
|----------|-----------|-----------|
| AI usa contexto SQL nas respostas? | Grep aiSummary por referências históricas | > 50% dos casos |
| Decisões mudaram com contexto? | Comparar ações recomendadas | > 20% diferentes |
| Operador achou útil? | Feedback subjetivo | "Sim, faz mais sentido" |
| Busca semântica traria algo que SQL não traz? | Analisar manualmente 10 casos | > 3/10 beneficiariam |

### Para Decidir se RAG Está Funcionando (após Fase 1)

| Métrica | Meta | Medição |
|---------|------|---------|
| Busca retorna resultados relevantes | Precision@5 >= 60% | Avaliação manual mensal |
| AI referencia histórico nas análises | > 70% dos incidentes | Grep aiSummary |
| Decisões mais assertivas | -20% recorrência | blocked_ips reattack rate |
| Operador satisfeito | Subjetivo | "Alertas mais contextualizados" |

---

## 9. Sequência Completa

```
Dia 1-2: Fase 0 (SQL Context)
  ├── buildSQLContext() no SOC Analyst
  ├── Queries: IP history, similar incidents, playbook stats
  └── Injetar no prompt do AI

Dia 3-30: Validar Fase 0
  ├── Monitorar aiSummary: AI usa o contexto?
  ├── Operador percebe diferença?
  └── Decisão: go/no-go para Fase 1

Dia 30-37: Fase 1 (RAG)
  ├── pgvector setup + migração
  ├── Embedding service (OpenAI primary, Ollama fallback)
  ├── RAG service (store + retrieve)
  ├── Integração com SOC Analyst
  └── Case ingestion automática

Dia 37-67: Validar Fase 1
  ├── Busca retorna casos relevantes?
  ├── AI produz análises melhores?
  └── Decisão: go/no-go para Fase 2

Dia 67+: Fase 2 (Learning Loop)
  ├── Feedback automático (reattack detection)
  ├── Feedback Telegram
  ├── Cross-server correlation
  └── Re-ranking por eficácia
```

---

## 10. Conclusão

RAG para o Guardian é **potencialmente valioso mas prematuramente complexo** no estágio atual (1 servidor, poucas semanas de dados). A abordagem recomendada é:

1. **Começar simples** (SQL context no prompt — 80% do valor com 10% do esforço)
2. **Validar** (AI realmente faz decisões melhores com contexto?)
3. **Evoluir** (se validado, implementar embeddings + pgvector)
4. **Crescer** (feedback loop + learning + multi-server)

**Decisão sugerida:**
- Fase 0 (SQL Context): **GO imediatamente** (baixo custo, alto ROI potencial)
- Fase 1 (RAG pgvector): **CONDITIONAL GO** (após validar Fase 0 em 30 dias)
- Fase 2 (Learning Loop): **EVALUATE** (após 60 dias de Fase 1)

O maior risco é implementar RAG completo antes de ter dados suficientes para justificá-lo. A Fase 0 valida a premissa ("contexto histórico melhora decisões") com custo mínimo.
