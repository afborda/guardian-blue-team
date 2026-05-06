# RAG — Estado Atual do AI no Guardian

**Data:** 2026-05-06  
**Versão:** Guardian v1.4.0

---

## 1. Como AI é Usado Hoje

### 1.1 AIProvider (Multi-Provider)

**Arquivo:** `src/services/ai-provider.ts`

Camada de abstração que suporta 4 provedores com fallback automático:
- Gemini (primário, free tier)
- OpenAI / GPT-5.2 (secundário)
- Claude (terciário)
- Ollama (fallback local)

**Capacidades:**
- `AIProvider.chat(prompt, systemPrompt)` — conversa genérica
- `AIProvider.analyze(data, instruction)` — análise estruturada de dados

**Limitações:**
- Stateless: cada chamada é independente, sem memória de chamadas anteriores
- Sem contexto histórico: AI não sabe o que aconteceu ontem/semana passada
- Sem feedback: não sabe se suas decisões anteriores foram boas ou ruins

### 1.2 SOC Analyst Service

**Arquivo:** `src/services/soc-analyst.service.ts`

O "cérebro" analítico do Guardian. Faz 3 coisas:

**1. Análise de Incidentes:**
- Recebe: incidente + últimos 50 eventos associados
- Produz: resumo executivo + threat assessment + ação recomendada
- Contexto disponível: APENAS os eventos deste incidente específico

**2. Relatório Semanal:**
- Recebe: estatísticas de eventos (tipo + severidade) + incidentes abertos
- Produz: resumo semanal em português
- Contexto disponível: APENAS dados da última semana, sem comparação histórica

**3. Queries em Linguagem Natural:**
- Recebe: pergunta do operador + stats dos últimos 7 dias
- Produz: resposta contextualizada
- Contexto disponível: APENAS snapshot atual, sem histórico

### 1.3 Guardian Decision Service

**Arquivo:** `src/services/guardian-decision.service.ts`

Decisor autônomo que roda quando um incidente é criado:
- Avalia severidade + tipo + contagem de eventos
- Decide: bloquear IP, executar playbook, ou apenas notificar
- Regras hardcoded (não usa AI para decisão direta)

### 1.4 Intelligence Workers

**Arquivos:** `src/intelligence/`

- `anomaly-detector.ts` — Z-score (sem AI)
- `trend-predictor.ts` — regressão linear (sem AI)
- `root-cause.ts` — usa AI para explicar quedas de score
- `recommendations.ts` — usa AI para gerar recomendações

### 1.5 Discovery (Auto-configuração)

**Arquivo:** `src/discovery/analyzer.ts`

Usa AI para analisar probes do servidor e gerar configuração:
- Input: snapshot de rede, Docker, proxy, segurança, sistema
- Output: JSON com architecture type, env vars, monitoring profile
- Funciona bem (96% confidence no hetzner-prod)

---

## 2. O Que o AI NÃO Sabe Hoje

### 2.1 Histórico de Incidentes

Quando analisa um brute force, o AI não sabe:
- "Este IP foi bloqueado 3 vezes no último mês"
- "Ataques deste subnet acontecem toda segunda-feira"
- "Da última vez, bloquear por 24h não foi suficiente — voltou em 2h"

### 2.2 Eficácia de Ações

Quando decide bloquear um IP, não sabe:
- "Block de 24h tem 70% de eficácia para este tipo de ataque"
- "Block de 7 dias tem 95% de eficácia"
- "Para este subnet específico, block permanente foi necessário"

### 2.3 Falsos Positivos

Quando gera um alerta, não sabe:
- "Alertas deste tipo em horário X são 90% falsos positivos"
- "Login deste admin de IP novo é normal (viaja frequentemente)"
- "Container restart do serviço X às 3am = cron de update"

### 2.4 Padrões Cross-Temporal

Não consegue correlacionar:
- "3 IPs diferentes, mesmo subnet, atacaram nas últimas 2 semanas = campanha"
- "Toda vez que package X é atualizado, container Y crasha dentro de 1h"
- "Spike de DNS queries sempre precede brute force neste servidor"

### 2.5 Contexto do Servidor

O AI sabe (via discovery) a arquitetura, mas não sabe:
- "Este servidor hospeda n8n, que faz webhook calls externos (normal)"
- "Evolution API abre muitas conexões WebSocket (não é DDoS)"
- "O admin costuma fazer deploys às terças entre 14-16h"

---

## 3. Dados Que Poderiam Ser RAG

### 3.1 Tabela `soc_incidents` (Já Existe)

```
id, title, severity, status, category
sourceIps[], affectedServers[], eventCount
firstSeenAt, lastSeenAt, resolvedAt
aiSummary (TEXT — preenchido mas nunca reutilizado)
```

**Gap:** Não tem: `resolution_notes`, `was_false_positive`, `effectiveness_score`, `root_cause_confirmed`

### 3.2 Tabela `blocked_ips` (Já Existe)

```
ip, serverId, reason, playbookExecutionId, incidentId
blockedAt, expiresAt, unblockedAt, active
```

**Gap:** Não rastreia: "IP voltou a atacar depois do unblock?", "Block foi efetivo?"

### 3.3 Tabela `playbook_executions` (Já Existe)

```
playbookName, incidentId, serverId
status (running/completed/failed)
stepsCompleted[], stepsFailed[]
startedAt, completedAt
```

**Gap:** Não tem: `outcome_effective`, `recurrence_detected`, `operator_override`

### 3.4 Tabela `security_events` (Já Existe)

```
serverId, timestamp, source, severity, eventType
sourceIp, destinationPort, userName, processName
metadata (JSONB), enrichment (JSONB), rawLog
```

**Útil para RAG:** Eventos enriquecidos podem ser embedded para busca semântica de "eventos parecidos".

---

## 4. Fluxo de Decisão Atual vs Com RAG

### Hoje (Sem Memória)

```
Incidente: "SSH brute force from 5.6.7.8"
    ↓
AI recebe: incidente + 50 eventos + nada mais
    ↓
AI responde: "Brute force detectado. Recomendo bloquear por 24h."
    ↓
Playbook executa: block 24h
    ↓
Ninguém avalia se funcionou
    ↓
Próximo incidente: processo repete do zero (sem memória)
```

### Com RAG (Memória)

```
Incidente: "SSH brute force from 5.6.7.8"
    ↓
RAG busca: "incidentes similares a brute force de 5.6.7.x"
    ↓
Retorna: 
  - "5.6.7.8 bloqueado em 2026-04-20 por 24h, voltou em 3h"
  - "5.6.7.12 bloqueado em 2026-04-15 por 7 dias, não voltou"
  - "Subnet 5.6.7.0/24: 4 ataques no último mês, todos brute force"
    ↓
AI recebe: incidente + 50 eventos + contexto RAG
    ↓
AI responde: "Reincidente de subnet conhecida. Bloquear /24 por 30 dias."
    ↓
Playbook executa: block subnet 30 dias
    ↓
Sistema avalia automaticamente: "IP não retornou em 7 dias = efetivo"
    ↓
Caso armazenado para futuras consultas
```

---

## 5. SOC Analyst Hoje: Limitações do Prompt

O prompt atual do SOC Analyst é:

```
"Analyze this security incident:
INCIDENT: {title, severity, category, eventCount, sourceIps}
ASSOCIATED EVENTS: [{timestamp, eventType, sourceIp}]

Provide: executive summary, threat assessment, recommended action"
```

**O que falta no prompt:**
- ❌ "Casos similares do passado e seus outcomes"
- ❌ "Eficácia de playbooks para este tipo de incidente"
- ❌ "Taxa de falso positivo para este padrão"
- ❌ "Contexto do servidor (o que é normal aqui)"
- ❌ "Histórico do IP/subnet atacante"

Com RAG, o prompt se torna:

```
"Analyze this security incident:

INCIDENT: {title, severity, category, eventCount, sourceIps}

HISTORICAL CONTEXT:
- Similar incidents: [{title, resolution, outcome, timeToContain}]
- IP history: [{previous_blocks, effectiveness, recurrence}]
- Playbook stats: [{name, successRate, avgExecutionTime}]
- Server baseline: "This server normally sees X events/hour of this type"

ASSOCIATED EVENTS: [{timestamp, eventType, sourceIp}]

Provide: analysis, confidence, recommended action (informed by historical outcomes)"
```

---

## 6. O Que Precisa Mudar no Banco

### Campos Novos em Tabelas Existentes

```sql
-- soc_incidents: adicionar feedback fields
ALTER TABLE soc_incidents ADD COLUMN was_false_positive BOOLEAN;
ALTER TABLE soc_incidents ADD COLUMN resolution_notes TEXT;
ALTER TABLE soc_incidents ADD COLUMN effectiveness_score INT;  -- 0-100
ALTER TABLE soc_incidents ADD COLUMN recurrence_days INT;      -- NULL se não recorreu

-- blocked_ips: adicionar outcome tracking
ALTER TABLE blocked_ips ADD COLUMN reattack_detected BOOLEAN DEFAULT FALSE;
ALTER TABLE blocked_ips ADD COLUMN reattack_within_hours INT;
ALTER TABLE blocked_ips ADD COLUMN effectiveness VARCHAR(20); -- 'effective', 'partial', 'ineffective'

-- playbook_executions: adicionar outcome
ALTER TABLE playbook_executions ADD COLUMN was_effective BOOLEAN;
ALTER TABLE playbook_executions ADD COLUMN operator_override BOOLEAN DEFAULT FALSE;
ALTER TABLE playbook_executions ADD COLUMN notes TEXT;
```

### Tabelas Novas (para embeddings)

Definidas no estudo de pgvector (doc 02).

---

## 7. Mecanismo de Feedback

O RAG só melhora se tiver feedback. Proposta de coleta automática + manual:

### Automático
1. Quando `blocked_ips.expiresAt` passa → checar se mesmo IP aparece em `security_events` nos próximos 7 dias → definir `reattack_detected`
2. Quando incidente fica sem novos eventos por 72h → marcar `effectiveness_score = 100`
3. Quando mesmo IP cria novo incidente < 7 dias → marcar `effectiveness_score = 20`

### Manual (via Telegram)
```
🛡️ Incidente #42 resolvido.
Foi falso positivo? [Sim] [Não]
Block efetivo? [Sim] [Não] [Parcial]
```

Operador pode responder via callback buttons no Telegram.

---

## 8. Conclusão

O AI do Guardian é **competente mas amnésico**. Faz boas análises pontuais mas começa do zero toda vez. RAG transforma o Guardian de um "analista júnior que não lembra do que fez ontem" em um "analista sênior que lembra de cada incidente e aprende com cada decisão".

**Prontidão para RAG:**
- ✅ AI multi-provider já funciona
- ✅ Dados ricos no PostgreSQL (eventos, incidentes, blocks, playbooks)
- ✅ PostgreSQL 16 suporta pgvector
- ✅ Pipeline maduro que já normaliza/enriquece eventos
- ❌ Sem feedback loop (não sabe se decisões foram boas)
- ❌ Sem embeddings (dados não vetorizados)
- ❌ SOC Analyst hardcoded para Gemini (deveria usar AIProvider)
- ❌ Sem mecanismo de coleta de outcomes
