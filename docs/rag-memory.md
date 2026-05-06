# Memoria RAG (Retrieval-Augmented Generation)

Guardian **aprende com incidentes passados** e usa esse conhecimento para tomar decisoes melhores no futuro.

---

## Por que RAG?

| Sem RAG | Com RAG |
|---------|---------|
| "Brute force detectado de 5.6.7.8" | "Brute force de 5.6.7.8 — IP ja bloqueado 3x no ultimo mes, sempre volta apos 24h. Recomendo block permanente." |
| Playbook generico executa | "Playbook X teve 95% sucesso para este tipo. Playbook Y falhou 2x semana passada." |
| AI analisa sem contexto | "Similar ao incidente de 15/04 onde containerX minerava. Root cause: API key exposta." |
| Cada incidente comeca do zero | Decisoes baseadas em 50+ casos historicos |

---

## Como Funciona

### 1. Armazenamento

Quando um incidente e resolvido (manual ou automaticamente), Guardian armazena:

| Campo | Descricao |
|-------|-----------|
| `category` | Tipo do incidente (brute_force, mining, file_tamper, etc.) |
| `title` | Titulo descritivo |
| `sourceIps` | IPs envolvidos |
| `resolution` | Como foi resolvido |
| `outcome` | Resultado (resolved, false_positive, mitigated) |
| `rootCause` | Causa raiz (se identificada) |
| `timeToContain` | Minutos ate contencao |
| `tags` | Classificacoes (distributed, high_volume, etc.) |

### 2. Busca por Similaridade

Quando um novo incidente acontece, Guardian busca casos similares:

```
Novo incidente: "SSH brute force de 5.6.7.8"
  ↓
Busca: category=brute_force + overlap de IPs
  ↓
Encontra: 3 casos similares com resolucoes
  ↓
AI recebe contexto historico no prompt
  ↓
Recomendacao: "Block permanente — IP reincidente"
```

**Criterios de similaridade**:
- Mesma categoria (obrigatorio)
- IPs em comum (bonus +2 por IP overlapping)
- Ordenado por relevancia, limitado a top 3-5

### 3. Contexto para AI

O historico e injetado no prompt do AI provider:

```
HISTORICAL CONTEXT (3 similar past incidents):
- "SSH Brute Force from 5.6.7.8": Block 7 dias (resultado: resolved, tempo: 2min)
- "SSH Brute Force from 5.6.7.0/24": Block range /24 (resultado: resolved, tempo: 5min)
- "Distributed Brute Force": Falso positivo — era scan de seguranca interno [FALSO POSITIVO]
```

Isso permite que a AI:
- Reconheca padroes recorrentes
- Sugira acoes que funcionaram antes
- Identifique potenciais falsos positivos
- Recomende escalacao quando o historico mostra reincidencia

---

## Auto-Learn

Guardian aprende automaticamente em dois momentos:

### Via Playbooks (automatico)
Quando um playbook executa com sucesso:
```
Playbook "block_ip_ufw" completou → armazena:
  resolution: "Auto-resolved by playbook block_ip_ufw: blocked 5.6.7.8 for 24h"
  outcome: "resolved"
```

### Via Telegram (manual)
Operador resolve incidente e ensina:
```
/learn 42 "IP era scanner de seguranca interno, falso positivo. Adicionar em TRUSTED_IPS."
```

Armazena:
```
  resolution: "IP era scanner de seguranca interno..."
  outcome: "false_positive"
```

---

## Como Melhora com o Tempo

| Periodo | Comportamento |
|---------|-------------|
| Semana 1 | Guardian detecta brute force → bloqueia IP → armazena caso |
| Semana 2 | Mesmo tipo de ataque → RAG encontra caso similar → sugere ban mais longo |
| Mes 1 | Base com 20+ casos → AI percebe: "IPs de subnet 5.6.7.x atacam toda segunda" |
| Mes 2 | Base com 50+ casos → decisoes precisas, falsos positivos identificados rapidamente |
| Mes 3+ | Guardian virtualmente "conhece" seu ambiente — sugere acoes sem hesitacao |

---

## Estatisticas

Consulte via Telegram:
```
/memory

📊 Incident Memory Stats:
  Total cases: 47
  By category:
    brute_force: 23
    port_scan: 12
    mining: 5
    file_tamper: 4
    container_escape: 3
  False positive rate: 8%
```

---

## Consumo de Recursos

| Metrica | Valor |
|---------|-------|
| RAM adicional | < 5MB (queries sob demanda) |
| Disco (PostgreSQL) | ~1KB por caso armazenado |
| 1000 casos | ~1MB total em disco |
| CPU | Negligivel (busca indexada por categoria) |
| Dependencias externas | Nenhuma (busca por keyword, sem embeddings) |

---

## Limitacoes Atuais

- Busca por **categoria + IP overlap** (nao semantica)
- Sem embeddings vetoriais (planejado: nomic-embed-text via Ollama)
- Sem clustering automatico de incidentes
- Maximo de 5 casos retornados por busca

**Roadmap**: Adicionar embeddings via Ollama (nomic-embed-text) para busca semantica — encontrar casos similares mesmo quando categorias diferem mas o padrao e o mesmo.
