# ML — Análise de Valor, Riscos, e Decisão Go/No-Go

**Data:** 2026-05-06  
**Objetivo:** Decidir se ML vale o investimento para o Guardian Blue Team

---

## 1. Resumo Executivo

O Guardian hoje usa **regras estáticas** para detecção. Funciona, mas tem problemas reais:
- Falsos positivos em servidores com padrões regulares (backups, CI)
- Falsos negativos em ataques "low-and-slow" (abaixo dos thresholds)
- Zero aprendizado — os mesmos erros se repetem indefinidamente

ML propõe resolver isto em **duas fases incrementais**, cada uma com valor mensurável.

---

## 2. Análise de Valor por Fase

### Fase 1: Statistical Baselines

| Aspecto | Detalhe |
|---------|---------|
| **Custo de implementação** | ~2-3 semanas dev, 0 infra nova |
| **Dependências externas** | Nenhuma (TypeScript puro) |
| **Valor imediato** | -40-60% falsos positivos, alertas contextualizados |
| **Risco técnico** | Baixo (math simples: médias, desvios, EMA) |
| **Risco de produto** | Baixo (melhora UX sem mudar arquitetura) |
| **Reversibilidade** | Total (desabilitar baselines volta ao comportamento anterior) |

**ROI:** Alto. Custo mínimo, valor imediato, sem risco.

### Fase 2: Isolation Forest + pgvector

| Aspecto | Detalhe |
|---------|---------|
| **Custo de implementação** | ~3-4 semanas dev, trocar imagem PG |
| **Dependências externas** | pgvector (extensão PostgreSQL) |
| **Valor imediato** | Detecta ataques coordenados invisíveis a regras |
| **Risco técnico** | Médio (feature engineering, tuning de contamination) |
| **Risco de produto** | Médio (modelo pode gerar alertas confusos sem boa explicabilidade) |
| **Reversibilidade** | Alta (IF é camada adicional, não substitui regras) |

**ROI:** Médio-Alto. Valor real mas dependente de bom feature engineering.

---

## 3. Comparação: Com ML vs Sem ML

### Cenário: Servidor hetzner-prod rodando 6 meses

**Sem ML (status quo):**
- ~5-10 falsos positivos/semana (backup = anomalia, login de IP novo = alerta)
- Operador aprende a ignorar alertas → fadiga de alertas
- Ataques low-and-slow passam despercebidos
- Cada novo servidor precisa do mesmo tuning manual de thresholds
- Decisões do AI (GPT-5.2) sem contexto histórico

**Com ML (após implementação):**
- ~1-2 falsos positivos/semana (baselines eliminam ruído previsível)
- Alertas têm contexto: "CPU alta mas é horário de backup, score 0.1"
- Ataques coordenados detectados: "IP com atividade em 3 vetores simultaneamente"
- Novos servidores auto-calibram em 7 dias
- Busca vetorial encontra "incidentes parecidos" do passado

---

## 4. Análise de Riscos

### 4.1 Riscos Técnicos

| Risco | Prob. | Impact | Mitigação |
|-------|-------|--------|-----------|
| Baseline envenenado (ataque durante warm-up) | 10% | Alto | Validação manual do primeiro baseline, alertas durante warm-up |
| Modelo degrada com o tempo | 30% | Médio | Re-treino semanal automático + monitoramento de distribuição |
| Feature engineering inadequado | 40% | Alto | Começar com features simples, expandir incrementalmente |
| pgvector incompatível com hosting | 20% | Baixo | Fallback: IF funciona sem pgvector (perde busca vetorial) |
| Overhead de performance | 10% | Baixo | IF scoring = <1ms, baselines = in-memory |

### 4.2 Riscos de Produto

| Risco | Prob. | Impact | Mitigação |
|-------|-------|--------|-----------|
| Operador não confia nos scores ML | 40% | Alto | Explicabilidade obrigatória: sempre mostrar POR QUE |
| Complexidade assusta novos usuários | 30% | Médio | ML é opt-in, padrão = regras determinísticas |
| Falso negativo ML gera incidente real | 15% | Crítico | ML nunca desabilita regras existentes, só adiciona camada |
| Métricas de sucesso difíceis de medir | 50% | Médio | Definir baseline ANTES de implementar (contar FP/FN agora) |

### 4.3 Riscos Organizacionais

| Risco | Prob. | Impact | Mitigação |
|-------|-------|--------|-----------|
| Projeto demora mais que estimado | 60% | Médio | Fases incrementais, cada uma entrega valor isolado |
| Complexidade de manutenção a longo prazo | 40% | Alto | Código simples, TypeScript puro, sem deps pesadas |
| Dificuldade de debugging em produção | 50% | Médio | Logs detalhados de scoring, dashboard de explicabilidade |

---

## 5. Alternativas a ML

### 5.1 Melhorar Regras (Sem ML)

Em vez de ML, podemos:
- Tornar thresholds configuráveis por servidor
- Adicionar "quiet hours" por servidor (ex: não alertar 3-4am)
- Adicionar whitelist de IPs por servidor
- Regras compostas (IF ssh_fails > 10 AND port_scans > 3 THEN alert)

**Prós:** Simples, previsível, fácil de debugar  
**Contras:** Manual, não escala, não aprende, operador precisa configurar tudo

### 5.2 Só AI (Sem ML local)

Enviar tudo para GPT-5.2/Gemini e deixar o LLM decidir:
- "Aqui estão os últimos 100 eventos. O que é suspeito?"

**Prós:** Zero implementação local, reasoning sofisticado  
**Contras:** Custo ($), latência (5-10s/request), sem baseline (cada análise é independente), vendor lock-in

### 5.3 ML Como Proposto (Hybrid)

Baselines locais + IF para scoring rápido + AI para casos complexos.

**Prós:** Melhor dos mundos, escala, aprende, baixo custo  
**Contras:** Mais código para manter, complexidade

---

## 6. Recomendação

### Fase 1 (Statistical Baselines): **GO**

Razões:
1. ROI inequívoco (menos falsos positivos = operador mais feliz)
2. Zero risco de infra (TypeScript puro)
3. Reversível (desliga e volta ao normal)
4. Valor isolado (funciona sem Fase 2)
5. Pré-requisito para Fase 2 (fornece features)

### Fase 2 (Isolation Forest): **CONDITIONAL GO**

Condicional a:
1. Fase 1 implementada e validada (2-3 semanas de dados)
2. Pelo menos 7 dias de feature vectors coletados
3. Confirmação de que pgvector roda no ambiente alvo

Razões para go condicional:
- Valor real (detecta ataques que regras perdem)
- Sem infra adicional (pgvector no PG existente)
- Implementação simples (~500 linhas IF em TS)
- Mas depende de bom feature engineering que só pode ser validado com dados reais

---

## 7. Sequência de Implementação

```
Semana 1-3: Statistical Baselines
  ├── Tabelas + migração
  ├── ServerBaseline (hourly means/stddevs)
  ├── UserBaseline (SSH profiles)
  ├── IPReputation (scoring cumulativo)
  └── ScoringEngine (combina tudo)

Semana 4: Validação
  ├── Rodar 7 dias com baselines + alertas antigos em paralelo
  ├── Comparar: "baseline teria eliminado este falso positivo?"
  └── Ajustar thresholds baseado em dados reais

Semana 5-7: Isolation Forest (se Fase 1 validada)
  ├── pgvector setup
  ├── Feature extractor
  ├── IsolationForest TypeScript
  ├── Integração com pipeline
  └── Dashboard de anomalias

Semana 8: Validação IF
  ├── Rodar 7 dias com IF + regras em paralelo
  ├── Analisar: "IF teria pego algo que regras perderam?"
  └── Ajustar contamination/features
```

---

## 8. Métricas de Decisão Final

**Para decidir se valeu a pena (após 30 dias em produção):**

| Métrica | Meta | Medição |
|---------|------|---------|
| Redução de falsos positivos | >= 40% | Comparar alertas/semana antes vs depois |
| Novos ataques detectados | >= 1/mês | Incidentes pegos por IF que regras perderam |
| Tempo médio de detecção | -30% | Tempo entre primeiro evento e alerta |
| Satisfação do operador | Subjetiva | "Os alertas fazem sentido? Confia neles?" |
| Overhead de performance | < 5% CPU | Monitorar uso de recursos do Guardian |

---

## 9. Conclusão

ML para o Guardian não é sobre "ter ML porque é trendy". É sobre resolver problemas concretos:

1. **Fadiga de alertas** — o operador ignora alertas porque metade são falsos → baselines resolvem
2. **Ataques invisíveis** — ataques distribuídos passam abaixo dos thresholds → IF resolve
3. **Zero aprendizado** — os mesmos erros se repetem → baselines + retraining resolvem

A abordagem proposta é **conservadora** (não substitui regras, adiciona camada) e **incremental** (cada fase entrega valor isolado). O custo é baixo (TypeScript puro, PG existente) e o risco é gerenciável (reversível, explicável).

**Decisão sugerida:** Implementar Fase 1 imediatamente. Avaliar Fase 2 após 2-3 semanas de dados.
