# Guardian Blue Team — Estudo ML (Machine Learning)

Estudo aprofundado sobre implementação de Machine Learning no Guardian para detecção de anomalias, redução de falsos positivos, e evolução do sistema de segurança.

## Documentos

| Documento | Foco |
|-----------|------|
| [01-estado-atual.md](./01-estado-atual.md) | O que temos hoje, limitações, dados disponíveis |
| [02-proposta-statistical-baselines.md](./02-proposta-statistical-baselines.md) | Fase 1: Baselines comportamentais sem deps externas |
| [03-proposta-isolation-forest.md](./03-proposta-isolation-forest.md) | Fase 2: Detecção multidimensional com pgvector |
| [04-valor-e-riscos.md](./04-valor-e-riscos.md) | Análise de valor, riscos, e decisão go/no-go |

## Princípio

ML no Guardian deve seguir o princípio: **"Valor incremental, complexidade mínima"**. Cada fase deve entregar valor mensurável ao operador (menos falsos positivos, detecção mais precisa) sem adicionar infraestrutura desnecessária.
