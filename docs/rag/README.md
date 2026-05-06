# Guardian Blue Team — Estudo RAG (Retrieval-Augmented Generation)

Estudo aprofundado sobre implementação de RAG no Guardian para dar memória ao agente, permitindo decisões baseadas em histórico e aprendizado contínuo.

## Documentos

| Documento | Foco |
|-----------|------|
| [01-estado-atual-ai.md](./01-estado-atual-ai.md) | Como AI é usado hoje, limitações, contexto que falta |
| [02-proposta-rag-pgvector.md](./02-proposta-rag-pgvector.md) | Arquitetura RAG com pgvector (sem Qdrant) |
| [03-embeddings-e-busca.md](./03-embeddings-e-busca.md) | Modelos de embedding, busca semântica, performance |
| [04-valor-e-riscos.md](./04-valor-e-riscos.md) | Análise de valor, riscos, e decisão go/no-go |

## Princípio

RAG no Guardian existe para responder uma pergunta: **"Já vimos isso antes? O que fizemos? Funcionou?"**

Cada decisão do agente deve ser informada pelo histórico. Não é sobre ter um chatbot sofisticado — é sobre decisões melhores baseadas em experiência acumulada.
