<p align="center">
  <img src="docs/guardian-overview.png" alt="Guardian Blue Team" width="100%">
</p>

<p align="center">
  <a href="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml"><img src="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://ghcr.io/afborda/guardian-blue-team"><img src="https://img.shields.io/badge/Docker-ghcr.io-blue" alt="Docker"></a>
  <img src="https://img.shields.io/badge/version-1.5.0-blue" alt="Version">
</p>

<p align="center">
  <a href="README.md"><strong>English</strong></a> · <a href="docs/getting-started.md">Instalacao</a> · <a href="docs/architecture.md">Arquitetura</a> · <a href="docs/configuration.md">Configuracao</a>
</p>

---

**Guardian** e um SIEM/SOAR agentless que monitora seus servidores via SSH, detecta ameacas em tempo real, e responde automaticamente. Nenhum agente para instalar, nenhum setup complexo — aponte para seus servidores e ele comeca a protege-los.

Aprende com cada incidente, constroi baselines comportamentais para usuarios e containers, e melhora a precisao de deteccao com o tempo — tudo rodando localmente numa unica maquina.

---

## Visao Geral

| | Fail2ban | CrowdSec | Wazuh | **Guardian** |
|-|----------|----------|-------|:------------:|
| Setup | 5 min | 30 min | 2+ horas | **30 segundos** |
| Agentes nos alvos | Sim | Sim | Sim | **Nao** |
| Analise AI | — | — | — | **Local-first** |
| Aprende com incidentes | — | — | — | **Sim (RAG)** |
| ML comportamental | — | — | — | **Sim** |
| Alertas mobile-first | — | — | — | **Telegram** |

---

## Consumo de Recursos

| Componente | RAM | Disco | CPU |
|-----------|-----|-------|-----|
| Guardian (app) | 50-100MB | 200MB | 0.5 core |
| PostgreSQL | 64-256MB | 500MB-2GB | 0.2 core |
| Ollama (opcional, AI local) | 4-6GB | 3GB | 2 cores (pico) |
| **Total sem AI local** | **~300MB** | **~2GB** | **1 core** |
| **Total com AI local** | **~6GB** | **~5GB** | **2 cores** |

Nao quer rodar AI local? Configure `GEMINI_API_KEY` — o tier gratuito do Google resolve.

---

## Contra O Que Protege

- **SSH**: brute force, logins nao autorizados, movimento lateral, horarios incomuns
- **Containers**: tentativas de escape, crashloops, crypto mining, abuso de recursos
- **Integridade de Arquivos**: /etc/passwd, sudoers, sshd_config, authorized_keys
- **Rede**: port scanning, DNS DGA (deteccao C2), TLDs suspeitos
- **Supply Chain**: monitoramento de CVE em pacotes instalados (OSV.dev)
- **Persistencia**: cron jobs maliciosos, reverse shells, chaves SSH nao autorizadas

15+ regras de deteccao, 15 playbooks automatizados. [Detalhes completos →](docs/security-features.md)

---

## Por Que ML e RAG?

**ML Behavioral Baselines** — Guardian aprende o que e "normal" para cada usuario SSH (horarios, IPs, chaves) e cada container (CPU, memoria, restarts). Quando algo desvia, pontua a anomalia 0-1 em vez de disparar alerta binario. Resultado: ~50% menos falsos positivos apos 7 dias.

**RAG Memoria de Incidentes** — Cada incidente resolvido e armazenado. Na proxima vez que algo similar acontece, Guardian diz pra AI: "Ultima vez que esse IP atacou, bloqueamos por 24h e voltou. Recomendo block permanente." Fica mais inteligente toda semana sem treinamento manual.

- Latencia de deteccao: ~2 minutos
- Resposta automatica: ~5 segundos (execucao de playbook)
- Zero dependencias externas para ML (estatistica pura em TypeScript)

[Detalhes ML →](docs/ml-intelligence.md) · [Detalhes RAG →](docs/rag-memory.md)

---

## Quick Start

### O que voce precisa

| Dado | Como obter | Obrigatorio? |
|------|-----------|:------------:|
| Telegram Bot Token | [@BotFather](https://t.me/BotFather) → `/newbot` | Sim |
| Telegram Chat ID | Envie qualquer coisa para [@userinfobot](https://t.me/userinfobot) | Sim |
| Dominio publico (HTTPS) | DNS apontando para seu servidor | Sim |
| Chave SSH | Auto-gerada ou use `~/.ssh/id_ed25519` existente | Auto |
| AI API key | [aistudio.google.com](https://aistudio.google.com/) (gratis) ou pule (Ollama roda local) | Nao |

### Instalacao

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
cp .env.example .env
```

Edite `.env` — preencha **apenas estes 4 valores**:

```env
TELEGRAM_BOT_TOKEN=seu_token_do_botfather
TELEGRAM_CHAT_ID=seu_chat_id
GUARDIAN_BASE_URL=https://guardian.seudominio.com
GUARDIAN_DB_PASSWORD=senha_forte_aqui
```

Inicie:

```bash
docker compose up -d
```

Aguarde 2-3 minutos (Ollama baixa modelos AI na primeira execucao).

### Verificacao

Envie `/help` para seu bot no Telegram. Se respondeu, esta pronto.

Adicione seu primeiro servidor:
```
/add-server meuserver 1.2.3.4 22 root
```

Aguarde 5 minutos, depois:
```
/status     → metricas do servidor
/events     → eventos de seguranca
/scores     → scores de saude
```

### O que inicia automaticamente

- Webhook do Telegram registrado (bot comeca a receber mensagens)
- PostgreSQL inicializado com schema
- Ollama baixa modelos (qwen3:4b + nomic-embed-text)
- Coleta de eventos a cada 2 minutos
- ML profiling e deteccao de anomalias a cada hora
- Relatorio diario as 08:00 BRT

[Guia completo de instalacao com troubleshooting →](docs/getting-started.md)

---

## Telegram (30+ comandos)

| Comando | O que faz |
|---------|-----------|
| `/status` | Todos os servidores de relance |
| `/block <ip>` | Bloqueia IP imediatamente via UFW |
| `/ask <pergunta>` | Consulta em linguagem natural (AI) |
| `/events` | Eventos de seguranca recentes |
| `/memory` | Stats da memoria de incidentes (RAG) |

[Todos os 30+ comandos com exemplos →](docs/telegram-commands.md)

---

## Dashboard

Dashboard web com 11 paginas em `https://seu-dominio/dashboard?token=TOKEN`

Overview · Fleet Health · Scores · Incidents · Servers · CVE · Blocks · Logs · Timeline · Attack Map · API Status

[Detalhes do dashboard →](docs/dashboard.md)

---

## Documentacao

| Doc | Descricao |
|-----|-----------|
| [Instalacao](docs/getting-started.md) | Requisitos, passo-a-passo, troubleshooting |
| [Arquitetura](docs/architecture.md) | Diagramas de pipeline, estrutura de pastas, fluxo de dados |
| [Configuracao](docs/configuration.md) | Todas as variaveis de ambiente com exemplos |
| [Features de Seguranca](docs/security-features.md) | Regras de deteccao, playbooks, CVE |
| [Inteligencia ML](docs/ml-intelligence.md) | Baselines comportamentais, scoring, consumo |
| [Memoria RAG](docs/rag-memory.md) | Como Guardian aprende com incidentes passados |
| [Comandos Telegram](docs/telegram-commands.md) | Todos os comandos com exemplos |
| [Dashboard](docs/dashboard.md) | Paginas, acesso, stack tecnica |

---

## Contribuindo

Contribuicoes sao bem-vindas! Abra uma issue primeiro para discutir.

## Licenca

[AGPL-3.0](LICENSE)
