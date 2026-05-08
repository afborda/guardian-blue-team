<p align="center">
  <img src="docs/guardian-overview.png" alt="Guardian Blue Team" width="100%">
</p>

<p align="center">
  <a href="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml"><img src="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://ghcr.io/afborda/guardian-blue-team"><img src="https://img.shields.io/badge/Docker-ghcr.io-blue" alt="Docker"></a>
  <img src="https://img.shields.io/badge/version-2.0.0-blue" alt="Version">
</p>

<p align="center">
  <b>SIEM/SOAR Agentless com AI Local</b> — Detecta, Analisa, Bloqueia, Aprende<br>
  <a href="README.md"><strong>English</strong></a> · <a href="docs/getting-started.md">Instalacao</a> · <a href="docs/architecture.md">Arquitetura</a> · <a href="docs/configuration.md">Configuracao</a>
</p>

---

**Guardian** e um SIEM/SOAR agentless que monitora seus servidores via SSH, detecta ameacas em tempo real, e responde automaticamente com bloqueios permanentes. Nenhum agente para instalar, nenhum setup complexo — aponte para seus servidores e ele comeca a protege-los.

Usa AI local (Ollama) para analise de ameacas, constroi memoria semantica de cada incidente (RAG com embeddings), caca ameacas proativamente a cada 4 horas, e fornece resposta graduada a DDoS com escalacao automatica.

---

## Como Funciona

```mermaid
flowchart LR
    subgraph Coleta["Coleta (a cada 2min)"]
        SSH[SSH Logs]
        UFW[Firewall/UFW]
        NET[Rede]
        PROC[Processos]
        DOCKER[Docker Events]
        AUDIT[Audit/Syslog]
    end

    subgraph Pipeline["Pipeline de Processamento"]
        NORM[Normalizar]
        DETECT[Regras de Deteccao]
        ENRICH[Enriquecer\nGeo + Threat Intel]
        CORRELATE[Correlacionar\nIncidentes]
    end

    subgraph AI["Camada AI"]
        ADVISOR[Block Advisor\nblock / rate-limit / monitor]
        HUNTER[Threat Hunter\nScan proativo 4h]
        RAG[Memoria RAG\nEmbeddings + Historico]
    end

    subgraph Resposta["Resposta Automatica"]
        BLOCK[Bloqueio Permanente\nUFW / fail2ban]
        RATE[Rate Limit\niptables]
        ESCALATE[Escalar\nrate-limit → block]
        NOTIFY[Alerta Telegram]
    end

    Coleta --> NORM --> DETECT --> ENRICH --> CORRELATE
    CORRELATE --> ADVISOR
    ADVISOR -->|"block"| BLOCK
    ADVISOR -->|"rate_limit"| RATE
    ADVISOR -->|"monitor"| NOTIFY
    RATE -->|"ataque continua"| ESCALATE --> BLOCK
    HUNTER --> RAG
    CORRELATE --> NOTIFY
    BLOCK --> NOTIFY
```

---

## Comparativo

| | Fail2ban | CrowdSec | Wazuh | **Guardian** |
|-|----------|----------|-------|:------------:|
| Setup | 5 min | 30 min | 2+ horas | **30 segundos** |
| Agentes nos alvos | Sim | Sim | Sim | **Nao** |
| Decisoes com AI | — | — | — | **Local-first** |
| Aprende com incidentes | — | — | — | **RAG + Embeddings** |
| Deteccao DDoS | — | Parcial | — | **SYN/Rate/Bandwidth** |
| Caca proativa de ameacas | — | — | — | **A cada 4 horas** |
| ML comportamental | — | — | — | **Sim** |
| Alertas mobile-first | — | — | — | **Telegram** |
| Bloqueios permanentes | Config | Config | — | **Sempre** |

---

## Visao da Arquitetura

```mermaid
graph TB
    subgraph Servers["Servidores Monitorados (SSH)"]
        S1[Servidor A]
        S2[Servidor B]
        S3[Servidor C]
    end

    subgraph Guardian["Guardian (Docker)"]
        COLLECT[Coletores\n12 tipos]
        PIPE[Pipeline\nNormalizar → Detectar → Enriquecer → Correlacionar]
        ENGINE[Engine de Playbooks\n15+ playbooks automatizados]
        AI_LAYER[Camada AI\nOllama qwen3 + nomic-embed-text]
        DB[(PostgreSQL\nEventos, Incidentes, Bloqueios, Memoria)]
        WORKERS[Workers\n12 processos em background]
    end

    subgraph External["Integracoes"]
        TG[Bot Telegram\n30+ comandos]
        DASH[Dashboard Web\n12 paginas]
        INTEL[Threat Intel\nAbuseIPDB + VirusTotal]
    end

    S1 & S2 & S3 -->|"SSH (read-only)"| COLLECT
    COLLECT --> PIPE --> ENGINE
    ENGINE -->|"block/rate-limit"| S1 & S2 & S3
    PIPE --> DB
    AI_LAYER --> ENGINE
    AI_LAYER --> DB
    WORKERS --> PIPE
    Guardian --> TG & DASH
    INTEL --> PIPE
```

---

## Features Principais (v2.0)

### Bloqueio Permanente — Uma Vez Bloqueado, Sempre Bloqueado

Toda ameaca detectada e bloqueada permanentemente em todos os servidores. Sem TTL, sem auto-desbloqueio. Desbloqueio e apenas manual (via dashboard ou comando `/unblock`).

```mermaid
flowchart LR
    THREAT[Ameaca Detectada] --> BLOCK[Bloqueio Permanente]
    BLOCK --> VERIFY{Verificar no\nfirewall}
    VERIFY -->|confirmado| DB[(Registrar no DB\nverified: true)]
    VERIFY -->|falhou| RETRY[Retentar via\nmetodo alternativo]
    RETRY --> DB
```

### Deteccao DDoS e Resposta Graduada

```mermaid
flowchart TD
    ATTACK[Ataque DDoS] --> DETECT_SYN{SYN Flood?\n>50 SYN_RECV}
    ATTACK --> DETECT_RATE{Taxa de Conexao?\n>100/seg}
    ATTACK --> DETECT_BW{Bandwidth?\n>3σ do baseline}
    
    DETECT_SYN & DETECT_RATE & DETECT_BW -->|sim| RATE_LIMIT[Rate Limit\n10 req/seg, burst 20]
    RATE_LIMIT --> WATCH{Continua atacando?\ncheck 2min}
    WATCH -->|sim| PERMANENT[Bloqueio Permanente\n+ Alerta Telegram]
    WATCH -->|nao| KEEP[Manter Rate Limit]
```

### Decisoes com AI

```mermaid
flowchart LR
    EVENT[Evento de Seguranca] --> ADVISOR[AI Block Advisor]
    ADVISOR --> HISTORY[Consultar Memoria RAG\nBusca semantica]
    ADVISOR --> INTEL[Verificar Threat Intel]
    HISTORY & INTEL --> DECISION{Decisao AI\n+ confianca %}
    DECISION -->|"≥70% block"| BLOCK[Bloqueio Permanente]
    DECISION -->|"≥70% rate_limit"| RATE[Rate Limit]
    DECISION -->|"≥70% monitor"| MONITOR[Apenas Monitorar]
    DECISION -->|"<70% confianca"| DEFAULT[Default por Regra\n= Bloquear]
```

### Caca Proativa de Ameacas

A cada 4 horas, a AI do Guardian analisa as ultimas 6 horas de eventos buscando:
- Ataques coordenados de multiplos IPs
- Padroes de APT (slow-roll)
- Reconhecimento/scanning ativo
- Indicadores de movimento lateral
- Padroes de atividade incomuns

Findings sao armazenados em `threat_hunt_findings` e os de alta/critica severidade sao enviados ao Telegram imediatamente.

### Verificacao de Login com Inteligencia de IP

Quando um login SSH e detectado, Guardian envia notificacao no Telegram com:
- Servidor, usuario, metodo de autenticacao, fingerprint
- **Geolocalizacao do IP** (pais, ISP)
- **Score de reputacao** (AbuseIPDB + VirusTotal)
- Nivel de risco (Limpo / Suspeito / Alto Risco)
- Botoes de acao: ✅ Sou eu | ❌ NAO sou eu | 👁️ Monitorar

### RAG — Aprende com Cada Incidente

```mermaid
flowchart LR
    INCIDENT[Novo Incidente] --> EMBED[Gerar Embedding\nnomic-embed-text]
    EMBED --> STORE[(Vector Store\nPostgreSQL)]
    
    NEXT[Proximo Incidente\nSimilar] --> SEARCH[Busca Semantica\nCosine Similarity]
    STORE --> SEARCH
    SEARCH --> CONTEXT[Contexto Historico\nResolucoes passadas]
    CONTEXT --> AI[AI usa historico\npara melhores decisoes]
```

---

## Contra O Que Protege

| Categoria | Ameacas | Resposta |
|----------|---------|----------|
| **SSH** | Brute force, usuarios invalidos, logins nao autorizados, horarios incomuns, movimento lateral | Bloqueio permanente |
| **DDoS** | SYN flood, pico de conexoes, anomalia de bandwidth | Rate-limit → Escalar → Bloquear |
| **Rede** | Port scanning, DNS DGA (C2), TLDs suspeitos, flood de conexoes | Bloqueio permanente |
| **Containers** | Tentativas de escape, crypto mining, crashloops, abuso de recursos | Kill + block + isolar |
| **Integridade** | /etc/passwd, sudoers, sshd_config, authorized_keys alterados | Alerta critico |
| **Supply Chain** | CVEs em pacotes instalados (OSV.dev) | Alerta + passos de remediacao |
| **Persistencia** | Cron jobs maliciosos, reverse shells, chaves SSH nao autorizadas | Alerta + bloquear |

15+ regras de deteccao, 15+ playbooks automatizados.

---

## Workers (Processos em Background)

| Worker | Intervalo | Funcao |
|--------|----------|--------|
| Event Collector | 2 min | Coleta logs de todos servidores, roda pipeline |
| DDoS Escalation | 2 min | Verifica IPs com rate-limit, escala para bloqueio |
| Score Calculator | 5 min (metricas), 1h (scores) | Health + security scores |
| Threat Hunter | 4 horas | Analise proativa AI de padroes |
| Intelligence | 1 hora | Profiling comportamental ML |
| FIM | 4 horas | Monitoramento de integridade de arquivos |
| CVE Monitor | 6 horas | Scan de vulnerabilidades |
| Block Cleanup | 5 min | Garante que todos bloqueios sao permanentes |
| Daily Report | 08:00 BRT | Resumo diario no Telegram |
| Metrics Retention | 24 horas | Remove dados com mais de 30 dias |
| Discovery | 24 horas | Auto-descobre novos servicos |
| Vuln Scanner | Semanal (Sab 09:00) | Scan profundo de vulnerabilidades |

---

## Consumo de Recursos

| Componente | RAM | Disco | CPU |
|-----------|-----|-------|-----|
| Guardian (app) | 50-100 MB | 200 MB | 0.5 core |
| PostgreSQL | 64-256 MB | 500 MB-2 GB | 0.2 core |
| Ollama (AI local) | 4-6 GB | 3 GB | 2 cores (pico) |
| **Total sem AI** | **~300 MB** | **~2 GB** | **1 core** |
| **Total com AI** | **~6 GB** | **~5 GB** | **2 cores** |

Nao quer AI local? Configure `GEMINI_API_KEY` — tier gratuito do Google funciona. Ou defina `AI_STRATEGY=api-only`.

---

## Quick Start (5 minutos)

### 1. Clone e Configure

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
cp .env.example .env
```

Edite `.env`:

```env
TELEGRAM_BOT_TOKEN=seu_token_do_botfather
TELEGRAM_CHAT_ID=seu_chat_id
GUARDIAN_BASE_URL=https://guardian.seudominio.com
GUARDIAN_DB_PASSWORD=senha_forte_aqui
DASHBOARD_TOKEN=string_aleatoria_para_acesso_web

# AI (escolha um ou ambos):
GEMINI_API_KEY=sua_chave_google_ai_gratis    # Fallback API
AI_STRATEGY=auto                              # auto | local-only | api-only

# Threat Intel (opcional mas recomendado):
ABUSEIPDB_API_KEY=sua_chave_gratis
```

### 2. Inicie

```bash
docker compose up -d
```

Aguarde 2-3 minutos para Ollama baixar modelos AI (`qwen3:4b` + `nomic-embed-text`).

### 3. Adicione Servidores

Envie `/help` para seu bot no Telegram. Depois:

```
/add-server meuserver 1.2.3.4 22 root
```

Guardian gera uma chave SSH, mostra a chave publica para adicionar ao alvo, e comeca a monitorar imediatamente.

### O Que Acontece Automaticamente

```mermaid
gantt
    title Timeline de Startup do Guardian
    dateFormat X
    axisFormat %s

    section Imediato
    Health check : 0, 5
    Webhook Telegram : 0, 3
    
    section 30 segundos
    Coleta de eventos : 10, 30
    Coleta de metricas : 10, 30
    
    section 5 minutos
    Primeira caca de ameacas : 300, 360
    Calculo de scores : 300, 360
    
    section Contínuo
    Coleta a cada 2min : 120, 900
    Check DDoS a cada 2min : 120, 900
    AI hunting a cada 4h : 600, 900
```

---

## Estrategia de AI

Guardian suporta tres modos de AI via `AI_STRATEGY`:

| Modo | Comportamento |
|------|----------|
| `auto` (padrao) | Ollama primeiro → Gemini → OpenAI → Claude |
| `local-only` | Apenas Ollama (totalmente offline, nenhum dado sai do servidor) |
| `api-only` | Apenas APIs cloud (quando nao tem GPU para Ollama) |

AI e usada para:
- Decisoes de bloqueio (AI Block Advisor)
- Caca proativa de ameacas (a cada 4h)
- Analise de incidentes (comando `/ask`)
- Relatorios diarios
- Contexto de verificacao de login

Se AI estiver completamente indisponivel, Guardian faz fallback para defaults baseados em regras (sempre bloqueia).

---

## Fluxo de Dados — Ponta a Ponta

```mermaid
sequenceDiagram
    participant S as Servidores (SSH)
    participant C as Coletores
    participant P as Pipeline
    participant AI as Camada AI
    participant DB as PostgreSQL
    participant T as Telegram
    participant FW as Firewall

    loop A cada 2 minutos
        C->>S: Comandos SSH (read-only)
        S-->>C: Logs, metricas, estado da rede
        C->>P: Eventos brutos
        P->>P: Normalizar → Detectar → Enriquecer (GeoIP)
        P->>DB: Armazenar eventos
        P->>P: Correlacionar → Criar incidentes
        
        alt Novo incidente detectado
            P->>AI: Devemos bloquear este IP?
            AI->>DB: Consultar memoria RAG (incidentes similares)
            AI-->>P: Decisao (block/rate-limit/monitor)
            P->>FW: Aplicar regra de firewall
            FW-->>DB: Registrar bloqueio (verified)
            P->>T: Notificacao de alerta
        end
    end

    loop A cada 4 horas
        AI->>DB: Consultar ultimas 6h de eventos
        AI->>AI: Analise de padroes
        alt Findings
            AI->>T: Alerta de threat hunt
            AI->>DB: Armazenar findings
        end
    end
```

---

## Bot Telegram — 30+ Comandos

### Resposta a Incidentes (Botoes de Acao)

Todo incidente vem com botoes inline:

| Botao | Acao |
|--------|--------|
| ✅ Resolver | Marcar como tratado |
| 🚫 Falso Positivo | Dispensar + Guardian aprende (RAG) |
| 🔒 Bloquear IP | Bloqueio permanente no firewall |
| 🔍 Threat Intel | Reputacao do IP + recomendacao AI |

### Comandos Principais

| Comando | O que faz |
|---------|-----------|
| `/status` | Todos servidores de relance |
| `/incidents` | Incidentes abertos com botoes de acao |
| `/threat 1.2.3.4` | Reputacao do IP + geo + recomendacao |
| `/block 1.2.3.4` | Bloqueio permanente em todos servidores |
| `/unblock 1.2.3.4` | Remover bloqueio (apenas manual) |
| `/verify-blocks` | Verificar todos bloqueios existem nos firewalls |
| `/ask qualquer pergunta` | Analista AI responde com contexto |
| `/events` | Eventos de seguranca recentes |
| `/scores` | Scores de seguranca por servidor |
| `/report` | Relatorio de seguranca |
| `/vulns` | Vulnerabilidades CVE |
| `/dashboard` | Token temporario de acesso |
| `/help` | Todos os comandos |

---

## Dashboard

Dashboard web com 12 paginas:

**Visao Geral** · **Fleet Health** · **Scores** · **Incidentes** · **Servidores** · **CVE** · **Bloqueios** · **Logs** · **Timeline** · **Mapa de Ataques** · **Status API** · **Inteligencia**

Acesso: `https://seu-dominio/dashboard?token=TOKEN`

---

## Tech Stack

| Camada | Tecnologia |
|-------|-----------|
| Runtime | Node.js 20 + TypeScript |
| Banco de Dados | PostgreSQL 16 |
| AI (local) | Ollama + qwen3:4b + nomic-embed-text |
| AI (cloud) | Gemini / OpenAI / Claude (failover) |
| Firewall | UFW + fail2ban + iptables |
| Alertas | Telegram Bot API |
| Monitoramento | SSH (agentless) |
| Container | Docker + Docker Compose |
| Reverse Proxy | Traefik (HTTPS) |

---

## Documentacao

| Doc | Descricao |
|-----|-----------|
| [Instalacao](docs/getting-started.md) | Requisitos, passo-a-passo, troubleshooting |
| [Arquitetura](docs/architecture.md) | Diagramas de pipeline, estrutura de pastas |
| [Configuracao](docs/configuration.md) | Todas as variaveis de ambiente |
| [Features de Seguranca](docs/security-features.md) | Regras de deteccao, playbooks |
| [Inteligencia ML](docs/ml-intelligence.md) | Baselines comportamentais, scoring |
| [Memoria RAG](docs/rag-memory.md) | Como Guardian aprende com incidentes |
| [Comandos Telegram](docs/telegram-commands.md) | Todos os comandos com exemplos |
| [Dashboard](docs/dashboard.md) | Paginas, acesso, features |

---

## Contribuindo

Contribuicoes sao bem-vindas! Abra uma issue primeiro para discutir.

## Licenca

[AGPL-3.0](LICENSE)
