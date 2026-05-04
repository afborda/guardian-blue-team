<p align="center">
  <img src="https://img.shields.io/badge/Guardian-Blue%20Team-0066cc?style=for-the-badge&logo=shield&logoColor=white" alt="Guardian Blue Team">
</p>

<h1 align="center">Guardian Blue Team</h1>

<p align="center">
  <strong>SIEM/SOAR leve + Observabilidade de Infraestrutura para o resto de nos</strong>
</p>

<p align="center">
  <a href="README.md">Read in English</a>
</p>

<p align="center">
  <a href="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml"><img src="https://github.com/afborda/guardian-blue-team/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL-3.0"></a>
  <a href="https://ghcr.io/afborda/guardian-blue-team"><img src="https://img.shields.io/badge/Docker-ghcr.io-blue" alt="Docker"></a>
</p>

---

Guardian e um SIEM/SOAR agentless que monitora seus servidores via SSH, detecta ameacas em tempo real, computa scores de saude da infraestrutura, preve esgotamento de recursos, e responde automaticamente. Feito para operadores solo, startups pequenas, e homelabbers que querem monitoramento de nivel enterprise sem a complexidade enterprise.

## Por que Guardian?

| Feature | Fail2ban | CrowdSec | Wazuh | **Guardian** |
|---------|----------|----------|-------|--------------|
| Tempo de setup | 5 min | 30 min | 2+ horas | **30 segundos** |
| Instala nos alvos | Sim | Sim | Sim | **Nao (agentless SSH)** |
| Acoes de resposta | Block IP | Block IP | Scripts | **Playbooks + aprovacao** |
| Notificacoes | Email | — | Email | **7 canais** |
| Monitoramento CVE | — | — | Sim | **Sim (OSV.dev + AI fix)** |
| Score de saude | — | — | — | **6 dimensoes** |
| Deteccao de anomalias | — | — | — | **Baseline estatistico** |
| Predicao de tendencias | — | — | — | **Regressao linear** |
| Analise por IA | — | — | — | **4 providers** |
| Dashboard | — | Web | Web | **HTMX (leve)** |
| Mobile-first | — | — | — | **Telegram/WhatsApp** |
| Uso de recursos | Minimo | Baixo | Alto | **~50MB RAM** |

## Inicio Rapido

```bash
# Docker em uma linha (SQLite, zero dependencias)
docker run -d --name guardian \
  -e TELEGRAM_BOT_TOKEN=seu_token \
  -e TELEGRAM_CHAT_ID=seu_chat_id \
  -v guardian_data:/data \
  -v ~/.ssh:/home/node/.ssh:ro \
  -p 3334:3334 \
  ghcr.io/afborda/guardian-blue-team:latest
```

Ou use o instalador interativo:

```bash
curl -fsSL https://raw.githubusercontent.com/afborda/guardian-blue-team/main/install.sh | bash
```

O instalador guia voce por: geracao de chave SSH, configuracao do .env, escolha do provedor de IA, e setup do primeiro servidor — tudo com interface colorida no terminal.

## Arquitetura

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Guardian Core                                 │
├─────────────┬────────────┬─────────────┬─────────────┬───────────────┤
│  Coletores  │  Pipeline  │Inteligencia │  Playbook   │   Dashboard   │
│  (SSH/proc) │(Bronze→Gold)│(Anomalia/IA)│   Engine    │  (HTMX/SSR)  │
├─────────────┴────────────┴─────────────┴─────────────┴───────────────┤
│                     Sistema de Plugins (7 notificadores)               │
├────────┬─────────┬────────┬────────┬───────┬────────┬────────────────┤
│Telegram│ Discord │ Slack  │ Email  │ ntfy  │Webhook │  WhatsApp      │
└────────┴─────────┴────────┴────────┴───────┴────────┴────────────────┘
      ↕                    ↕                    ↕               ↕
 [Telegram Bot]     [PostgreSQL/SQLite]    [Servidores SSH] [Provedores IA]
  comandos+alertas    armazenamento        seus servidores  Gemini/GPT/Claude/Ollama
```

### Pipeline de Dados (Bronze → Silver → Gold)

```
Coletores (5min)            Pipeline                      Saida
────────────────            ────────                      ─────
Health  ─┐                  ┌─ Bronze ──────────────┐
System  ─┼─► cmds SSH ──►  │ server_metrics (bruto)│──► Dashboard
Perf    ─┘                  └───────────────────────┘
                                     │
                            ┌─ Gold ─┴──────────────┐
                            │ server_scores (6 dim) │──► Telegram
                            └───────────────────────┘
                                     │
                            ┌─ Inteligencia ────────┐
                            │ Anomalia + Tendencia  │──► Alertas
                            └───────────────────────┘
```

### Pipeline de Eventos de Seguranca

```
Logs SSH → Normalizar → Detectar → Enriquecer → Correlacionar → Playbook → Notificar
  (2min)    (parse)     (regras)    (intel)     (incidentes)    (auto)     (7 canais)

FIM/Cron/SSH Keys → Comparar Baseline → Detectar → Correlacionar → Playbook → Notificar
       (4h)             (diff no DB)      (regras)   (incidentes)    (auto)     (7 canais)
```

## Funcionalidades

### Monitoramento de Seguranca (SIEM/SOAR)

**Deteccao de Ameacas (15 regras embutidas):**
- Brute force SSH — 20+ tentativas de login falhadas do mesmo IP
- Port scanning — 5+ portas sondadas em 10 minutos
- Mineracao de cripto — Detecta xmrig, minerd, cpuminer, kdevtmpfsi, kinsing
- Binarios suspeitos — Execucao de /tmp, /dev/shm, paths ocultos
- Logins nao autorizados — SSH de IPs/fingerprints nao confiados
- Logins por senha — Alerta quando autenticacao por chave deveria ser obrigatoria
- Logins em horario incomum — Acesso entre 00:00-06:00 de IPs nao confiados
- Movimento lateral — SSH de IP que anteriormente fez brute force
- Escape de container — 5+ mortes de container em 10 minutos
- Tampering de arquivos criticos (FIM — /etc/passwd, shadow, sudoers, sshd_config)
- Comandos sudo suspeitos (curl, wget, nc, base64 -d, chmod 777)
- Persistencia via cron (novos crons com padrao de reverse shell / download)
- SSH keys nao autorizadas (novas chaves adicionadas ao authorized_keys)
- Deteccao de DGA via DNS (dominios com alta entropia Shannon)
- TLDs DNS suspeitos (.tk, .ml, .ga, .cf, .top, .xyz, .pw, .cc)

**Resposta Automatizada (15 playbooks):**
- Bloquear IPs maliciosos via UFW (automatico ou com aprovacao humana)
- Matar processos de mineracao de cripto
- Pausar/desconectar containers comprometidos
- Enriquecer IPs com threat intelligence (AbuseIPDB, VirusTotal)
- Rastrear reincidentes entre servidores
- Alertar sobre violacoes de integridade de arquivo (requer aprovacao)
- Flagrar atividade sudo suspeita
- Detectar mecanismos de persistencia via cron (requer aprovacao)
- Alertar sobre adicao de SSH keys nao autorizadas (requer aprovacao)
- Responder a indicadores C2 via DNS (DGA + TLDs suspeitos)

**Monitoramento de CVE:**
- Escaneia pacotes instalados (Debian, Alpine, npm) contra OSV.dev
- Recomendacoes de fix por IA com avaliacao de risco
- Patching em um clique via Telegram com aprovacao humana

### Observabilidade de Infraestrutura

**Coletores (agentless, via SSH lendo /proc):**

| Coletor | Dados | Fonte |
|---------|-------|-------|
| Health | Load CPU, memoria, swap, uso de disco, uptime | `/proc/loadavg`, `free`, `df`, `/proc/uptime` |
| System | Erros kernel, erros journal, unidades systemd falhadas | `dmesg`, `journalctl`, `systemctl` |
| Performance | Disk I/O (read/write Bps), Network I/O (rx/tx Bps) | `/proc/diskstats`, `/proc/net/dev` (delta sampling) |

**Scoring de Servidor em 6 Dimensoes (0-100, baseado em penalidades):**

| Score | O que mede | Peso |
|-------|-----------|------|
| Health | Load ratio CPU, memoria %, disco %, swap % | 20% |
| Security | Incidentes abertos, eventos de ataque, IPs bloqueados | 25% |
| Quality | Servicos falhados, erros kernel, erros journal, uptime | 15% |
| Waste | CPU ociosa, memoria nao usada, recursos desperdicados | 10% |
| Vulnerability | CVEs abertas (criticas/altas), dias desde ultimo scan | 20% |
| Availability | Uptime, reinicializacoes de servicos, crashes de container | 10% |

**Score Geral** = media ponderada das 6 dimensoes.

### Camada de Inteligencia com IA

Funciona com 4 provedores (configuravel, com fallback automatico):

| Provedor | Config | Uso |
|----------|--------|-----|
| Gemini | `GEMINI_API_KEY` | Tier gratis, rapido, recomendado |
| OpenAI | `OPENAI_API_KEY` | GPT-4o-mini para analise |
| Claude | `ANTHROPIC_API_KEY` | Melhor raciocinio |
| Ollama | `OLLAMA_URL` | Local, gratis, mais lento |

**Capacidades:**

| Funcionalidade | Precisa API? | Descricao |
|----------------|-------------|-----------|
| Deteccao de Anomalias | Nao | Baseline estatistico (media + 2.5σ sobre 7 dias) |
| Predicao de Tendencias | Nao | Regressao linear — preve esgotamento de disco/memoria |
| Analise de Causa Raiz | Opcional | IA explica por que um score caiu significativamente |
| Recomendacoes de Otimizacao | Opcional | Sugestoes semanais priorizadas por impacto |
| Consultas em Linguagem Natural | Sim | Faca perguntas via `/ask` no Telegram |

### Dashboard (HTMX, renderizado no servidor)

| Pagina | URL | Descricao |
|--------|-----|-----------|
| Overview | `/dashboard` | Resumo (servidores, incidentes, blocks, CVEs) |
| Fleet Health | `/dashboard/health` | Cards de score por servidor com cores |
| Detalhe Servidor | `/dashboard/health/:id` | Metricas, discos, unidades falhadas |
| Grid de Scores | `/dashboard/scores` | Tabela comparativa: servidores x 6 dimensoes |
| Incidentes | `/dashboard/incidents` | Incidentes abertos com severidade |
| Servidores | `/dashboard/servers` | Servidores registrados + ultima conexao |
| Alertas CVE | `/dashboard/cve` | CVEs pendentes com acoes one-click |
| Blocks IP | `/dashboard/blocks` | Blocks ativos com botao de unblock |
| Logs | `/dashboard/logs` | Eventos de seguranca recentes |

### Comandos Telegram

| Comando | Descricao |
|---------|-----------|
| `/status` | Overview dos servidores (load, mem, disco) |
| `/health` | Saude da frota com scores e metricas |
| `/scores` | Grid de scores (6 dimensoes) de todos servidores |
| `/scores <server>` | Scores detalhados de um servidor |
| `/servers` | Lista + verificacao de conectividade |
| `/containers` | Containers Docker rodando |
| `/events` | Eventos de seguranca recentes (filtravel) |
| `/incidents` | Incidentes abertos |
| `/threat <ip>` | Reputacao do IP + historico local |
| `/hunt <ip\|user>` | Buscar nos logs por IOC |
| `/files [server]` | Mudancas de integridade de arquivos |
| `/sudo [hours]` | Atividade sudo (default 24h) |
| `/crons [server]` | Cron jobs / mudancas recentes |
| `/keys [server]` | SSH keys / mudancas recentes |
| `/dns [server] [hours]` | Queries DNS / anomalias |
| `/playbook list` | Playbooks disponiveis |
| `/playbook run <nome> <server> [ip]` | Executar um playbook |
| `/vulns` | Resumo de vulnerabilidades |
| `/ask <pergunta>` | Consulta em linguagem natural com IA |
| `/report` | Forcar relatorio diario |
| `/report full` | Relatorio historico completo |
| `/add-server <nome> <host> [porta] [user] [key]` | Registrar servidor |
| `/rm-server <nome>` | Remover servidor |

## Configuracao

### Obrigatorias

| Variavel | Descricao |
|----------|-----------|
| `TELEGRAM_BOT_TOKEN` | De [@BotFather](https://t.me/BotFather) |
| `TELEGRAM_CHAT_ID` | De [@userinfobot](https://t.me/userinfobot) |

### Principais

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `PORT` | `3334` | Porta HTTP |
| `NODE_ENV` | `development` | `production` para logs otimizados |
| `DATABASE_URL` | SQLite | URL PostgreSQL ou `sqlite:/caminho/arquivo.db` |
| `DASHBOARD_TOKEN` | — | Token para acessar dashboard web |
| `NOTIFIERS` | `telegram` | Separados por virgula: `telegram,discord,slack,whatsapp,email,ntfy,webhook` |

### Provedores de IA

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `AI_PROVIDER` | `auto` | `gemini`, `openai`, `claude`, `ollama`, ou `auto` |
| `GEMINI_API_KEY` | — | Chave Google AI Studio |
| `GEMINI_MODEL` | `gemini-2.0-flash-001` | Modelo Gemini |
| `OPENAI_API_KEY` | — | Chave OpenAI |
| `OPENAI_MODEL` | `gpt-4o-mini` | Modelo OpenAI |
| `ANTHROPIC_API_KEY` | — | Chave Anthropic |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6-20250514` | Modelo Claude |
| `OLLAMA_URL` | `http://localhost:11434` | Instancia Ollama local |
| `OLLAMA_MODEL` | `qwen3:4b` | Modelo para analise |
| `OLLAMA_CHAT_MODEL` | `qwen3:0.6b` | Modelo leve para chat |

### Threat Intelligence

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB (gratis: 1000/dia) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal (gratis: 500/dia) |
| `ABUSE_CONFIDENCE_THRESHOLD` | `70` | Confianca minima para auto-block |

### Monitor CVE

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `CVE_MONITOR_ENABLED` | `true` | Ativar/desativar scan |
| `CVE_MONITOR_MIN_CVSS` | `7.0` | CVSS minimo para alertar (7.0 = High+) |
| `CVE_MONITOR_INTERVAL_HOURS` | `6` | Intervalo de verificacao |

### Canais de Notificacao

| Variavel | Descricao |
|----------|-----------|
| `DISCORD_WEBHOOK_URL` | URL do webhook Discord |
| `SLACK_WEBHOOK_URL` | URL do incoming webhook Slack |
| `RESEND_API_KEY` | Chave API Resend para alertas por email |
| `RESEND_FROM_EMAIL` | Endereco de email remetente |
| `WHATSAPP_API_URL` | URL da Evolution API |
| `WHATSAPP_INSTANCE` | Nome da instancia Evolution API |
| `WHATSAPP_NUMBER` | Numero de telefone destino |
| `NTFY_SERVER` | URL do servidor ntfy (padrao: https://ntfy.sh) |
| `NTFY_TOPIC` | Nome do topico ntfy |
| `WEBHOOK_URL` | Endpoint do webhook customizado |
| `WEBHOOK_SECRET` | Segredo HMAC para assinatura do webhook |

### SSH Padroes

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `HOST_SSH_HOST` | `127.0.0.1` | Host SSH padrao |
| `HOST_SSH_PORT` | `22` | Porta SSH padrao |
| `HOST_SSH_USER` | `ubuntu` | Usuario SSH padrao |
| `HOST_SSH_KEY_PATH` | `/home/node/.ssh/id_ed25519` | Caminho para chave SSH privada |

### Seguranca — Entidades Confiaveis

| Variavel | Padrao | Descricao |
|----------|--------|-----------|
| `TRUSTED_IPS` | — | IPs separados por virgula que nao disparam alerta `unauthorized_login` (seus IPs admin/casa) |
| `TRUSTED_FINGERPRINTS` | — | Fingerprints SSH separados por virgula (`SHA256:xxx`) que nao disparam alerta `unauthorized_login` |
| `DASHBOARD_TOKEN` | — | Token secreto para acessar `/dashboard` (auto-gerado pelo instalador) |
| `TELEGRAM_WEBHOOK_SECRET` | — | Header secreto para validacao do webhook Telegram (rejeita em producao se ausente) |

## Instalador Interativo

O instalador (`install.sh`) guia voce pelo setup completo em 7 passos. Tudo que ele pergunta:

| Passo | O que pergunta | Obrigatorio? | Notas |
|-------|---------------|--------------|-------|
| 1 | — | — | Detecta SO e gerenciador de pacotes automaticamente |
| 2 | — | — | Verifica pre-requisitos (Node.js 20+, npm, SSH client, Docker) |
| 3 | Diretorio de instalacao | Nao | Padrao: `~/.guardian` |
| 4 | — | — | Gera par de chaves SSH ed25519; mostra chave publica para adicionar nos servidores |
| 5 | **Token do Bot Telegram** | Sim | De [@BotFather](https://t.me/BotFather) |
| 5 | **Chat ID do Telegram** | Sim | De [@userinfobot](https://t.me/userinfobot) |
| 5 | Escolha do provedor IA (1-5) | Nao | 1=Gemini, 2=OpenAI, 3=Claude, 4=Ollama, 5=Pular |
| 5 | Chave API do provedor IA | So se 1-3 | Input secreto (nao exibido) |
| 5 | Escolha de banco de dados (1-2) | Nao | 1=SQLite (padrao), 2=PostgreSQL |
| 5 | URL do PostgreSQL | So se 2 | String de conexao |
| 5 | Chave API AbuseIPDB | Nao | Para threat intelligence (Enter para pular) |
| 5 | IPs confiaveis | Nao | IPs admin separados por virgula para evitar alertas falsos |
| 5 | Fingerprints SSH confiaveis | Nao | Valores `SHA256:xxx` separados por virgula (obter via `ssh-keygen -lf ~/.ssh/id_ed25519.pub`) |
| 6 | Modo de deploy (1-2) | Nao | 1=Docker Compose (se disponivel), 2=Node.js nativo + systemd |
| 7 | **Nome do servidor** | Sim | Nome amigavel (ex: `prod-web-1`) |
| 7 | **IP/hostname do servidor** | Sim | Endereco do servidor alvo |
| 7 | Porta SSH | Nao | Padrao: `22` |
| 7 | Usuario SSH | Nao | Padrao: `ubuntu` |

Apos o setup, o instalador:
- Cria `.env` com todos os valores configurados
- Testa conectividade SSH com o primeiro servidor
- Cria servico systemd (modo nativo) ou prepara Docker Compose
- Exibe a URL do dashboard com token auto-gerado

## Desenvolvimento

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
npm install
cp .env.example .env  # preencha seus valores

npm run dev           # servidor com hot-reload
npm run build         # TypeScript → dist/
npm run type-check    # tsc --noEmit
npm run test          # vitest (53 testes)
npm run lint          # ESLint
```

### Estrutura do Projeto

```
src/
├── collectors/           # Coleta de dados via SSH (agentless)
│   ├── ssh-collector.ts      # Camada base de execucao SSH
│   ├── log-collector.ts      # auth.log, ufw, docker events
│   ├── health-collector.ts   # CPU, memoria, disco, uptime
│   ├── system-collector.ts   # erros kernel, journal, unidades falhadas
│   ├── performance-collector.ts  # disk I/O, network throughput
│   ├── process-collector.ts  # deteccao de processos suspeitos
│   ├── network-collector.ts  # deteccao de flood de conexoes
│   ├── fim-collector.ts      # integridade de arquivos (baselines SHA256)
│   ├── sudo-collector.ts     # auditoria de comandos sudo
│   ├── cron-collector.ts     # enumeracao de cron jobs
│   ├── ssh-keys-collector.ts # auditoria de authorized_keys
│   └── dns-collector.ts      # monitoramento de queries DNS
├── pipeline/             # Processamento de eventos
│   ├── normalizer.ts         # Logs brutos → eventos estruturados
│   ├── detector.ts           # Deteccao baseada em regras
│   ├── enricher.ts           # Enriquecimento com threat intel
│   ├── correlator.ts         # Evento → Incidente
│   ├── ingestor.ts           # Persistencia de eventos (seguranca)
│   ├── metrics-ingestor.ts   # Persistencia de metricas (Bronze)
│   └── score-calculator.ts   # Scoring 6 dimensoes (Gold)
├── intelligence/         # IA + analise estatistica
│   ├── anomaly-detector.ts   # Aprendizado de baseline + alertas de desvio
│   ├── trend-predictor.ts    # Predicoes por regressao linear
│   ├── root-cause.ts         # Analise de causa raiz com IA
│   └── recommendations.ts   # Recomendacoes de otimizacao
├── services/             # Logica de negocio
│   ├── ai-provider.ts        # Multi-provider IA (Gemini/OpenAI/Claude/Ollama)
│   ├── ai.service.ts         # Servico IA legado
│   ├── server.service.ts     # CRUD de servidores
│   └── soc-analyst.service.ts # Consultas em linguagem natural
├── workers/              # Jobs em background
│   ├── event-collector.worker.ts     # Eventos de seguranca (2min)
│   ├── fim.worker.ts                 # Baselines arquivo/cron/keys (4h)
│   ├── score-calculator.worker.ts    # Metricas (5min) + Scores (1h)
│   ├── intelligence.worker.ts        # Anomalias + Tendencias (1h)
│   ├── metrics-retention.worker.ts   # Limpeza >30d (diario)
│   ├── daily-report.worker.ts        # Relatorio matinal (08:00 BRT)
│   ├── block-cleanup.worker.ts       # Blocks IP expirados
│   ├── cve-monitor.worker.ts         # Scan de CVEs
│   └── vuln-scanner.worker.ts        # Scan de vulnerabilidades em pacotes
├── playbooks/            # Playbooks de resposta automatizada
├── plugins/              # Sistema de plugins de notificacao
├── telegram/             # Comandos + callbacks do bot Telegram
├── dashboard/            # Dashboard web HTMX
├── database/             # Schema Drizzle ORM + conexao
├── config/               # Ambiente + constantes
└── index.ts              # Servidor Express + orquestracao de workers
```

## Docker Compose

```yaml
services:
  guardian:
    image: ghcr.io/afborda/guardian-blue-team:latest
    env_file: .env
    ports:
      - "3334:3334"
    volumes:
      - guardian_data:/data
      - ~/.ssh:/home/node/.ssh:ro
    restart: unless-stopped

  # Opcional: PostgreSQL para producao multi-servidor
  guardian-db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: ${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - pg_data:/var/lib/postgresql/data

volumes:
  guardian_data:
  pg_data:
```

## Contribuindo

Contribuicoes sao bem-vindas! Abra uma issue primeiro para discutir o que voce gostaria de mudar.

1. Fork o repositorio
2. Crie sua branch de feature (`git checkout -b feature/feature-incrivel`)
3. Commit suas mudancas (`git commit -m 'feat: adiciona feature incrivel'`)
4. Push para a branch (`git push origin feature/feature-incrivel`)
5. Abra um Pull Request

## Licenca

AGPL-3.0 — veja [LICENSE](LICENSE).
