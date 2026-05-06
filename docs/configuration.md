# Configuracao

Todas as variaveis de ambiente do Guardian, organizadas por categoria.

---

## Obrigatorias

Sem estas, Guardian nao funciona:

| Variavel | Descricao | Como obter |
|----------|-----------|-----------|
| `TELEGRAM_BOT_TOKEN` | Token de autenticacao do bot | [@BotFather](https://t.me/BotFather) → /newbot |
| `TELEGRAM_CHAT_ID` | ID do chat/grupo para alertas | [@userinfobot](https://t.me/userinfobot) |
| `GUARDIAN_BASE_URL` | URL publica do Guardian (webhook) | Seu dominio com HTTPS (ex: `https://guardian.exemplo.com`) |
| `DATABASE_URL` | String de conexao PostgreSQL | Inclusa no docker-compose: `postgres://guardian:senha@guardian-db:5432/guardian` |

---

## Core

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `PORT` | `3334` | Porta do servidor HTTP |
| `NODE_ENV` | `development` | Use `production` em servidores reais |
| `DASHBOARD_TOKEN` | — | Token para acessar o dashboard web (gere com `openssl rand -hex 24`) |
| `NOTIFIERS` | `telegram` | Canais de notificacao: `telegram,discord,slack,whatsapp,email,ntfy,webhook` |

---

## AI — Providers

Guardian usa **local-first**: Ollama sempre e tentado primeiro. Se indisponivel, tenta cloud na ordem configurada.

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `AI_PROVIDER` | `auto` | `ollama`, `gemini`, `openai`, `claude`, ou `auto` (local-first) |
| `OLLAMA_URL` | `http://ollama:11434` | Endpoint da API do Ollama |
| `OLLAMA_MODEL` | `qwen3:4b` | Modelo para analise (requer ~4GB VRAM/RAM) |
| `OLLAMA_CHAT_MODEL` | `qwen3:0.6b` | Modelo leve para chat/NL queries (~600MB) |
| `GEMINI_API_KEY` | — | Chave do Google AI Studio (tier gratuito disponivel) |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Modelo Gemini |
| `OPENAI_API_KEY` | — | Chave OpenAI |
| `OPENAI_MODEL` | `gpt-4o-mini` | Modelo OpenAI |
| `ANTHROPIC_API_KEY` | — | Chave Anthropic |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-6-20250514` | Modelo Claude |

**Ordem de fallback (modo `auto`):**
```
Ollama (120s timeout) → Gemini → OpenAI → Claude
```

---

## Threat Intelligence

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `ABUSEIPDB_API_KEY` | — | Enriquecimento de IPs (gratis: 1000 consultas/dia) |
| `VIRUSTOTAL_API_KEY` | — | Analise de IPs/hashes (gratis: 500/dia) |
| `ABUSE_CONFIDENCE_THRESHOLD` | `70` | Confianca minima (0-100) para propor acao automatica |

---

## CVE Monitor

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `CVE_MONITOR_ENABLED` | `true` | Habilitar/desabilitar scan de vulnerabilidades |
| `CVE_MONITOR_MIN_CVSS` | `7.0` | CVSS minimo para alertar (7.0 = High + Critical) |
| `CVE_MONITOR_INTERVAL_HOURS` | `6` | Frequencia do scan (em horas) |

---

## Canais de Notificacao (todos opcionais)

### Discord
| Variavel | Descricao |
|----------|-----------|
| `DISCORD_WEBHOOK_URL` | URL do webhook Discord |

### Slack
| Variavel | Descricao |
|----------|-----------|
| `SLACK_WEBHOOK_URL` | URL do webhook Slack |

### Email (Resend)
| Variavel | Descricao |
|----------|-----------|
| `RESEND_API_KEY` | API key do [Resend](https://resend.com/) |
| `RESEND_FROM_EMAIL` | Email remetente (ex: `guardian@seudominio.com`) |

### WhatsApp (Evolution API)
| Variavel | Descricao |
|----------|-----------|
| `WHATSAPP_API_URL` | URL da Evolution API (ex: `http://evolution:8080`) |
| `WHATSAPP_INSTANCE` | Nome da instancia |
| `WHATSAPP_NUMBER` | Numero destino (ex: `5511999999999`) |

### ntfy
| Variavel | Descricao |
|----------|-----------|
| `NTFY_SERVER` | URL do servidor ntfy (default: `https://ntfy.sh`) |
| `NTFY_TOPIC` | Topico para publicacao |

### Webhook customizado
| Variavel | Descricao |
|----------|-----------|
| `WEBHOOK_URL` | Endpoint para receber eventos |
| `WEBHOOK_SECRET` | Secret HMAC para assinatura dos payloads |

---

## SSH (defaults para servidor local)

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `HOST_SSH_HOST` | `127.0.0.1` | Host SSH padrao |
| `HOST_SSH_PORT` | `22` | Porta SSH padrao |
| `HOST_SSH_USER` | `ubuntu` | Usuario SSH padrao |
| `HOST_SSH_KEY_PATH` | `/home/node/.ssh/id_ed25519` | Caminho da chave privada dentro do container |

---

## Seguranca

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `TRUSTED_IPS` | — | IPs que nunca disparam alerta `unauthorized_login` (separados por virgula) |
| `TRUSTED_FINGERPRINTS` | — | Fingerprints SSH (`SHA256:xxx`) que bypass alertas de login |
| `TELEGRAM_WEBHOOK_SECRET` | — | Header secreto para validacao de webhook do Telegram |

---

## Docker Compose

| Variavel | Default | Descricao |
|----------|---------|-----------|
| `SSH_KEY_DIR` | `~/.ssh` | Diretorio de chaves SSH (montado read-only) |
| `GUARDIAN_DOMAIN` | `guardian.localhost` | Dominio para roteamento Traefik |
| `GUARDIAN_DB_PASSWORD` | `guardian_secret` | Senha do PostgreSQL |

---

## Monitoramento Externo

| Variavel | Descricao |
|----------|-----------|
| `UPTIME_KUMA_PUSH_URL` | URL de push para [Uptime Kuma](https://github.com/louislam/uptime-kuma) heartbeat |

---

## Configuracoes Recomendadas por Cenario

### Homelab (1 servidor, minimo)
```env
TELEGRAM_BOT_TOKEN=seu_token
TELEGRAM_CHAT_ID=seu_chat_id
GUARDIAN_BASE_URL=https://guardian.seudominio.com
DATABASE_URL=postgres://guardian:senha@guardian-db:5432/guardian
AI_PROVIDER=auto
# Ollama roda no compose, nao precisa de API key
```

### Startup (2-5 servidores)
```env
TELEGRAM_BOT_TOKEN=seu_token
TELEGRAM_CHAT_ID=seu_chat_id
GUARDIAN_BASE_URL=https://guardian.empresa.com
DATABASE_URL=postgres://guardian:senha_forte@guardian-db:5432/guardian
DASHBOARD_TOKEN=token_seguro_aqui
AI_PROVIDER=auto
GEMINI_API_KEY=sua_chave_gemini
ABUSEIPDB_API_KEY=sua_chave
TRUSTED_IPS=ip_do_escritorio,ip_vpn
NOTIFIERS=telegram,slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
CVE_MONITOR_ENABLED=true
```

### Producao (5+ servidores)
```env
TELEGRAM_BOT_TOKEN=seu_token
TELEGRAM_CHAT_ID=seu_chat_id
GUARDIAN_BASE_URL=https://guardian.empresa.com
DATABASE_URL=postgres://guardian:senha_muito_forte@db-externo:5432/guardian
DASHBOARD_TOKEN=token_criptografado
AI_PROVIDER=auto
GEMINI_API_KEY=chave
OPENAI_API_KEY=chave_backup
ABUSEIPDB_API_KEY=chave
VIRUSTOTAL_API_KEY=chave
TRUSTED_IPS=10.0.0.0/24
TRUSTED_FINGERPRINTS=SHA256:abc,SHA256:def
NOTIFIERS=telegram,slack,email,webhook
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
RESEND_API_KEY=chave
RESEND_FROM_EMAIL=guardian@empresa.com
WEBHOOK_URL=https://siem.empresa.com/ingest
WEBHOOK_SECRET=hmac_secret
TELEGRAM_WEBHOOK_SECRET=secret_forte
CVE_MONITOR_ENABLED=true
CVE_MONITOR_MIN_CVSS=5.0
NODE_ENV=production
```
