# Guia de Instalacao

Guia completo para instalar Guardian Blue Team do zero.

---

## Requisitos do Host (onde Guardian roda)

| Requisito | Minimo | Recomendado |
|-----------|--------|-------------|
| **OS** | Qualquer com Docker | Ubuntu 22.04+, Debian 12+ |
| **CPU** | 1 core | 2+ cores |
| **RAM** | 512MB (sem AI local) | 8GB+ (com Ollama) |
| **Disco** | 2GB | 10GB+ |
| **Docker** | 20.10+ | 24+ |
| **Docker Compose** | v2+ | v2.20+ |
| **Rede** | Outbound HTTPS | IP publico ou reverse proxy |

### Sobre Ollama (AI local)

Ollama roda o modelo de AI localmente. Consumo por modelo:

| Modelo | RAM | Disco | Qualidade |
|--------|-----|-------|-----------|
| `qwen3:0.6b` (chat) | ~600MB | ~400MB | Basico — respostas rapidas |
| `qwen3:4b` (analise) | ~4GB | ~2.5GB | Bom — recomendado |
| `qwen3:8b` (analise) | ~8GB | ~5GB | Excelente — se tiver RAM |
| `nomic-embed-text` (embeddings) | ~300MB | ~275MB | Para busca semantica futura |

**Se nao tiver RAM para Ollama**: configure `GEMINI_API_KEY` e use AI na nuvem (gratis).

---

## Requisitos dos Servidores Alvo (monitorados)

| Requisito | Detalhes |
|-----------|---------|
| **SSH** | Acesso por chave (senha nao suportada) |
| **Usuario** | Root, ou usuario com sudo NOPASSWD para: `ufw`, `docker`, `journalctl`, `systemctl` |
| **OS** | Linux (Ubuntu/Debian/Alpine testados) |
| **Portas** | SSH acessivel a partir do host Guardian |

### Permissoes necessarias no servidor alvo

O usuario SSH precisa executar sem senha:
```bash
# Se nao for root, adicione em /etc/sudoers.d/guardian:
guardian ALL=(ALL) NOPASSWD: /usr/sbin/ufw, /usr/bin/docker, /usr/bin/journalctl, /usr/bin/systemctl, /usr/sbin/ausearch
```

---

## Dados Necessarios Antes de Comecar

Tenha em maos antes de iniciar:

| Dado | Como obter | Obrigatorio? |
|------|-----------|:------------:|
| **Telegram Bot Token** | Abra [@BotFather](https://t.me/BotFather) no Telegram → `/newbot` → copie o token | Sim |
| **Telegram Chat ID** | Envie qualquer mensagem para [@userinfobot](https://t.me/userinfobot) → ele responde seu ID | Sim |
| **Dominio publico** | DNS A record apontando para seu servidor (ex: `guardian.seudominio.com`) | Sim |
| **Certificado SSL** | Let's Encrypt via Traefik (automatico) ou qualquer reverse proxy com HTTPS | Sim |
| **Chave SSH** | Sera gerada automaticamente, ou use existente em `~/.ssh/id_ed25519` | Auto |
| **Gemini API key** | [aistudio.google.com](https://aistudio.google.com/) → Create API Key (gratis) | Nao |
| **AbuseIPDB key** | [abuseipdb.com](https://www.abuseipdb.com/register) → API Keys (gratis: 1000/dia) | Nao |

---

## Instalacao Passo a Passo

### 1. Clone o repositorio

```bash
git clone https://github.com/afborda/guardian-blue-team.git
cd guardian-blue-team
```

### 2. Copie e edite o .env

```bash
cp .env.example .env
nano .env  # ou seu editor preferido
```

**Preencha APENAS estas 4 variaveis** (o resto tem defaults seguros):

```env
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
GUARDIAN_BASE_URL=https://guardian.seudominio.com
GUARDIAN_DB_PASSWORD=uma_senha_forte_aqui
```

### 3. Configure o reverse proxy

Guardian precisa ser acessivel via HTTPS para receber webhooks do Telegram.

**Se ja tem Traefik** (recomendado):
- O `docker-compose.yml` ja vem configurado com labels Traefik
- Edite `GUARDIAN_DOMAIN` no `.env` com seu dominio
- Certifique-se que a network `traefik-public` existe: `docker network create traefik-public`

**Se usa Nginx**:
```nginx
server {
    listen 443 ssl;
    server_name guardian.seudominio.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:3334;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4. Configure chaves SSH

```bash
# Se nao tem chave SSH:
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""

# Copie a chave publica para o servidor alvo:
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@seu-servidor-alvo
```

### 5. Suba os containers

```bash
docker compose up -d
```

**O que acontece** (aguarde ~2-3 minutos):
1. PostgreSQL inicia e cria banco `guardian`
2. Ollama inicia e fica saudavel
3. `ollama-pull` baixa modelos (qwen3:4b + nomic-embed-text) — **pode demorar 3-5 min na primeira vez**
4. Guardian inicia, roda migrations, registra webhook no Telegram
5. Workers comecam coleta automatica

### 6. Verifique

```bash
# Logs do Guardian:
docker compose logs -f guardian

# Deve mostrar:
# INFO: Telegram webhook registered
# INFO: Intelligence worker started (every 1h)
# INFO: Event collector started (every 2min)
```

**No Telegram**: envie `/help` ao bot. Se respondeu, tudo esta funcionando.

### 7. Adicione seu primeiro servidor

No Telegram:
```
/add-server meuserver 1.2.3.4 22 root
```

Aguarde 2-5 minutos para o primeiro ciclo de coleta. Depois:
```
/status     → metricas do servidor
/events     → eventos de seguranca
/scores     → score de saude
```

---

## Troubleshooting

### Bot nao responde no Telegram

1. Verifique se `GUARDIAN_BASE_URL` esta correto e acessivel externamente:
   ```bash
   curl -I https://guardian.seudominio.com/webhook/telegram
   # Deve retornar 200 ou 401
   ```

2. Verifique logs:
   ```bash
   docker compose logs guardian | grep -i "webhook\|telegram"
   ```

3. Confirme que o bot token esta correto:
   ```bash
   curl "https://api.telegram.org/bot<SEU_TOKEN>/getMe"
   ```

### SSH falha para servidor alvo

1. Teste manualmente de dentro do container:
   ```bash
   docker exec -it guardian ssh -i /home/node/.ssh/id_ed25519 root@1.2.3.4 "echo ok"
   ```

2. Verifique permissoes da chave:
   ```bash
   ls -la ~/.ssh/id_ed25519
   # Deve ser -rw------- (600)
   ```

3. Verifique se a chave publica esta no servidor alvo:
   ```bash
   ssh root@1.2.3.4 "cat ~/.ssh/authorized_keys"
   ```

### Ollama nao sobe / modelo nao baixa

1. Verifique RAM disponivel:
   ```bash
   free -h
   # Precisa de pelo menos 4GB livres para qwen3:4b
   ```

2. Verifique logs do Ollama:
   ```bash
   docker compose logs ollama
   docker compose logs ollama-pull
   ```

3. Se nao tiver RAM suficiente, use AI na nuvem:
   ```env
   AI_PROVIDER=gemini
   GEMINI_API_KEY=sua_chave
   ```
   E remova/comente o servico `ollama` do docker-compose.yml.

### Dashboard nao carrega

1. Verifique se `DASHBOARD_TOKEN` esta definido no `.env`
2. Acesse com token na URL: `https://dominio/dashboard?token=SEU_TOKEN`
3. Verifique se a porta 3334 esta exposta/roteada

---

## Upgrade

```bash
cd guardian-blue-team
git pull
docker compose build
docker compose up -d
```

Guardian roda migrations automaticamente ao iniciar — nao precisa rodar nada manual.

---

## Uninstall

```bash
# Para containers
docker compose down

# Remove volumes (APAGA TODOS OS DADOS):
docker compose down -v

# Remove o diretorio:
cd .. && rm -rf guardian-blue-team
```
