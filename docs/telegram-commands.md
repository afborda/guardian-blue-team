# Comandos Telegram

Guardian oferece **30+ comandos** para monitoramento, acoes e consultas diretamente pelo Telegram.

---

## Monitoramento

| Comando | Descricao | Exemplo |
|---------|-----------|---------|
| `/status` | Resumo de todos os servidores (load, mem, disk) | `/status` |
| `/health` | Fleet health com scores e metricas | `/health` |
| `/scores` | Grid de 6 dimensoes para todos os servidores | `/scores` |
| `/scores <server>` | Scores detalhados de um servidor | `/scores hetzner-prod` |
| `/servers` | Lista servidores + check de conectividade | `/servers` |
| `/containers` | Containers Docker rodando | `/containers` |

---

## Seguranca

| Comando | Descricao | Exemplo |
|---------|-----------|---------|
| `/events` | Ultimos eventos de seguranca (filtravel) | `/events` |
| `/incidents` | Incidentes abertos | `/incidents` |
| `/threat <ip>` | Reputacao do IP + historico local | `/threat 5.6.7.8` |
| `/hunt <ip\|user>` | Buscar logs por IOC | `/hunt root` |
| `/files [server]` | Mudancas de integridade de arquivos | `/files hetzner-prod` |
| `/sudo [hours]` | Atividade sudo (default 24h) | `/sudo 48` |
| `/crons [server]` | Cron jobs / mudancas recentes | `/crons` |
| `/keys [server]` | Chaves SSH / mudancas recentes | `/keys` |
| `/dns [server] [hours]` | Queries DNS / anomalias | `/dns hetzner-prod 12` |
| `/vulns` | Resumo de vulnerabilidades | `/vulns` |
| `/scan <server>` | Disparar scan de vulnerabilidades | `/scan hetzner-prod` |

---

## Acoes Diretas

| Comando | Descricao | Exemplo |
|---------|-----------|---------|
| `/block <ip> [server] [hours]` | Bloquear IP via UFW (default: 24h) | `/block 5.6.7.8 hetzner-prod 72` |
| `/unblock <ip> [server]` | Desbloquear IP | `/unblock 5.6.7.8` |
| `/firewall [server]` | Status do UFW (regras ativas) | `/firewall hetzner-prod` |
| `/services [server]` | Listar servicos/containers rodando | `/services` |
| `/playbook list` | Playbooks disponiveis | `/playbook list` |
| `/playbook run <name> <server> [ip]` | Executar playbook manualmente | `/playbook run block_ip hetzner-prod 5.6.7.8` |

---

## AI e Inteligencia

| Comando | Descricao | Exemplo |
|---------|-----------|---------|
| `/ask <pergunta>` | Pergunta em linguagem natural (AI) | `/ask por que o disco encheu?` |
| `/ai` | Status do provider AI (qual esta ativo, latencia) | `/ai` |
| `/learn <incident_id> <resolucao>` | Ensinar Guardian sobre um incidente resolvido | `/learn 42 "IP era scanner, block permanente"` |
| `/memory` | Estatisticas da memoria de incidentes (RAG) | `/memory` |

---

## Gestao

| Comando | Descricao | Exemplo |
|---------|-----------|---------|
| `/add-server <name> <host> [port] [user] [key]` | Registrar servidor | `/add-server prod 1.2.3.4 22 root` |
| `/rm-server <name>` | Remover servidor | `/rm-server old-server` |
| `/report` | Disparar relatorio diario | `/report` |
| `/report full` | Relatorio historico completo | `/report full` |
| `/apis` | Health check de APIs externas | `/apis` |
| `/help` | Lista completa de comandos | `/help` |

---

## Callbacks (botoes inline)

Alguns alertas vem com botoes de acao:

| Botao | Acao |
|-------|------|
| **Bloquear IP** | Bloqueia o IP do alerta via UFW |
| **Aprovar Playbook** | Executa playbook que requer aprovacao |
| **Ignorar CVE** | Marca CVE como ignorado |
| **Atualizar Pacote** | Aplica fix de CVE no servidor |

---

## Seguranca dos Comandos

- Todos os comandos so funcionam no chat configurado em `TELEGRAM_CHAT_ID`
- Webhook validado via `X-Telegram-Bot-Api-Secret-Token` (se `TELEGRAM_WEBHOOK_SECRET` configurado)
- Acoes destrutivas (`/block`, `/playbook run`) geram log com timestamp e executor
- Em producao, comandos de chat_id diferente sao rejeitados silenciosamente
