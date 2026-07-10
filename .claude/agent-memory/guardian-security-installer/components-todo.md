---
name: components-todo
description: Lista de arquivos novos a criar e arquivos existentes a modificar para o modelo guardian-shell
type: project
---

# Componentes a criar/modificar — modelo guardian-shell

Status: 🟡 aguardando autorização do usuário (2026-05-29)

## Schema (DDL-in-code, `src/database/connection.ts`)

### Tabela nova: `install_tokens`
```sql
CREATE TABLE IF NOT EXISTS install_tokens (
  token_hash VARCHAR(64) PRIMARY KEY,         -- bcrypt hash do token raw
  server_name VARCHAR(255) NOT NULL,
  os_family VARCHAR(16) NOT NULL DEFAULT 'unknown',
  created_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,              -- created_at + 15min
  consumed_at TIMESTAMP,                      -- single-use marker
  consumed_by_ip VARCHAR(45),                 -- audit
  fingerprint VARCHAR(255)                    -- preenchido após install
);
CREATE INDEX IF NOT EXISTS idx_install_tokens_expires ON install_tokens(expires_at) WHERE consumed_at IS NULL;
```

### Colunas novas em `soc_servers`
```sql
ALTER TABLE soc_servers ADD COLUMN IF NOT EXISTS host_fingerprint VARCHAR(255);
ALTER TABLE soc_servers ADD COLUMN IF NOT EXISTS install_method VARCHAR(32) NOT NULL DEFAULT 'legacy';
ALTER TABLE soc_servers ADD COLUMN IF NOT EXISTS os_family VARCHAR(16) NOT NULL DEFAULT 'unknown';
ALTER TABLE soc_servers ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMP;
```

`install_method` pode ser: `legacy`, `guardian-shell`, `guardian-shell-v2` (futuro).

## Arquivos novos

### `src/discovery/install.ts`
- `generateInstallToken(serverName, osFamily): Promise<{token, expiresAt, url}>`
- `consumeInstallToken(token, fingerprint, ip): Promise<{ok, serverName}>`
- `revokeExpiredTokens(): Promise<number>` — chamado por worker

### `src/discovery/bootstrap-script.ts`
- `renderBootstrap(serverName, osFamily, baseUrl, sshPubkey): string`
- Retorna shell script bash que faz tudo (templates por OS family)
- Embute `guardian-shell` Python source inline (heredoc) — sem download separado

### `src/dashboard/routes/install.ts`
- `GET /install/:token` — retorna o bootstrap script (Content-Type: text/x-shellscript)
  - Valida token (TTL, não-consumido)
  - Marca como "downloaded" mas NÃO consome ainda (consumo = call `complete`)
- `POST /install/:token/complete` — webhook do bootstrap
  - Body: `{hostname, fingerprint, os_family}`
  - Marca token consumido + atualiza `soc_servers`

### `src/dashboard/pages/add-server.html` (template)
- Form: nome, label, OS family (select com auto-detect)
- Após submit: mostra comando `curl|bash` + box de fingerprint esperado
- Polling do status: aguarda até `consumed_at IS NOT NULL`

### `src/workers/heartbeat.worker.ts`
- Interval: 1min
- Para cada servidor com `install_method LIKE 'guardian-shell%'`:
  - Roda `guardian-shell --ping` via SSH
  - Atualiza `last_heartbeat_at` se sucesso
  - Se silêncio > 5min: gera incidente "server_silenced"
- `start()` / `stop()` standard

### `scripts/guardian-shell.py`
- Source canônico do wrapper Python
- Versionado no repo, embedded no bootstrap script
- Tem versão semver no header — operador pode upgrade in-place

## Arquivos existentes a modificar

### `src/collectors/ssh-collector.ts`
- Adicionar parâmetro opcional `installMethod` no `run(target, cmd, timeoutMs, installMethod?)`
- Quando `installMethod !== 'legacy'`:
  - `StrictHostKeyChecking=yes`
  - `UserKnownHostsFile=/data/known_hosts/${serverName}` (per-server)
  - Opção `-o BatchMode=yes`
- Manter compat com legacy (path atual sem mudanças)

### `src/services/server.service.ts`
- `toSSHTarget(server)` lê `server.installMethod` e ajusta opções

### `src/index.ts`
- Registrar `HeartbeatWorker` na startup sequence
- Adicionar route `install` ao Express

### `src/database/connection.ts`
- DDL idempotente das tabelas/colunas novas

### `src/dashboard/index.ts`
- Adicionar página `/dashboard/servers/add`

## Ordem de implementação sugerida

1. **Schema** (DDL) — base, sem efeito até Guardian usar
2. **bootstrap-script.ts** + **guardian-shell.py** — arte rendering, testável isolado
3. **install.ts** (token gen/consume) — testável com SQLite
4. **Routes /install/:token** — exposição HTTP
5. **add-server.html** — UI
6. **HeartbeatWorker** — observabilidade contínua
7. **SSHCollector ajustado** — switch entre legacy e guardian-shell
8. **End-to-end test** em servidor de teste
9. **Migrar 1 servidor real** (manualmente, sem automação)
10. **Documentar** processo

## Decisões já tomadas (gravadas em decisions.md ADR-009)

- Ubuntu 22.04+/Debian 12+ primário, RHEL/Fedora best-effort
- Rsyslog push real-time → v2
- Append-only PG triggers → v2
- Migração automática de servidores legacy → v2
- `GUARDIAN_BASE_URL` (HTTPS) usado para servir `/install/:token`

## Trade-offs aceitos

- Token roubado dentro de 15min ainda é exploitable (mitigado: requer rede até o servidor + saber qual servidor instalar). Aceitável.
- `chattr +a` em `/var/log/auth.log` falha em alguns FS — capture e logue, não bloqueie install.
- Atacante com root local ainda pode `chattr -a` e editar logs. Mitigação: heartbeat externo + Telegram out-of-band detecta silêncio.
- Wrapper Python adiciona dependência (`python3`). Já vem em todos os primários — Alpine precisa `apk add python3`.

## Quem chama quem

```
Operator → dashboard/add-server.html
              ↓
          POST → install.ts.generateInstallToken
              ↓ (token URL)
Operator → ssh server → curl|bash → bootstrap script
              ↓
          POST /install/:token/complete → install.ts.consumeInstallToken
              ↓
          soc_servers UPDATE install_method='guardian-shell', host_fingerprint=X
              ↓
          HeartbeatWorker começa a rodar para esse server
```
