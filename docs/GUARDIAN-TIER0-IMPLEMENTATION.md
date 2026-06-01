# Guardian Tier 0 — Modelo de Instalação Seguro

> Plano para migrar todos os servidores monitorados do modelo legacy (sudo NOPASSWD: ALL + accept-new fingerprint) para o modelo seguro (guardian-shell wrapper + sudoers allowlist exata + fingerprint pinning).
>
> Filosofia: **upgrade invisível para o usuário** — Guardian Central detecta servidores em legacy, prepara payload, executa via SSH, valida cada passo, e só notifica em caso de erro.
>
> Decisões base (refinadas após PoC v1 em 2026-05-31):
> - **(1a) Migrar tudo de uma vez** — re-rodar /add-server em modo upgrade nos servidores existentes, sem flag de coexistência
> - **(2c) Opção 3 — Hash-allowlist + per-placeholder regex** — guardian-shell normaliza o comando recebido (substitui timestamps/IDs por placeholders `%ISO_DATETIME%`, `%LINES%`, `%MINUTES%`, `%CONTAINER_ID%`), calcula SHA256, e compara contra lista de hashes embedded no binário. Cada placeholder tem regex-validator próprio antes da execução.
> - **(3a) PoC focado antes de PR4** — validar Opção 3 com 3 collectors representativos (log/audit/container) em server-1 antes de implementar `ServerUpgradeService.upgrade()`.
>
> **PoC v1 (literal allowlist + metachar deny) descartado em 2026-05-31**: bloqueava 80% dos collectors reais por causa de timestamps variáveis e pipes legítimos. Artefatos arquivados em `src/security/*.archive`.

---

## 1. Cenário atual (inventário 2026-05-31)

### Servidores monitorados em prod

| ID | Nome | Host | Usuário | Estado sudoers | Estado guardian-shell |
|----|------|------|---------|----------------|----------------------|
| 1 | hetzner-prod | 172.26.0.1 | root | (caso especial — Guardian Central monitora a si mesmo via Docker network) | — |
| 5 | server-1 | OVH_IP_1 | ubuntu | sudo NOPASSWD: ALL | ❌ não instalado |
| 6 | server-2 | OVH_IP_2 | ubuntu | sudo NOPASSWD: ALL | ❌ não instalado |
| 7 | synthfin | 192.99.43.163 | ubuntu | (disabled — ignorar) | — |

**Acesso SSH local** já está em `~/.ssh/config` (aliases: `hetzner`, `server-1`, `server-2`, `synthfin`). Permite ao Guardian Central executar upgrade remoto sem intervenção manual no servidor.

### Modelo legacy hoje

- `ssh-collector.ts:26`: `StrictHostKeyChecking=accept-new` (aceita troca silenciosa de fingerprint)
- Sudoers: nenhum arquivo dedicado — usuário `ubuntu` herda `sudo NOPASSWD: ALL` do grupo padrão
- Comandos: collectors mandam strings de shell direto via SSH, com `sudo` quando precisa
- `/add-server` (commands.ts:625): cadastra servidor após teste de conectividade. Não instala nada no servidor.

---

## 2. Modelo Tier 0 — o que muda no servidor monitorado

Após o upgrade, cada servidor terá:

### 2.1 Usuário dedicado `guardian` (não mais `ubuntu`)

```bash
sudo useradd -m -s /usr/local/bin/guardian-shell guardian
sudo install -d -m 0700 -o guardian -g guardian /home/guardian/.ssh
```

- Login shell forçado para `guardian-shell` (não `bash`)
- ~/.ssh/authorized_keys com a chave pública do Guardian Central + opção `command=` redundante

### 2.2 Wrapper `guardian-shell` (`/usr/local/bin/guardian-shell`)

Script de ~40 linhas (bash) que:
1. Lê o comando solicitado (vem em `$SSH_ORIGINAL_COMMAND` quando ssh roda com `command="..."`)
2. Compara contra allowlist literal em `/etc/guardian/allowed-commands.txt`
3. Se está na lista → executa via `eval "$SSH_ORIGINAL_COMMAND"` ou `bash -c`
4. Se não está → recusa com exit code 126, escreve linha em `/var/log/guardian-shell.log`

### 2.3 Sudoers allowlist (`/etc/sudoers.d/guardian`)

Sudoers funciona como **defesa em profundidade**, não como mecanismo principal de validação. A linguagem do sudoers só suporta wildcards literais (`*`), não regex — então deixamos validação rica pro `guardian-shell` (seção 5.1) e usamos sudoers só pra evitar que um bug no wrapper escale pra root irrestrito.

```
# Guardian Tier 0 — defesa em profundidade
# Validação real acontece em /usr/local/bin/guardian-shell (hash + regex).
# Estas regras só existem pra impedir que guardian execute root arbitrário caso o wrapper falhe.

guardian ALL=(root) NOPASSWD: /usr/bin/journalctl *
guardian ALL=(root) NOPASSWD: /usr/bin/tail -[0-9]* /var/log/*.log
guardian ALL=(root) NOPASSWD: /usr/bin/cat /etc/passwd, /usr/bin/cat /etc/shadow, /usr/bin/cat /etc/sudoers, /usr/bin/cat /etc/ssh/sshd_config, /usr/bin/cat /etc/os-release, /usr/bin/cat /etc/hosts, /usr/bin/cat /etc/crontab
guardian ALL=(root) NOPASSWD: /usr/bin/sha256sum /etc/*
guardian ALL=(root) NOPASSWD: /usr/bin/docker events *
guardian ALL=(root) NOPASSWD: /usr/bin/docker ps *
guardian ALL=(root) NOPASSWD: /usr/bin/docker inspect *
guardian ALL=(root) NOPASSWD: /usr/bin/docker logs *

# Bloqueio explícito de shells e ferramentas de exfiltração — mesmo que algo da lista acima
# passe wildcards muito frouxos, nenhum deles pode chamar bash/sh/python/curl/wget/nc.
guardian ALL=(root) NOPASSWD: !/usr/bin/bash, !/usr/bin/sh, !/usr/bin/python*, !/usr/bin/perl, !/usr/bin/curl, !/usr/bin/wget, !/usr/bin/nc, !/usr/bin/ncat, !/usr/bin/socat
```

> Nota: O `*` em sudoers é shell-glob literal, não regex. Não tente escrever validação fina aqui — é exatamente o tipo de coisa que falha em produção (sudoers parser tem regras estranhas com escape de vírgulas, espaços, etc). O wrapper guardian-shell faz isso direito.

### 2.4 Chattr append-only no log do guardian-shell

```bash
sudo touch /var/log/guardian-shell.log
sudo chattr +a /var/log/guardian-shell.log  # só permite append, nem root pode editar/deletar sem chattr -a primeiro
```

Atacante que tenha root ainda precisa explicitamente remover o atributo antes de apagar tracks.

### 2.5 Heartbeat worker (lado do servidor)

Cron a cada 1 min escreve timestamp em `/var/run/guardian-heartbeat`. Guardian Central lê e detecta quando heartbeat para → alerta de tampering.

---

## 3. O que muda no Guardian Central

### 3.1 Schema (`src/database/guardian-schema.ts`) — **PR1 já mergeado**

PR1 adicionou os campos abaixo de forma puramente aditiva (todos NULLABLE, sem default). Servidores legacy continuam funcionando porque `installMode = NULL` é tratado como modo legacy pelo `ssh-collector.ts`. PR4 (`ServerUpgradeService`) é quem populará esses campos após upgrade.

```ts
// soc_servers — campos Tier 0 adicionados em PR1
export const socServers = pgTable('soc_servers', {
  // ...campos legacy preservados
  installMode: varchar('install_mode', { length: 20 }),         // null = legacy, 'guardian' = Tier 0
  sshFingerprint: varchar('ssh_fingerprint', { length: 128 }),  // SHA256:abc... pinado
  guardianShellVersion: varchar('guardian_shell_version', { length: 20 }),
  upgradedAt: timestamp('upgraded_at'),
  lastHeartbeatAt: timestamp('last_heartbeat_at'),
  osFamily: varchar('os_family', { length: 30 }),               // ubuntu/debian/rhel/fedora/almalinux
});

// collector_state — nova tabela em PR1 (cursor persistence)
export const collectorState = pgTable('collector_state', {
  serverId: integer('server_id').notNull(),
  collectorName: varchar('collector_name', { length: 50 }).notNull(),
  lastCursor: text('last_cursor'),                              // formato opaco por collector
  cursorMeta: jsonb('cursor_meta').$type<Record<string, unknown>>().default({}),
  lastRunAt: timestamp('last_run_at'),
  lastError: text('last_error'),
  consecutiveFailures: integer('consecutive_failures').default(0).notNull(),
}, (table) => ({
  pk: primaryKey({ columns: [table.serverId, table.collectorName] }),
}));
```

**Status pós-PR1**:
- ✅ DDL idempotente em `connection.ts` (PostgreSQL `ADD COLUMN IF NOT EXISTS` + SQLite `ensureColumn`)
- ✅ `ServerService.ServerInfo` reflete os 6 campos novos (todos `| null`)
- ✅ `ServerService.toSSHTarget()` propaga `installMode` + `sshFingerprint` para `SSHTarget`
- ✅ `DiscoveryWorker` persiste `os_family` da probe `/etc/os-release` (PR1 fechou esse loop)
- ⏳ `SSHCollector.buildArgs()` ainda **não** consome `installMode` — PR2 fará a seleção de transporte (legacy `ssh user@host 'cmd'` vs Tier 0 `ssh guardian@host 'cmd-via-shell-wrapper'`).

### 3.2 SSH config — fingerprint pinning (`ssh-collector.ts`)

```ts
private static buildArgs(target: SSHTarget): string[] {
  const args = [
    '-o', target.sshFingerprint
      ? 'StrictHostKeyChecking=yes'           // modo seguro: recusa fingerprint diferente
      : 'StrictHostKeyChecking=accept-new',   // primeira vez: aceita, depois pina
    '-o', `UserKnownHostsFile=${process.env.SSH_KNOWN_HOSTS || '/data/known_hosts'}`,
    '-o', 'ConnectTimeout=10',
    '-o', 'LogLevel=ERROR',
    '-o', 'BatchMode=yes',
    '-o', 'ControlMaster=auto',
    '-o', 'ControlPath=/tmp/guardian-ssh-%h-%p-%r',
    '-o', 'ControlPersist=180',
  ];
  // ...
}
```

### 3.3 Novo serviço: `ServerUpgradeService` (`src/services/server-upgrade.service.ts`)

Responsável por executar todo o fluxo de upgrade. Detalhe na seção 4.

---

## 4. Fluxo de upgrade invisível

### 4.1 Trigger automático (worker)

Novo worker `LegacyMigrationWorker` roda a cada 6h (ou 1× no startup do Guardian Central):

```
Para cada server em soc_servers WHERE install_mode = 'legacy' AND enabled = true:
  1. Verificar se já existe upgrade pendente (lock no DB)
  2. Notificar Telegram: "🔄 Iniciando upgrade Tier 0 em <name>..."
  3. Chamar ServerUpgradeService.upgrade(server)
  4. Em caso de erro: rollback automático + notificar
  5. Em caso de sucesso: notificar "✅ <name> migrado para Tier 0"
```

Idempotente: se rodar 2× em servidor já migrado, detecta e não faz nada.

### 4.2 Trigger manual (Telegram)

Comando novo: `/upgrade-server <id>` força execução do upgrade fora da janela do worker.

### 4.3 Etapas internas do `ServerUpgradeService.upgrade()`

```typescript
async upgrade(server: ServerInfo): Promise<UpgradeResult> {
  const target = ServerService.toSSHTarget(server);

  // ── ETAPA 1 — Pré-flight (read-only)
  // Verifica:
  // - SSH alcançável
  // - Usuário atual tem sudo NOPASSWD (precisa pra criar guardian user)
  // - OS detectado (cat /etc/os-release)
  // - Espaço em /usr/local/bin, /etc/sudoers.d, /var/log
  // - Não existe usuário 'guardian' já (idempotência)
  await preFlightChecks(target);

  // ── ETAPA 2 — Backup do estado atual
  // Salva em /tmp/guardian-pre-upgrade-<timestamp>/:
  // - /etc/sudoers.d/ (cópia inteira)
  // - sshd_config
  // - authorized_keys do usuário atual
  // Permite rollback automático se algo der errado.
  await backupCurrentState(target);

  // ── ETAPA 3 — Criar usuário guardian + chave SSH dedicada
  // Guardian Central gera novo par ed25519 SÓ para esse servidor.
  // Chave privada salva em /data/keys/guardian-<server.id>.key (700)
  // Chave pública instalada em /home/guardian/.ssh/authorized_keys com options:
  //   command="/usr/local/bin/guardian-shell",no-pty,no-X11-forwarding,no-agent-forwarding,no-port-forwarding
  await createGuardianUser(target);

  // ── ETAPA 4 — Instalar guardian-shell
  // Copia script via heredoc SSH:
  //   ssh server 'sudo tee /usr/local/bin/guardian-shell <<EOF ... EOF'
  // Permissão: 755, owner root.
  await installGuardianShell(target);

  // ── ETAPA 5 — Instalar sudoers allowlist
  // Heredoc + 'visudo -cf' (valida sintaxe antes de mover pra /etc/sudoers.d/)
  // Se visudo falha, NÃO substitui — mantém estado anterior.
  await installSudoers(target);

  // ── ETAPA 6 — Capturar fingerprint do servidor
  // ssh-keyscan -t ed25519 host > known_hosts/<server.id>.pub
  // Hash SHA256 salvo em soc_servers.sshFingerprint
  await pinFingerprint(target);

  // ── ETAPA 7 — Smoke test no novo modelo
  // Conecta SSH como 'guardian' (não mais 'ubuntu') usando nova chave + fingerprint pin.
  // Roda 5 comandos do allowlist + 1 fora dele.
  // Allowlist deve passar; fora dele deve recusar (exit 126).
  // Se algum teste falha → rollback automático (etapa 8 inverso).
  const smokeOk = await smokeTest(target);
  if (!smokeOk) {
    await rollback(target);
    throw new Error('Smoke test failed — rolled back');
  }

  // ── ETAPA 8 — Atualizar DB e ativar modo seguro
  await db.update(soc_servers).set({
    sshUser: 'guardian',                   // muda usuário
    sshKeyPath: `/data/keys/guardian-${server.id}.key`,
    installMode: 'secure',
    sshFingerprint: capturedFingerprint,
    guardianShellVersion: '1.0.0',
    upgradedAt: new Date(),
  }).where(eq(soc_servers.id, server.id));

  // ── ETAPA 9 — Aguardar 1 ciclo de coleta no novo modo (2 min)
  // Se collectors normais funcionarem, upgrade está confirmado.
  // Se falharem → rollback delayed (etapa 10).
  await waitFirstCollection(server.id);

  // ── ETAPA 10 — Limpeza
  // Após 24h em modo seguro estável (heartbeat OK + coletas OK):
  // - Remove usuário 'ubuntu' do servidor (opcional, configurável)
  // - Remove backup de /tmp/guardian-pre-upgrade-*
}
```

### 4.4 Rollback automático

Se qualquer etapa entre 3-7 falha:
1. SSH como `ubuntu` ainda funciona (não tocamos nada do modelo antigo até etapa 8)
2. Restaura `/etc/sudoers.d/` do backup
3. Remove `/usr/local/bin/guardian-shell` se foi criado
4. Remove usuário `guardian` se foi criado
5. Notifica Telegram com erro detalhado + saída de cada comando

### 4.5 Visualização de progresso (Telegram)

Mensagem editada em tempo real (não múltiplas mensagens novas):

```
🔄 Upgrade Tier 0 — server-1
✅ Pre-flight OK
✅ Backup salvo em /tmp/guardian-pre-upgrade-1717174800
✅ Usuário 'guardian' criado
⏳ Instalando guardian-shell...
```

---

## 5. Componentes técnicos detalhados

### 5.1 `guardian-shell` v2 (script bash) — Opção 3

```bash
#!/usr/bin/env bash
# /usr/local/bin/guardian-shell
# Tier 0 v2 — wrapper com hash-allowlist + per-placeholder regex.
#
# Modelo:
#  1. Recebe $SSH_ORIGINAL_COMMAND
#  2. Normaliza: substitui timestamps, contadores, IDs por placeholders fixos
#  3. SHA256 do template normalizado → compara contra hashes embedded (HASHES[])
#  4. Se hash bate, valida cada placeholder com regex específico
#  5. Se tudo OK → executa via `bash -c` com env limpo
#  6. Caso contrário → exit 126 + log

set -euo pipefail

LOGFILE=/var/log/guardian-shell.log
VERSION=2.0.0

CMD="${SSH_ORIGINAL_COMMAND:-}"
TS=$(date -Iseconds)
SRC_IP="${SSH_CLIENT%% *}"

log() {
  local status=$1
  local detail=${2:-}
  echo "${TS} v${VERSION} ${status} src=${SRC_IP} cmd=${CMD} ${detail}" >> "$LOGFILE"
}

# ── Allowlist embedded (gerada por scripts/generate-allowlist.ts a partir dos
# collectors em src/collectors/*.ts). NÃO editar à mão — regenera no CI.
declare -A HASHES=(
  ["ALLOWLIST_HASHES_PLACEHOLDER"]="will-be-replaced-at-build-time"
)

# ── Recusa shell interativo (CMD vazio = login bash, não permitido)
if [[ -z "$CMD" ]]; then
  log "DENIED_INTERACTIVE_SHELL"
  echo "guardian-shell: interactive shell forbidden" >&2
  exit 126
fi

# ── Normalização: extrai placeholders e substitui por tokens fixos
# Cada regex captura UM placeholder; tudo o que não bate fica literal.
normalize() {
  local input=$1
  # %ISO_DATETIME% — formato ISO8601 (journalctl --since "2025-01-15 10:00:00")
  input=$(echo "$input" | sed -E "s/[\"']?[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:?[0-9]{2}|Z)?[\"']?/%ISO_DATETIME%/g")
  # %MINUTES% — find -mmin -60 / journalctl --since "60 minutes ago"
  input=$(echo "$input" | sed -E "s/-mmin -[0-9]+/-mmin -%MINUTES%/g")
  input=$(echo "$input" | sed -E "s/\"[0-9]+ minutes ago\"/\"%MINUTES% minutes ago\"/g")
  # %LINES% — tail -100 / tail -n 200
  input=$(echo "$input" | sed -E "s/tail -n? ?[0-9]+/tail -n %LINES%/g")
  # %CONTAINER_ID% — docker logs/inspect com hex de 12-64 chars
  input=$(echo "$input" | sed -E "s/\b[0-9a-f]{12,64}\b/%CONTAINER_ID%/g")
  echo "$input"
}

TEMPLATE=$(normalize "$CMD")
TEMPLATE_HASH=$(echo -n "$TEMPLATE" | sha256sum | cut -d' ' -f1)

# ── Verifica hash contra allowlist
if [[ -z "${HASHES[$TEMPLATE_HASH]:-}" ]]; then
  log "DENIED_HASH_MISMATCH" "template=${TEMPLATE} hash=${TEMPLATE_HASH}"
  echo "guardian-shell: command not in allowlist" >&2
  exit 126
fi

# ── Per-placeholder validation: extrai valores reais e valida cada um
validate_placeholders() {
  local cmd=$1
  # %ISO_DATETIME%
  for v in $(echo "$cmd" | grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:?[0-9]{2}|Z)?" || true); do
    [[ "$v" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[T\ ][0-9]{2}:[0-9]{2}:[0-9]{2}([+-][0-9]{2}:?[0-9]{2}|Z)?$ ]] || return 1
  done
  # %MINUTES% — só dígitos, max 1440 (24h)
  for v in $(echo "$cmd" | grep -oE "(-mmin -|[\"'])[0-9]+( minutes ago)?" | grep -oE "[0-9]+" || true); do
    [[ "$v" =~ ^[0-9]+$ ]] && (( v <= 1440 )) || return 1
  done
  # %LINES% — só dígitos, max 10000
  for v in $(echo "$cmd" | grep -oE "tail -n? ?[0-9]+" | grep -oE "[0-9]+" || true); do
    [[ "$v" =~ ^[0-9]+$ ]] && (( v <= 10000 )) || return 1
  done
  # %CONTAINER_ID% — só hex
  for v in $(echo "$cmd" | grep -oE "\b[0-9a-f]{12,64}\b" || true); do
    [[ "$v" =~ ^[0-9a-f]{12,64}$ ]] || return 1
  done
  return 0
}

if ! validate_placeholders "$CMD"; then
  log "DENIED_PLACEHOLDER_INVALID" "template=${TEMPLATE}"
  echo "guardian-shell: placeholder validation failed" >&2
  exit 126
fi

# ── Tudo OK — executa com env limpo
log "ALLOWED" "template=${TEMPLATE}"
exec env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 bash -c "$CMD"
```

**Por que normalizar antes de hashear?** Porque os mesmos collectors rodam com timestamps e contadores diferentes a cada ciclo. Se hasheássemos o comando inteiro, cada execução geraria hash novo e nada bateria. A normalização leva o comando ao formato canônico ANTES do hash; a regex per-placeholder garante que o que foi extraído realmente é o tipo declarado (não injeção mascarada de placeholder válido).

**Por que env limpo no exec?** Para o comando rodar como se viesse de um shell limpo, sem herdar `LD_PRELOAD`, `BASH_ENV`, `IFS`, etc, que poderiam ser injetados via SSH (mesmo que `PermitUserEnvironment=no` em sshd_config já bloqueie o vetor mais óbvio).

### 5.2 `/etc/guardian/allowed-commands.txt` v2 — templates com placeholders

Arquivo plain-text com **templates normalizados** (não comandos literais). Cada linha é um template; o hash SHA256 de cada template é embedded em `HASHES[]` no `guardian-shell` durante o build (`scripts/generate-allowlist.ts`).

Exemplo (parcial — set inicial cobrindo log/audit/container collectors):

```
# === Log collector (LogCollector) ===
sudo journalctl -u ssh -u sshd --since "%ISO_DATETIME%"
sudo journalctl -u sudo --since "%ISO_DATETIME%"
sudo journalctl -u systemd-resolved --since "%ISO_DATETIME%"
sudo journalctl -k --since "%ISO_DATETIME%"
sudo tail -n %LINES% /var/log/auth.log
sudo tail -n %LINES% /var/log/ufw.log
sudo tail -n %LINES% /var/log/syslog
sudo tail -n %LINES% /var/log/dpkg.log

# === FIM (file integrity) ===
sudo sha256sum /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/hosts /etc/crontab /etc/ld.so.preload
find /etc -mmin -%MINUTES% -type f

# === System probes (sem sudo — RemoteProber) ===
cat /etc/os-release
last -F -n %LINES%
ps auxf
ss -tunap

# === Docker / container collectors ===
sudo docker events --since "%ISO_DATETIME%" --until "%ISO_DATETIME%"
sudo docker ps --format json
sudo docker inspect %CONTAINER_ID%
sudo docker logs --tail %LINES% %CONTAINER_ID%

# === Cron baseline ===
crontab -l
sudo cat /etc/crontab
```

> **Geração automática**: `scripts/generate-allowlist.ts` faz parse AST dos `src/collectors/*.ts`, extrai cada string passada para `SSHCollector.run()` ou `runMulti()`, normaliza (mesma rotina do bash), calcula hash, e gera dois arquivos:
> - `src/security/allowed-commands.txt` (human-readable, commitado, usado como referência)
> - `src/security/guardian-shell.sh` (com `HASHES=(...)` populado a partir dos templates)
>
> Roda no CI como check obrigatório: se collector adicionou comando novo e não regenerou, build falha.

### 5.3 Captura de fingerprint (TypeScript)

```typescript
// src/services/ssh-fingerprint.service.ts
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';

const execFileAsync = promisify(execFile);

export class SSHFingerprintService {
  static async capture(host: string, port: number): Promise<string> {
    const { stdout } = await execFileAsync('ssh-keyscan', [
      '-t', 'ed25519', '-p', String(port), host
    ], { timeout: 10_000 });

    // ssh-keyscan output: "<host> ssh-ed25519 <base64key>"
    const keyMatch = stdout.match(/ssh-ed25519 ([A-Za-z0-9+/=]+)/);
    if (!keyMatch) throw new Error('Could not capture ed25519 fingerprint');

    const keyBytes = Buffer.from(keyMatch[1], 'base64');
    const sha256 = createHash('sha256').update(keyBytes).digest('base64')
      .replace(/=+$/, '');  // formato igual ao do ssh -V

    return `SHA256:${sha256}`;
  }

  static async writeKnownHost(serverId: number, host: string, port: number): Promise<void> {
    const knownHostsDir = '/data/known_hosts';
    await fs.mkdir(knownHostsDir, { recursive: true });
    const { stdout } = await execFileAsync('ssh-keyscan', [
      '-t', 'ed25519', '-p', String(port), host
    ]);
    await fs.writeFile(`${knownHostsDir}/${serverId}.pub`, stdout, { mode: 0o600 });
  }
}
```

---

## 6. Migração dos servidores existentes — passo a passo

Como você confirmou que tem acesso SSH a todos os servidores via aliases (`hetzner`, `server-1`, `server-2`), o fluxo é:

### 6.1 Pré-trabalho (status atual)

```
✅ PR1  — Schema soc_servers + collector_state (DDL idempotente)
             + ServerService types + os_family persistido por DiscoveryWorker
✅ PR2  — guardian-shell.sh v2 (Opção 3) + scripts/generate-allowlist.ts +
             allowed-commands.txt v2 + sudoers template
✅ PR3  — PoC v2 em server-1: 26/26 testes passando; 3 collectors representativos
             (log-collector com sudo + ||, network-collector com pipes + awk,
              audit-collector com placeholder template)
✅ PR4a — gerador TS (generate-allowlist.ts) + normalize.ts + template-matcher.ts +
             seleção de transporte em SSHCollector por installMode +
             11 templates PR4+ incorporados ao allowlist +
             testes: ssh-collector-guardian (10/10), template-matcher (11/11),
             normalize smoke JS (6/6), paridade bash↔TS (38 skip — requerem Docker em CI)
✅ PR4b — SSHFingerprintService + ServerUpgradeService (sem ativação) + rollback
✅ PR5  — LegacyMigrationWorker (gated por LEGACY_MIGRATION_ENABLED=false) +
             comando /upgrade-server + Telegram progress
⏳ PR6  — Testes em VM Multipass: ciclo completo upgrade + rollback + idempotência
```

### 6.2 Migração real (uma janela de manutenção, 1h)

```
1. Desabilitar EventCollectorWorker temporariamente (env GUARDIAN_PAUSE_COLLECTION=true)
2. /upgrade-server 5  (server-1)        — 10 min
3. /upgrade-server 6  (server-2) — 10 min
4. (synthfin = disabled, ignora)
5. (hetzner = caso especial, decisão à parte)
6. Reabilitar EventCollectorWorker
7. Monitorar primeiros 30 min — se algum servidor parar de coletar, rollback manual
```

### 6.3 Caso especial: hetzner-prod (id=1)

Guardian Central monitora a si mesmo via `172.26.0.1` (Docker network gateway). É o próprio host. Tier 0 aqui é diferente:
- Não precisa fingerprint pinning (loopback Docker)
- guardian-shell continua sendo boa ideia (defesa contra container compromise)
- sudoers allowlist pode ser ainda mais restrita (sem `docker events` — Guardian Central já tem socket Docker direto)

**Decisão para depois.** Migrar primeiro os 2 OVH (que são caso normal), depois pensar no Hetzner.

---

## 7. Ordem de PRs (~8-10h total)

| PR | Conteúdo | Status | Tempo |
|----|----------|--------|-------|
| PR1  | Schema (install_mode, ssh_fingerprint, guardian_shell_version, last_heartbeat_at, os_family, collector_state) + ServerService types + os_family via Discovery | ✅ mergeado 2026-05-31 | 1h |
| PR2  | `guardian-shell.sh` v2 (Opção 3) + `scripts/generate-allowlist.ts` + `allowed-commands.txt` v2 + sudoers template | ✅ mergeado 2026-05-31 | 2h |
| PR3  | **PoC v2** em server-1 — 26/26 testes passando; 3 collectors representativos provam Opção 3 | ✅ mergeado 2026-05-31 | 1h |
| PR4a | `normalize.ts` + `template-matcher.ts` + `generate-allowlist.ts` + transporte condicional em `SSHCollector` + 11 templates PR4+ + `build:allowlist` no `package.json` | ✅ mergeado 2026-05-31 | 2h |
| PR4b | `SSHFingerprintService.capture/writeKnownHost` + `ServerUpgradeService.upgrade()` + rollback + smoke test | ✅ mergeado 2026-05-31 | 2.5h |
| PR5  | `LegacyMigrationWorker` + comando `/upgrade-server` + Telegram progress (mensagem editada in-place) | ✅ mergeado 2026-05-31 | 1h |
| PR6  | Testes em VM Multipass: idempotência, rollback em cada etapa, recuperação após SSH drop | ⏳ | 1.5h |
| **PR7** | **Migração real server-1 + server-2 (janela de manutenção)** | ⏳ | 30min |

---

## 8. O que pode dar errado e como mitigar

| Risco | Probabilidade | Mitigação |
|-------|--------------|-----------|
| Sudoers allowlist sintaticamente inválido bloqueia tudo | Média | `visudo -cf` valida ANTES de mover pra `/etc/sudoers.d/`; backup + rollback automático |
| Fingerprint capturado é diferente do real (MITM no momento da migração) | Baixa | Comparar com fingerprint que `ssh -v` mostra hoje quando você conecta manualmente — confirmação humana antes de pinar |
| guardian-shell tem bug e recusa comando válido | Média | Testes em VM antes de prod; smoke test obrigatório na etapa 7 do upgrade |
| Comando do collector tem variação que não está no allowlist | Média | `generate-allowlist.ts` extrai do AST dos collectors; check no CI falha build se houve drift. Smoke test em PR3 (PoC v2) revela qualquer template faltando antes de PR4. |
| Bug no normalizador faz hash divergir do esperado | Média | A mesma rotina de normalização roda em TS (build-time) e bash (runtime) — testes unitários comparam saídas dos dois. PoC v2 valida em servidor real. |
| Per-placeholder regex aceita injeção mascarada de placeholder válido | Baixa | Regex são ancoradas (`^...$`) + caps numéricos (MINUTES ≤ 1440, LINES ≤ 10000). Valor que passa regex mas é semanticamente errado vai parar em sudoers (defesa em profundidade). |
| Conexão SSH cai no meio da migração | Baixa | `ServerUpgradeService` é idempotente — re-rodar continua de onde parou |
| Heartbeat não dispara (cron não está em todo OS) | Média | Fallback: collector próprio testa `test -f /var/run/guardian-heartbeat` a cada ciclo |
| Servidor RHEL/Fedora tem path diferente (`/usr/sbin/sshd`, journalctl difere) | Média | OS detection persistido (do plano de logs) — allowlist por OS family |

---

## 9. Pontos de extensibilidade (próxima década)

Decisões que tomamos agora pra não pintar parede:

1. **Allowlist em arquivo, não hardcoded** — futuro: versioning + rollback de allowlist sem redeploy
2. **`installMode` como string, não bool** — futuro: `'tier0'`, `'tier1-mtls'`, etc.
3. **Fingerprint hash separado da chave** — futuro: rotacionar chave do servidor sem perder identidade
4. **`ServerUpgradeService` modular** — etapas 1-10 são funções isoladas. Futuro: upgrade granular (só sudoers, só fingerprint).
5. **Heartbeat em arquivo, não service systemd** — funciona em Alpine sem systemd

---

## 10. Decisão final sobre install do servidor novo

Após Tier 0 estar em prod, o fluxo de `/add-server` muda:

### Antes (legacy)
```
Usuário no Telegram: /add-server server-1 OVH_IP_1 49222 ubuntu /root/.ssh/id_ed25519
Guardian: testa SSH → cadastra → fim
```

### Depois (Tier 0)
```
Usuário no Telegram: /add-server server-1 OVH_IP_1 49222
Guardian: gera install_token (válido 10 min)
Guardian: responde com URL one-time:
  curl https://guardian.exemplo.com/install/abc123 | sudo bash
Usuário cola comando no servidor
  └─ Script roda como root, baixa guardian-shell, cria usuário guardian,
     instala sudoers, captura fingerprint, retorna ack pro Guardian
Guardian: detecta ack → cadastra servidor já em modo 'secure' → fim
```

Comando one-time mais simples para o usuário (1 paste) e mais seguro (token expira).

---

## 11. Próxima ação

**Estado atual (2026-05-31)**:
- ✅ PR1 mergeado — schema pronto, ServerService consumindo, DiscoveryWorker persistindo `os_family`
- ✅ PR2/PR3 mergeados — guardian-shell.sh v2 + PoC v2 em server-1 26/26 testes
- ✅ PR4a mergeado — normalize.ts + template-matcher.ts + SSHCollector guardian mode + 11 templates incorporados + build:allowlist
- ✅ PR4b mergeado — SSHFingerprintService + ServerUpgradeService (10 etapas + rollback) + 10 testes passando
- ✅ PR5 mergeado — LegacyMigrationWorker (gated LEGACY_MIGRATION_ENABLED=false) + /upgrade-server Telegram command
- ⏳ Próximo: PR6 — Testes em VM Multipass: ciclo completo upgrade + rollback + idempotência
**Decisões trancadas** que NÃO se mexe sem novo design review:
- Hashes embedded no binário `guardian-shell` (geração via `scripts/generate-allowlist.ts` no build)
- Set inicial de 4 placeholders: `%ISO_DATETIME%`, `%LINES%`, `%MINUTES%`, `%CONTAINER_ID%`
- `installMode = NULL` semântica = legacy (não usa default `'legacy'` no DDL — preserva idempotência)
- Sudoers como defesa em profundidade, validação real no wrapper

PR2 não muda comportamento de produção: o `guardian-shell.sh` será apenas commitado em `src/security/` para uso futuro de PR4. Nenhum servidor é afetado até `LegacyMigrationWorker` ser destravado em PR5.
