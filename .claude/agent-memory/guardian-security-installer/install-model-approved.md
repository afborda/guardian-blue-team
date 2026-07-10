# Modelo aprovado: guardian-shell

Última atualização: 2026-05-29
Status: aprovado pelo usuário, **não implementado**

## Visão de 30 segundos

Em vez de Guardian conectar como root e rodar qualquer comando, ele conecta como usuário `guardian` que **só consegue executar um único binário** (`/usr/local/sbin/guardian-shell`). O binário valida o comando contra uma allowlist de regex, executa via `sudo` se permitido, recusa caso contrário. Resultado: chave vazada = atacante consegue rodar **só** os comandos da allowlist.

## Componentes

### 1. Usuário `guardian`
```bash
useradd -r -s /bin/bash -d /home/guardian -m guardian
mkdir -p /home/guardian/.ssh
chmod 700 /home/guardian/.ssh
```

### 2. `/usr/local/sbin/guardian-shell` (Python)
Binário Python que:
- Lê `$SSH_ORIGINAL_COMMAND`
- Valida contra allowlist regex (ver `allowlist.md`)
- Executa via `subprocess.run(..., timeout=N)` com timeout específico do comando
- Loga em `/var/log/guardian-shell.log` (chattr +a — append-only)
- Retorna stdout/stderr/exit code transparentemente

### 3. Sudoers (1 linha em `/etc/sudoers.d/guardian`)
```
guardian ALL=(root) NOPASSWD: /usr/local/sbin/guardian-shell
```
Mais nada. Sem ALL, sem comandos individuais, sem brechas.

### 4. `~guardian/.ssh/authorized_keys`
```
restrict,command="/usr/local/sbin/guardian-shell" ssh-ed25519 AAAA... guardian@central
```
- `restrict` desliga port-forward, X11, agent-forwarding, PTY
- `command="..."` força execução sempre desse binário, ignora o que o cliente pede

### 5. Logs append-only
```bash
touch /var/log/guardian-shell.log
chattr +a /var/log/guardian-shell.log
```
Atacante root **não** consegue editar nem deletar — só pode parar de escrever (e aí heartbeat detecta silêncio).

### 6. Heartbeat
Worker no Guardian central que verifica `last_seen` de cada servidor. Se > 5min sem evento, notifica Telegram — out-of-band, não passa pelo servidor comprometido.

## Bootstrap (instalação na máquina nova)

Operador roda no servidor novo:
```bash
curl -fsSL https://guardian.exemplo.com/install/abc123token | sudo bash
```

O endpoint serve script que:
1. Cria usuário `guardian`
2. Faz download do `guardian-shell` + verifica SHA256
3. Instala em `/usr/local/sbin/` com `chmod 750 root:guardian`
4. Cria sudoers de 1 linha
5. Recebe chave pública do Guardian central via API
6. Configura `authorized_keys` com `command=`
7. Cria log append-only
8. Imprime fingerprint do host (operador cola no dashboard)
9. Marca token como usado (one-shot, TTL 15min)

## Schema novo

```sql
-- Nova tabela
CREATE TABLE install_tokens (
  token VARCHAR(64) PRIMARY KEY,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  used_by_ip VARCHAR(45),
  os_hint VARCHAR(50),  -- ubuntu/debian/rhel/fedora
  created_by VARCHAR(100)  -- operador que criou
);

-- Colunas em soc_servers
ALTER TABLE soc_servers ADD COLUMN host_fingerprint VARCHAR(200);
ALTER TABLE soc_servers ADD COLUMN install_method VARCHAR(20) DEFAULT 'legacy';
ALTER TABLE soc_servers ADD COLUMN os_family VARCHAR(20);
ALTER TABLE soc_servers ADD COLUMN last_heartbeat_at TIMESTAMP;
```

`install_method` valores: `'legacy'` (root + accept-new) ou `'guardian-shell'` (novo modelo).

## SSHCollector ajustado

```typescript
// Para servidores install_method='guardian-shell':
const args = [
  'guardian@host',
  '-p', String(server.port),
  '-o', 'StrictHostKeyChecking=yes',
  '-o', `UserKnownHostsFile=${serverFingerprintFile}`,  // só esse fingerprint
  '-o', 'PreferredAuthentications=publickey',
  '-i', '/etc/guardian/keys/id_ed25519',
  cmd,
];

// Para servidores install_method='legacy':
// mantém comportamento atual com accept-new (transição)
```

## Compat legacy

Servidores antigos continuam funcionando até serem migrados. Migração manual por enquanto:
1. Operador roda bootstrap no servidor antigo
2. Atualiza linha em `soc_servers` pra `install_method='guardian-shell'` + fingerprint
3. Remove `authorized_keys` antigo do `~root/.ssh/`

## O que NÃO está incluído (v2)

- Rsyslog TLS push em tempo real (heartbeat sozinho cobre 80% do caso)
- Append-only triggers no PostgreSQL pra incident_memory
- Migração automática de servidores legacy
- Rotação automática de chave SSH

## Quando este arquivo deve mudar

- Quando começar a implementar: marque "Status: em implementação" + data
- Quando deployar primeiro servidor real: anote o servidor e data
- Quando descobrir problema com OS específico: registre em `os-quirks.md`
