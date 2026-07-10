# Modelo de instalação atual (legacy)

Última atualização: 2026-05-29

## Como funciona hoje

Quando um servidor é adicionado via dashboard (`/dashboard/add-server`), o operador faz manualmente:

1. Gera chave SSH no Guardian: `ssh-keygen -t ed25519 -N ""` (sem passphrase)
2. Copia a pública pro servidor monitorado: `~/.ssh/authorized_keys` do `root`
3. Cadastra no Guardian com IP + porta + nome
4. Guardian conecta e roda comandos via SSH como root

## Por que isso é frágil

| Vetor | Risco atual |
|-------|-------------|
| Chave roubada do container Guardian | Root na frota inteira, instantâneo |
| MITM no primeiro `accept-new` | Atacante captura chave e impersona servidor |
| Servidor comprometido por outro caminho | Atacante já era root, nada muda |
| Atacante cria regra iptables filtrando saída pro Guardian | Servidor "silencia" sem alerta |

## Componentes

- **`SSHCollector`** (`src/collectors/ssh-collector.ts`): usa `child_process.spawn('ssh', [...])` com `StrictHostKeyChecking=accept-new`
- **`ServerService.toSSHTarget()`**: monta string `user@host -p porta`
- **Dashboard `add-server.html`**: form simples sem fingerprint
- **Schema `soc_servers`**: `id, name, ip, port, ssh_user, ssh_key_path, status, ...` — sem `host_fingerprint`, sem `install_method`

## Por que não migramos ainda

- Funciona "pra mim" no laboratório do usuário (1 prod + N teste)
- Custo de migração: precisa rodar bootstrap em cada servidor existente
- Compat: o novo modelo tem que conviver com legacy via flag

## Quando este arquivo deve mudar

Atualize aqui quando:
- Migrar um servidor de legacy → guardian-shell (anote IP + data)
- Encontrar uma falha de segurança nova no modelo legacy
- Decidir deprecar legacy completamente (data + plano)
