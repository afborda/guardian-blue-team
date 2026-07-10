# OS quirks

Última atualização: 2026-05-29

## Matriz de suporte

| OS | Nível | Notas |
|----|-------|-------|
| Ubuntu 22.04+ | Primário | Testado em prod (Hetzner) |
| Ubuntu 24.04 | Primário | Idem |
| Debian 12+ | Primário | Igual Ubuntu na prática |
| RHEL 9 / Rocky 9 / AlmaLinux 9 | Best-effort | Diferenças abaixo |
| Fedora 39+ | Best-effort | Idem RHEL |
| Alpine | Não suportado | musl + onnxruntime quebra (commit 03b75b2) |
| OpenBSD/FreeBSD | Não suportado | Sem planos |

## Diferenças que importam

### Auth log

| OS | Caminho | Acesso |
|----|---------|--------|
| Ubuntu/Debian | `/var/log/auth.log` | Legível por `adm` group |
| RHEL/Fedora | `/var/log/secure` | Owner root, mode 600 |
| systemd-only | journalctl `-u sshd` | Requer `systemd-journal` group OR sudo |

**Implicação:** O `guardian-shell` precisa permitir os 3 padrões (entradas #1-3 da allowlist). Bootstrap detecta OS family e adiciona usuário ao grupo certo:

```bash
# Ubuntu/Debian
usermod -aG adm guardian

# RHEL/Fedora
usermod -aG systemd-journal guardian
# E precisa de sudoers extra pra ler /var/log/secure se ainda existir
```

### Init system

Todos os primários usam systemd. RHEL antigo (7) tinha SysVinit — não suportamos.

### Firewall

| OS | Default | Backend |
|----|---------|---------|
| Ubuntu | `ufw` (não habilitado por padrão) | iptables |
| Debian | `nftables` ou nada | nftables |
| RHEL/Fedora | `firewalld` | nftables |

**Implicação:** A função `enforceBlocks()` (em `block-ip.ts`) tenta UFW primeiro, fail2ban depois. Em RHEL precisa rota alternativa via `firewall-cmd`. **Ainda não implementado** — é dívida técnica documentada em `audits.md` do guardian-architect.

### Pacote SSH

Todos vêm com OpenSSH server. Versão importa:
- `restrict` em `authorized_keys`: precisa OpenSSH 7.2+ (Ubuntu 16.04+)
- Ed25519 keys: OpenSSH 6.5+ (universal nos primários)

### Python pra guardian-shell

Todos os primários têm Python 3.x:
- Ubuntu 22.04: 3.10
- Ubuntu 24.04: 3.12
- Debian 12: 3.11
- RHEL 9: 3.9 (mínimo aceitável)
- Fedora 39+: 3.12+

`guardian-shell` deve usar **só stdlib** — sem dependências externas. Compat com 3.9+ pra cobrir RHEL.

### chattr (logs append-only)

- Ubuntu/Debian: ext4 default, suporta `chattr +a`
- RHEL/Fedora: xfs default, **xfs também suporta `chattr +a`** (verificado kernel 5.x+)
- ZFS/btrfs: tem mecanismos próprios (zfs snapshot / btrfs ro), wrapper OS-agnóstico abstrai

### sudo version

- Ubuntu 22.04+: sudo 1.9+
- RHEL 9: sudo 1.9+
- Sintaxe `NOPASSWD:` é universal

### `ss` vs `netstat`

- Sistemas modernos: `ss` é o padrão (`iproute2`)
- Sistemas legados: só `netstat` (`net-tools`)

A allowlist tem ambos (#15 e #16) pra cobrir.

## Detecção de OS no bootstrap

```bash
. /etc/os-release
case "$ID" in
  ubuntu|debian) os_family=debian ;;
  rhel|centos|rocky|almalinux) os_family=rhel ;;
  fedora) os_family=fedora ;;
  alpine) echo "Unsupported"; exit 1 ;;
  *) echo "Unknown OS: $ID — proceeding best-effort"; os_family=unknown ;;
esac
```

Esse `os_family` vai pra coluna `soc_servers.os_family` e influencia path padrão de log no SSHCollector.

## Quando este arquivo deve mudar

- Testou novo OS e deu certo → promove pra Best-effort ou Primário
- Encontrou quirk novo → adiciona linha
- OS deprecou caminho/comando → atualiza tabela
