# Allowlist do guardian-shell

Última atualização: 2026-05-29
Status: desenhada, **não implementada**

## Princípio

Allowlist > blocklist. Se um comando não casa com NENHUM padrão abaixo, recusa. Cada padrão tem timeout máximo — comando que demora além disso é morto (defesa contra DoS via comando lento).

## Padrões aceitos

| # | Regex | Timeout | Por quê |
|---|-------|---------|---------|
| 1 | `^cat /var/log/auth\.log(\.\d+)?$` | 5s | Coleta de auth log Ubuntu/Debian |
| 2 | `^cat /var/log/secure(\.\d+)?$` | 5s | Coleta de auth log RHEL/Fedora |
| 3 | `^journalctl -u sshd --since '[0-9]+ minute(s)? ago' --no-pager$` | 10s | Fallback systemd |
| 4 | `^journalctl --since '[0-9]+ minute(s)? ago' --no-pager -n \d{1,5}$` | 15s | Logs gerais |
| 5 | `^ufw status numbered$` | 5s | Listar regras UFW |
| 6 | `^ufw deny from \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}( to any)?$` | 5s | Bloquear IP via UFW |
| 7 | `^ufw delete deny from \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}( to any)?$` | 5s | Remover bloqueio |
| 8 | `^iptables -L -n --line-numbers$` | 5s | Listar regras iptables |
| 9 | `^iptables -nvL GUARDIAN_RATELIMIT$` | 5s | Listar chain custom |
| 10 | `^fail2ban-client status$` | 5s | Status fail2ban |
| 11 | `^fail2ban-client status sshd$` | 5s | Status jail SSH |
| 12 | `^fail2ban-client set sshd banip \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$` | 5s | Banir via fail2ban |
| 13 | `^docker ps --format '\{\{json \.\}\}'$` | 10s | Listar containers |
| 14 | `^docker inspect [a-f0-9]{12,64}$` | 5s | Inspecionar container por ID |
| 15 | `^ss -tnp$` | 5s | Conexões TCP estabelecidas |
| 16 | `^netstat -tn \| awk 'NR>2 \{print \$5\}' \| cut -d: -f1 \| sort -u$` | 10s | IPs conectados (legado) |
| 17 | `^uptime$` | 2s | Heartbeat básico |
| 18 | `^uname -a$` | 2s | Detecção de OS |
| 19 | `^cat /etc/os-release$` | 2s | OS version |
| 20 | `^ps auxf --no-headers$` | 10s | Processos pra detecção |
| 21 | `^find /etc -type f -newer /var/lib/guardian/baseline\.ts -print0$` | 30s | FIM diff |
| 22 | `^sha256sum /etc/passwd /etc/shadow /etc/sudoers$` | 5s | Hashes pra FIM |

## O que está fora (recusado)

- `rm`, `mv`, `cp`, `chmod`, `chown` (mudança de filesystem)
- `bash -c`, `sh -c`, `eval`, `source` (escape do allowlist)
- `curl`, `wget`, `nc`, `netcat` (exfiltração / download)
- `apt`, `yum`, `dnf` (instalação de pacotes)
- `systemctl restart/stop/start` qualquer coisa exceto via wrapper específico
- `kill`, `pkill`, `killall` (dropar processo Guardian no servidor — seria DoS)
- Qualquer pipe (`|`), redirecionamento (`>`, `<`, `>>`), backtick, `$()`
  - **EXCETO** os pipes específicos da allowlist (#16) que casa exatamente

## Regras anti-bypass

1. Match com `^...$` (anchored), não substring match
2. Comparação **literal** dos espaços — sem normalização
3. Recusar se `$SSH_ORIGINAL_COMMAND` contém `\n`, `\r`, `\x00`
4. Recusar se length > 1024 chars
5. Log da tentativa de comando recusado em `/var/log/guardian-shell.log`

## Como expandir

Quando uma feature do Guardian precisar de comando novo:
1. **Não** liberar genérico — escreva regex tão restrito quanto possível
2. Pensa "que parametros um atacante poderia injetar nesse padrão pra escalar?"
3. Adiciona timeout coerente
4. Documenta aqui com a feature e justificativa
5. Implementa em `guardian-shell.py` + adiciona teste

## Quando este arquivo deve mudar

- Toda vez que adicionar um padrão: anote # + data + feature que motivou
- Quando remover um padrão (feature deprecada): anote em "Removidos"
- Se descobrir bypass: marca regra como vulnerável + plano de mitigação
