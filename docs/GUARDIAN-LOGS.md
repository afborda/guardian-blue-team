# Guardian — Logs Coletados, Lacunas e Padrões de IPs Maliciosos

> Documento gerado em 2026-05-31. Reflete o estado do código na versão v3.1.1.

---

## Sumário

1. [Logs que coletamos](#1-logs-que-coletamos)
2. [Logs que NÃO coletamos — lacunas](#2-logs-que-não-coletamos--lacunas)
3. [Padrões de IPs Maliciosos — o que detectamos](#3-padrões-de-ips-maliciosos--o-que-detectamos)
4. [Padrões de IPs Maliciosos — o que não detectamos](#4-padrões-de-ips-maliciosos--o-que-não-detectamos)
5. [Roadmap de Cobertura](#5-roadmap-de-cobertura)

---

## 1. Logs que Coletamos

### 1.1 Autenticação e Acesso

| Fonte | Arquivo/Comando | Eventos extraídos | Arquivos do collector |
|-------|----------------|------------------|----------------------|
| SSH login | `/var/log/auth.log` ou `journalctl -u ssh` | `ssh_failed_password`, `ssh_invalid_user`, `ssh_login_success`, `session_opened`, `ssh_breakin_attempt` | `src/collectors/log-collector.ts` |
| Sudo | `journalctl -u sudo` | `sudo_command` (usuário + TTY + comando completo) | `src/collectors/sudo-collector.ts` |
| PAM / sistema | `/var/log/auth.log` | Falhas de autenticação PAM, abertura de sessão | `src/collectors/audit-collector.ts` |
| Chaves SSH | `~/.ssh/authorized_keys` | `ssh_key_added`, `ssh_key_removed` (com fingerprint) | Integrado ao audit collector |
| Criação de usuários | `journalctl` + ausdit | `audit_user_change` (useradd, userdel, ADD_USER) | `src/collectors/audit-collector.ts` |

### 1.2 Rede e Firewall

| Fonte | Arquivo/Comando | Eventos extraídos |
|-------|----------------|------------------|
| UFW | `/var/log/ufw.log` | `firewall_block` (IP, porta, protocolo) — filtrado: exclui replies DNS/HTTP/NTP e IPs CGNAT |
| Conexões ativas | `netstat -tupn` / `ss` | `HIGH_CONN_COUNT`, `SYN_FLOOD` (>50 half-open), `BANDWIDTH_SPIKE`, `CONN_RATE_SPIKE` |
| DNS queries | `journalctl -u systemd-resolved` ou dnsmasq | `dns_query` (domínio + IP de origem) |
| Proxy (HTTP) | Logs HAProxy / nginx | `proxy_path_traversal`, `proxy_scanner_detected` |

### 1.3 Processos e Sistema

| Fonte | Arquivo/Comando | Eventos extraídos |
|-------|----------------|------------------|
| Processos | `ps aux` | `suspicious_process` (padrões: xmrig, minerd, netcat reverso, /tmp executáveis) |
| Syslog | `/var/log/syslog` | `syslog_oom_kill`, `syslog_service_crash`, `syslog_hardware_error` |
| Systemd | `systemctl --failed` + `journalctl` | `systemd_unit_failed` |
| Pacotes | `/var/log/dpkg.log` | `package_suspicious` (nmap, hydra, hashcat, metasploit...), `package_installed`, `package_removed` |
| Cron | `crontab -l` | `cron_added`, `cron_removed` |

### 1.4 Integridade de Arquivos

| Fonte | O que monitora | Eventos |
|-------|---------------|---------|
| FIM Worker (4h) | Hash SHA256 de: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/etc/hosts`, `/root/.ssh/authorized_keys`, `/etc/crontab`, `/etc/ld.so.preload` | `file_modified`, `file_created`, `file_deleted`, `file_permissions_changed` |

### 1.5 Containers (Docker)

| Fonte | Comando | Eventos |
|-------|---------|---------|
| Docker events | `docker events` | `docker_die`, `docker_kill`, `docker_start`, `docker_exec` |
| Processos em containers | `docker exec <c> ps` (2 min) | `container_process_list` |
| Rede de containers | `docker exec <c> netstat` (5 min) | `container_connection` (filtra portas de mining pools) |
| Filesystem de containers | Diff de layers (30 min) | `container_file_added` (executablem /tmp, /dev/shm) |
| Config de containers | `docker inspect <c>` (1h) | Inspeção: ReadOnly, CapDrop, no-new-privs, privileged |
| CVE em imagens | Trivy + OSV (6h) | `container_image_cve` com CVSS e pacote afetado |

### 1.6 Vulnerabilidades e Inteligência

| Fonte | Frequência | O que coleta |
|-------|-----------|-------------|
| NVD / OSV | Horária | CVEs novas nos pacotes instalados |
| CISA KEV | Diário (03:17 UTC) | Known Exploited Vulnerabilities |
| EPSS | Diário | Score de probabilidade de exploração |
| AbuseIPDB | Por evento de IP | Score de abuso (0–100) |
| VirusTotal | Por evento de IP crítico | Número de vendors marcando como malicioso |

---

## 2. Logs que NÃO Coletamos — Lacunas

### 2.1 Lacunas de Alta Prioridade (impacto de segurança imediato)

| Log / Fonte | Por que importa | Como implementar |
|-------------|-----------------|-----------------|
| **`/var/log/secure`** (RHEL/CentOS/Fedora) | Guardian assume `auth.log` (Debian/Ubuntu). Em RHEL/Fedora, SSH logs vão para `/var/log/secure`. Sem isso, brute force em RHEL passa invisível. | Detecção de OS no `add-server`, ramificação no log collector (planejado no Tier 3) |
| **`journalctl -u sshd`** (sistemas sem auth.log) | Ubuntu 22.04+ com `syslog` desabilitado só tem o journal. O collector já tem fallback, mas não é testado em prod. | Testar + adicionar `--no-pager -n 500` com controle de cursor |
| **`/var/log/wtmp` / `last -F`** | Histórico completo de logins (IP + duração + horário de logout). Detecta sessões abertas há dias — possível backdoor. | Coletar via `last -F -n 100` no auth collector |
| **`/proc/net/nf_conntrack`** | Tabela de conexões rastreadas pelo netfilter — visibilidade total de conexões ativas, incluindo UDP e ICMP. Detecta C2 com keep-alive longo. | Novo network collector, requer `net.netfilter.nf_conntrack_acct=1` no kernel |
| **Auditd (`/var/log/audit/audit.log`)** | Sistema de auditoria do kernel Linux: `execve` (todos processos), `openat` (todos arquivos abertos), `connect` (todas conexões). Base para detecção de evasão. Muito diferente de `journalctl`. | Exige `auditd` instalado + regras configuradas. Alto volume, precisa de filtro. |
| **`/var/log/nginx/error.log`** | Erros nginx revelam: tentativas de exploração de CVEs em apps web, 50x internos que podem indicar crash loop. Só coletamos o access log via proxy collector. | Adicionar coleta de error log ao proxy collector |
| **`sudo -l` por usuário** | Lista de permissões sudo de cada usuário — permite detectar escalação de privilégio nova (usuário ganhou `NOPASSWD ALL` sem que o Guardian visse o `visudo`). | Coleta periódica (1h) + diff contra baseline |
| **`/proc/net/tcp` + `/proc/net/tcp6`** | Lista de todas as conexões TCP no nível do kernel, sem depender de `netstat` (que pode ser substituído por versão trojanizada). | Leitura direta do `/proc` — mais difícil de evadir por rootkits de userspace |
| **Logs de aplicação de serviços críticos** | nginx access, MySQL slow query, PostgreSQL log. Ataques como SQLi, SSRF e RCE aparecem primeiro no log da aplicação, não no sistema. | Configurável por servidor — paths de log definidos pelo usuário no `add-server` |

### 2.2 Lacunas de Média Prioridade

| Log / Fonte | Por que importa |
|-------------|-----------------|
| **`/var/log/auth.log` para `su`** | Escalação de privilégio via `su` (não sudo) não é capturada pelas regras atuais. `su` não loga em `journalctl -u sudo`. |
| **`PAM tally2` / `faillock`** | Contador de falhas de login por usuário. Complementa o brute force SSH — detecta bruteforce em serviços PAM (FTP, SFTP). |
| **Registros de DNS reverso** | `PTR` records de IPs suspeitos poderiam enriquecer a análise de DGA sem chamada extra à API. |
| **`inotify` em tempo real** | FIM roda a cada 4h. Um atacante que modificar `/etc/passwd` e restaurar em 3h passa invisível. `inotifywait` detectaria em segundos. Requer agente instalado. |
| **Logs de containers específicos** | Stderr/stdout de containers (e.g., `docker logs nginx`). Ataques a aplicações aparecem aqui primeiro. |
| **`/var/log/faillog`** | Falhas de login local (terminal físico, não SSH). Relevante para servidores com acesso físico. |
| **Nginx/Apache `status` endpoint** | `nginx_status` e `mod_status` expõem conexões ativas, requests/sec. Complementaria a detecção de DDoS com dados da camada de aplicação. |
| **`iptables -L -n -v` contadores** | Contadores de hits por regra de firewall. Permitiria detectar regras adicionadas por rootkit (regra nova com contador crescendo). |
| **Logs de VPN (OpenVPN, WireGuard)** | Se o servidor tem VPN, logins via VPN não passam pelo SSH e ficam fora do Guardian. |
| **`/var/log/btmp`** | Log de tentativas de login com senha errada — binário, lido via `lastb`. Complementa auth.log quando este está sendo apagado. |

### 2.3 Lacunas de Baixa Prioridade (contexto adicional)

| Log / Fonte | Por que importa |
|-------------|-----------------|
| **`/proc/loadavg` + `/proc/meminfo`** | Já coletamos via `ScoreCalculatorWorker`, mas não correlacionamos com eventos de segurança em tempo real. |
| **`dmesg`** | Mensagens do kernel em tempo real: USB conectado, módulo de kernel carregado (rootkit), erro de hardware. |
| **`/var/log/boot.log`** | Reboots inesperados podem ser pós-exploração. Detectar reboot não programado. |
| **SNMP traps** | Para servidores com serviços de rede gerenciados (switches, roteadores): detecção de loop, link down, etc. |
| **S3/cloud storage access logs** | Se o servidor tem credenciais cloud, exfiltração pode acontecer por S3 sem passar pela rede monitorada. |

---

## 3. Padrões de IPs Maliciosos — o que detectamos

O Guardian identifica IPs perigosos através de múltiplas camadas:

### 3.1 Por comportamento direto (regras do Detector)

| Padrão | Como o Guardian detecta |
|--------|------------------------|
| **Brute force SSH** | 20+ falhas de mesma IP no buffer de 2000 eventos → `ssh_brute_force_burst` |
| **Port scanning** | 10+ portas distintas bloqueadas de mesma IP em 30 min → incidente Port Scan |
| **Lateral movement** | Login bem-sucedido de IP que tinha tentativas de brute force → `lateral_movement` (critical) |
| **DDoS SYN flood** | >50 conexões half-open → `syn_flood_detected` |
| **Connection flood** | Alto número de conexões simultâneas → `high_connection_flood` |
| **HTTP scanning** | 10+ requests de scanner de mesma IP → `proxy_scanner_burst` |
| **IP reincidente** | IP com block ativo tenta nova conexão → rebaixado para `info` (supressão) mas incrementa contador |

### 3.2 Por reputação externa (Threat Intelligence)

| Fonte | O que fornece | Limiar de ação |
|-------|--------------|----------------|
| AbuseIPDB | Score de abuso 0–100 com histórico de reports | Score >= 50: +1 severidade; >= 90: +2 severidade |
| VirusTotal | # vendors marcando como malicioso | Informativo (compõe feature do IP Classifier) |

### 3.3 Por modelo de ML (IP Classifier ONNX)

O modelo classifica IPs como perigosos baseado em 11 features históricas (ver seção 4.2 do GUARDIAN-ANALYSIS.md). Threshold: 0.6.

**Perfil de IP considerado perigoso pelo modelo:**
- Alta proporção de eventos high/critical (> 40%)
- Teve brute force OU lateral movement
- Afetou 2+ servidores distintos
- AbuseIPDB score alto
- Teve login bem-sucedido após tentativas (maior fator)

### 3.4 Por análise de IA (Threat Hunter)

A cada 4h, a IA analisa o conjunto de eventos e identifica:
- **IPs coordenados:** Vários IPs diferentes do mesmo /24 atacando o mesmo alvo em janela temporal
- **APT slow-roll:** IP com baixíssima taxa de tentativas (1-2/hora) por vários dias — evade threshold de brute force
- **Scanning distribuído:** Múltiplos IPs diferentes escaneando portas em sequência
- **Reuso de sessão C2:** Mesmo IP com padrões de DNS DGA + conexão de saída em porta incomum

---

## 4. Padrões de IPs Maliciosos — o que NÃO detectamos

### 4.1 Evasões de threshold

| Padrão | Problema | Solução possível |
|--------|----------|-----------------|
| **Low-and-slow brute force** | 1 tentativa SSH a cada 5+ min nunca atinge o threshold de 20 em buffer | Janela temporal longa (24h) com threshold menor (5 falhas/24h de mesma IP) |
| **Brute force distribuído (botnet)** | 1 tentativa por IP diferente — cada IP fica abaixo do threshold. IPs coordenados passam se vierem de /24 diferente | Detecção de /24 CIDR — agrupar IPs do mesmo bloco |
| **Port scan lento** | 1 porta bloqueada a cada 10 min — abaixo do threshold em 30 min | Janela maior (2h) com threshold menor |
| **Credential stuffing via proxy** | Cada tentativa de um IP diferente (proxy pool). Nunca acumula em mesmo IP | Detecção por usernames: muitos usuários inválidos distintos num período |

### 4.2 Técnicas que passam pelo Guardian

| Técnica | Por que passa | Mitigação possível |
|---------|--------------|-------------------|
| **IPv6 brute force** | Regras de threshold são por IPv4. IPv6 tem espaço imenso — cada tentativa de endereço diferente | Normalizar para /64 prefix IPv6 |
| **Tor exit nodes** | IPs do Tor mudam constantemente — nenhum IP acumula histórico suficiente para o ML | Blocklist de exit nodes do Tor (atualização diária) |
| **VPN/proxy residencial** | IPs "limpos" sem histórico de abuso no AbuseIPDB | Heurística de janelas longas por usernames |
| **ICMP/UDP scanning** | UFW loga, mas o correlator não agrupa ICMP/UDP de mesma IP como port scan (só TCP) | Incluir ICMP e UDP na correlação de port scan |
| **Exfiltração DNS** | DNS tunneling — dados codificados em subdomínio de domínio controlado pelo atacante. Diferente de DGA (domínio é constante, mas subdomínio varia muito) | Detecção por volume de queries ao mesmo domínio + comprimento médio dos subdomínios |
| **HTTPS C2** | Tráfego C2 sobre HTTPS porta 443 para CDN como Cloudflare — Guardian não decripta TLS | Análise de destinos de conexão (IP de destino + JA3 fingerprint de TLS) |
| **Living off the land** | Comandos com ferramentas nativas: `curl`, `python3 -c`, `bash -i >& /dev/tcp/...` | Alguns pegos via `sudo_suspicious_command`, mas variações escapam |
| **Pass-the-hash / Kerberos** | Ataques de autenticação Windows. Guardian é focado em Linux. | Fora do escopo atual |
| **Persistence via systemd timer** | `systemctl --user` não aparece no `systemctl --failed` e pode não estar em `crontab -l` | Coletar `systemctl --user list-timers` |

### 4.3 IPs legítimos que disparam falsos positivos

| Cenário | Impacto | Mitigação atual |
|---------|---------|-----------------|
| Scanner de segurança legítimo (Shodan, Censys) | `proxy_scanner_burst` dispara | Whitelist via `TRUSTED_IPS` |
| Monitoramento externo (UptimeRobot, Pingdom) | `high_connection_flood` pode disparar | Whitelist de IPs de monitoramento |
| Deploy CI/CD (GitHub Actions) | SSH de IPs diferentes a cada deploy | Adicionar CIDR do GitHub Actions à whitelist |
| Load balancer na frente do servidor | Todo tráfego vem do IP do LB | Configurar `TRUSTED_IPS` com IP do LB |
| Backup remoto (rsync) | Alto volume de conexões SSH de IP confiável | IP na whitelist |

---

## 5. Roadmap de Cobertura

### Prioridade Alta (Tier 3 — planejado)

- [ ] Detecção de OS no `add-server` → ramificação do log path (`auth.log` vs `/var/log/secure` vs `journalctl`)
- [ ] Coletar `last -F` para detectar sessões abertas anormalmente longas
- [ ] Detecção de /24 CIDR para brute force distribuído
- [ ] Janela de 24h para low-and-slow brute force (threshold: 5 falhas/24h de mesma IP)

### Prioridade Média

- [ ] Coleta de `sudo -l` periódico + diff (detectar escalação de privilégio sem `visudo`)
- [ ] Normalizar IPv6 para /64 prefix nas regras de threshold
- [ ] Detecção de DNS tunneling (volume de queries + comprimento de subdomain)
- [ ] `systemctl --user list-timers` para persistência via systemd timer de usuário
- [ ] Coleta de `/var/log/btmp` (lastb) como redundância contra apagamento de auth.log

### Prioridade Baixa

- [ ] Integração com blocklist de exit nodes Tor (atualização diária)
- [ ] `/proc/net/tcp` direto (anti-evasão de rootkits de userspace)
- [ ] Logs de aplicação configuráveis por servidor (nginx error, postgres, mysql)
- [ ] ICMP e UDP na correlação de port scan
- [ ] Coleta de `/var/log/nginx/error.log` separada do access log

---

## Referência rápida — cobertura atual

```
✅ Brute force SSH (threshold absoluto)
✅ Port scan TCP (>10 portas/30min)
✅ Lateral movement pós-brute
✅ Mineração de criptomoeda (processo + rede)
✅ DNS DGA (ONNX + entropia fallback)
✅ Path traversal HTTP
✅ File Integrity Monitoring (4h)
✅ Cron persistence
✅ Package ofensivo instalado
✅ SYN flood (rate-limit, sem ban por spoofing)
✅ Container escape + runtime compromise
✅ CVE crítica em imagem de container
✅ Comportamento SSH anômalo (profiler 30 dias)
✅ Sequência sudo anômala (Markov chain)
✅ Anomalia de métricas (STL + sigma)

⚠️  Brute force low-and-slow (só acima de 20/buffer — sem janela 24h)
⚠️  Brute force distribuído (sem agrupamento por /24)
⚠️  RHEL/Fedora (sem /var/log/secure — Tier 3)
⚠️  IPv6 brute force (sem normalização de prefixo)

❌ DNS tunneling
❌ HTTPS C2 (TLS não inspecionado)
❌ Tor exit nodes
❌ Audit syscall (auditd não coletado)
❌ Sessões abertas longas (wtmp/last não coletado)
❌ Systemd user timers
❌ Escalação via su (não sudo)
```
