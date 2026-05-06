# Features de Seguranca

Guardian detecta, correlaciona e responde a ameacas automaticamente.

---

## Regras de Deteccao (15+)

### SSH e Autenticacao

| Regra | Condicao | Severidade |
|-------|----------|-----------|
| SSH Brute Force | 20+ falhas do mesmo IP em 10min | high |
| Unauthorized Login | Login de IP/fingerprint nao-trusted | medium |
| Password Login | Login por senha (deveria ser apenas chave) | medium |
| Unusual Hour Login | Login entre 00:00-06:00 de IP nao-trusted | medium |
| Lateral Movement | SSH de IP que brute-forçou outro servidor | critical |

### Containers e Processos

| Regra | Condicao | Severidade |
|-------|----------|-----------|
| Container Escape | 5+ mortes de container em 10min | critical |
| Crypto Mining | Processo xmrig/minerd/cpuminer/kdevtmpfsi detectado | critical |
| Suspicious Binary | Execucao de /tmp, /dev/shm, caminhos ocultos | high |

### Rede

| Regra | Condicao | Severidade |
|-------|----------|-----------|
| Port Scanning | 5+ portas sondadas em 10min do mesmo IP | high |
| DNS DGA | Dominio com entropia Shannon > threshold | high |
| DNS Suspicious TLD | Query para .tk, .ml, .ga, .cf, .top, .xyz, .pw, .cc | medium |

### Integridade e Persistencia

| Regra | Condicao | Severidade |
|-------|----------|-----------|
| Critical File Tamper | Alteracao em /etc/passwd, shadow, sudoers, sshd_config | critical |
| Suspicious Sudo | Sudo com curl, wget, nc, base64 -d, chmod 777 | high |
| Cron Persistence | Novo cron com pattern de reverse shell ou download | high |
| Unauthorized SSH Key | Nova chave adicionada em authorized_keys | high |

---

## Playbooks de Resposta Automatica (15)

Playbooks executam acoes pre-definidas. Alguns requerem aprovacao humana (botao no Telegram).

| Playbook | Acao | Aprovacao? |
|----------|------|-----------|
| `block_ip_ufw` | Bloqueia IP via UFW por X horas | Nao (auto) |
| `block_ip_permanent` | Block permanente | Sim |
| `kill_crypto_miner` | Mata processos de mineracao | Nao (auto) |
| `pause_container` | Pausa container comprometido | Nao (auto) |
| `disconnect_container` | Desconecta container da rede | Sim |
| `enrich_ip_abuseipdb` | Consulta reputacao no AbuseIPDB | Nao (auto) |
| `enrich_ip_virustotal` | Consulta VirusTotal | Nao (auto) |
| `track_repeat_offender` | Marca IP como reincidente | Nao (auto) |
| `alert_fim_violation` | Alerta sobre alteracao de arquivo critico | Sim |
| `alert_sudo_suspicious` | Alerta sobre sudo suspeito | Nao (auto) |
| `alert_cron_persistence` | Alerta sobre cron malicioso | Sim |
| `alert_ssh_key_added` | Alerta sobre chave SSH nao autorizada | Sim |
| `respond_dns_c2` | Bloqueia dominio C2 via DNS | Sim |
| `escalate_to_critical` | Eleva incidente para critical | Nao (auto) |
| `auto_block_on_threshold` | Block automatico quando score AI > threshold | Nao (auto) |

**Auto-learn**: Quando um playbook resolve um incidente com sucesso, a resolucao e automaticamente armazenada na memoria (RAG) para referencia futura.

---

## CVE Monitoring

**Como funciona:**
1. Worker varre pacotes instalados nos servidores (a cada 6h)
2. Compara com base OSV.dev (open-source vulnerability database)
3. Filtra por CVSS >= 7.0 (configuravel)
4. AI gera recomendacao de fix com avaliacao de risco
5. Notifica via Telegram com botao de acao

**Acoes disponiveis:**
- Atualizar pacote (com aprovacao)
- Ignorar CVE (marca como aceito)
- Ver detalhes (link para advisory)

---

## Threat Intelligence

### AbuseIPDB
- Consulta automatica de IPs que atacam
- Score de confianca (0-100)
- Se score > `ABUSE_CONFIDENCE_THRESHOLD`: propoe block automatico
- Historico de reports por outros usuarios

### VirusTotal
- Analise de IPs e hashes
- Deteccoes por multiplos engines
- Informacoes de WHOIS e ASN

---

## File Integrity Monitoring (FIM)

**Arquivos monitorados:**
- `/etc/passwd`, `/etc/shadow`, `/etc/group`
- `/etc/sudoers`, `/etc/sudoers.d/*`
- `/etc/ssh/sshd_config`
- `/root/.ssh/authorized_keys`
- `~/.ssh/authorized_keys` de todos os usuarios

**Como funciona:**
1. Primeiro scan cria baseline (SHA256 de cada arquivo)
2. Scans subsequentes (a cada 4h) comparam com baseline
3. Diferencas geram eventos com severidade baseada no arquivo alterado
4. Incidente criado automaticamente para alteracoes criticas

---

## Monitoramento Adicional

### Sudo Auditing
- Captura todos os comandos sudo executados
- Alerta para comandos suspeitos (download, shells reversos, chmod perigoso)
- Historico consultavel via `/sudo [hours]`

### Cron Jobs
- Enumera cron jobs de todos os usuarios
- Detecta adicoes com patterns maliciosos:
  - `curl | bash`, `wget -O- | sh`
  - Reverse shells (`/dev/tcp`, `nc -e`)
  - Base64 encoded commands
- Baseline comparativo detecta mudancas

### SSH Keys
- Monitora `authorized_keys` de todos os usuarios
- Alerta quando chave nova e adicionada
- Compara fingerprint com lista de trusted (`TRUSTED_FINGERPRINTS`)

### DNS Monitoring
- Captura queries DNS dos servidores
- Calcula entropia Shannon para detectar DGA (Domain Generation Algorithm)
- Alerta para TLDs suspeitos usados em C2 (command & control)
