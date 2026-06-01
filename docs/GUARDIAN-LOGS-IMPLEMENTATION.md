# Guardian — Plano de Implementação para Logs Faltantes

> Plano prático para fechar as lacunas listadas em `GUARDIAN-LOGS.md`. Cada item tem: arquivo, snippet de código no padrão atual, schema impactado, regras desbloqueadas e estimativa.
> Gerado em 2026-05-31. Base: código v3.1.1.
> **Revisado em 2026-05-31 (v2)** após auditoria do código real — corrige 5 imprecisões e adiciona 3 bloqueadores operacionais.

---

## ⚠️ Bloqueadores antes do MVP

A auditoria do código identificou **3 dependências críticas** que precisam decisão antes do PR1:

### B1. Tier 0 (guardian-shell + sudoers allowlist) — não implementado
- **Estado atual:** modelo legacy. SSH usa `StrictHostKeyChecking=accept-new` (`ssh-collector.ts:26`), sudo sem allowlist
- **Impacto:** os 8 collectors novos herdam modelo inseguro
- **Decisão necessária:** implementar Tier 0 antes (~6-8h) **ou** documentar dívida técnica e seguir
- Roadmap: `.claude/agent-memory/guardian-architect/roadmap.md` (status "aguardando autorização")

### B2. Tabela `collector_state` (cursor persistente)
- **Estado atual:** cursor em `Map<number, string>` volátil — restart do Guardian = duplicação
- **Impacto:** PR3 (cursor journalctl) não funciona sem isso
- **Schema obrigatório (DDL-in-code em `connection.ts`):**
  ```sql
  CREATE TABLE IF NOT EXISTS collector_state (
    server_id INTEGER NOT NULL,
    source VARCHAR(50) NOT NULL,
    cursor TEXT,
    updated_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (server_id, source)
  );
  ```

### B3. auditd bootstrap
- **Estado atual:** `server-readiness.ts:44-45` marca `ausearch` como `required: false`. Auditd não vem em Ubuntu
- **Impacto:** PR8 (auditd integration) precisa: (a) instalação no `install.sh`, (b) write de `/etc/audit/rules.d/guardian.rules` durante `/add-server`, (c) sudoers para `auditctl`

---

## Sumário

1. [Pré-requisito comum — OS detection persistido](#1-pré-requisito-comum--os-detection-persistido)
2. [Fase 1 — Alta prioridade (~3 sprints curtas)](#2-fase-1--alta-prioridade-3-sprints-curtas)
3. [Fase 2 — Média prioridade](#3-fase-2--média-prioridade)
4. [Fase 3 — Baixa prioridade](#4-fase-3--baixa-prioridade)
5. [Convenções a respeitar](#5-convenções-a-respeitar)
6. [Ordem de merge sugerida](#6-ordem-de-merge-sugerida)

---

## 1. Pré-requisito comum — OS detection persistido

**Problema:** o Discovery (`src/discovery/probes/system.ts:21`) já parseia `/etc/os-release` e extrai `{ name, version, id }`, mas o resultado **nunca é persistido** — fica só no `ProbeResult` retornado pela função e é descartado depois do relatório de discovery. Todos os collectors hoje assumem Debian/Ubuntu (`/var/log/auth.log`, `/var/log/ufw.log`). Sem persistir o `os_family`, **nenhuma das melhorias abaixo funciona em RHEL/Fedora**.

**Solução em 3 passos** (auditoria confirmou os 3 são necessários):
1. Schema novo (`os_family` em `soc_servers`)
2. Hook no Discovery para gravar resultado já parseado (reusa `parseOS()` em `system.ts:54-59`)
3. `OSDetector` standalone para servidores cadastrados antes do Discovery existir

### 1.1 Schema (`src/database/guardian-schema.ts`)

```ts
// Em socServers (linha ~20)
export const socServers = pgTable('soc_servers', {
  // ...campos existentes
  osFamily: varchar('os_family', { length: 20 }).default('debian'),  // 'debian' | 'rhel' | 'alpine' | 'arch' | 'unknown'
  osVersion: varchar('os_version', { length: 50 }),
  osDetectedAt: timestamp('os_detected_at'),
});
```

DDL idempotente em `src/database/connection.ts` (na função `initDatabase`, seguindo o padrão de `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`):

```ts
await sql`ALTER TABLE soc_servers ADD COLUMN IF NOT EXISTS os_family VARCHAR(20) DEFAULT 'debian'`;
await sql`ALTER TABLE soc_servers ADD COLUMN IF NOT EXISTS os_version VARCHAR(50)`;
await sql`ALTER TABLE soc_servers ADD COLUMN IF NOT EXISTS os_detected_at TIMESTAMP`;
```

### 1.2 Mapeamento `ServerService.toSSHTarget` (`src/services/server.service.ts:137-146`)

**Auditoria descobriu:** mapeamento é literal (campo a campo), **não automático**. Adicionar `osFamily` exige edição em **2 lugares**:

```ts
// (1) src/collectors/ssh-collector.ts — interface SSHTarget
export interface SSHTarget {
  id: number;
  name: string;
  host: string;
  sshPort: number;
  sshUser: string;
  sshKeyPath: string | null;
  osFamily?: OSFamily;  // ← novo, opcional para não quebrar
}

// (2) src/services/server.service.ts:137 — função toSSHTarget()
static toSSHTarget(server: ServerInfo): SSHTarget {
  return {
    id: server.id,
    name: server.name,
    host: server.host,
    sshPort: server.sshPort,
    sshUser: server.sshUser,
    sshKeyPath: server.sshKeyPath,
    osFamily: (server.osFamily ?? 'debian') as OSFamily,  // ← novo
  };
}
```

### 1.3 Helper de detecção rápida (`src/collectors/os-detector.ts` — novo)

Para servidores legados (cadastrados antes do Discovery, ou que pularam o probe completo), um detector leve que roda 1× no primeiro ciclo de coleta:

```ts
import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { db, dbDate } from '../database/connection.js';
import { socServers } from '../database/guardian-schema.js';
import { eq } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export type OSFamily = 'debian' | 'rhel' | 'alpine' | 'arch' | 'unknown';

export class OSDetector {
  /** Detecta família do OS lendo /etc/os-release. Persiste em soc_servers. */
  static async detectAndPersist(target: SSHTarget): Promise<OSFamily> {
    const result = await SSHCollector.run(
      target,
      `cat /etc/os-release 2>/dev/null | grep -E '^(ID|VERSION_ID)='`,
      5_000,
    );
    if (!result.success) return 'unknown';

    const idMatch = result.stdout.match(/^ID="?([^"\n]+)"?/m);
    const versionMatch = result.stdout.match(/^VERSION_ID="?([^"\n]+)"?/m);
    const id = idMatch?.[1]?.toLowerCase() ?? '';

    const family: OSFamily =
      ['debian', 'ubuntu', 'linuxmint', 'raspbian'].includes(id) ? 'debian' :
      ['rhel', 'centos', 'fedora', 'rocky', 'almalinux', 'amzn'].includes(id) ? 'rhel' :
      ['alpine'].includes(id) ? 'alpine' :
      ['arch', 'manjaro'].includes(id) ? 'arch' :
      'unknown';

    await db.update(socServers)
      .set({ osFamily: family, osVersion: versionMatch?.[1], osDetectedAt: dbDate(new Date()) })
      .where(eq(socServers.id, target.id));

    logger.info({ server: target.name, family }, 'OS family detected');
    return family;
  }
}
```

Adicionar `osFamily` ao `SSHTarget` e ao mapeamento `ServerService.toSSHTarget()` para cada collector poder ramificar o comando.

**Custo:** 1h. **Sem isso, todos os itens da Fase 1 ficam meio-cegos em ~30% dos servidores reais.**

---

## 2. Fase 1 — Alta prioridade (3 sprints curtas)

### 2.1 `/var/log/secure` (RHEL) — corrigir cegueira em RHEL/Fedora

**Onde:** `src/collectors/log-collector.ts` — ramificar `collectAuthLogs` por `osFamily`.

```ts
static async collectAuthLogs(target: SSHTarget, sinceMinutes = 5): Promise<RawLogEntry[]> {
  const since = new Date(Date.now() - sinceMinutes * 60_000);
  const sinceStr = since.toISOString().replace('T', ' ').slice(0, 19);

  // Strategy: try journalctl (universal) → fall back to OS-specific file
  const fallbackFile = target.osFamily === 'rhel' ? '/var/log/secure' : '/var/log/auth.log';

  const result = await SSHCollector.run(target,
    `sudo journalctl -u ssh -u sshd --since '${sinceStr}' --no-pager -o short-iso 2>/dev/null || ` +
    `sudo tail -100 ${fallbackFile} 2>/dev/null || echo ''`,
    20_000,
  );
  // ...resto igual
}
```

**Mesmo padrão para:** `sudo-collector.ts` (linha 11) e `services/host-security.service.ts` (linha 73).

**Regras desbloqueadas:** `ssh_brute_force_burst`, `ssh_invalid_user`, `lateral_movement` passam a funcionar em RHEL.
**Custo:** 2h (escrever + testar em VM RHEL).

---

### 2.2 `last -F` — sessões abertas anormalmente longas (possível backdoor)

**Onde:** novo método no `auth-collector.ts` (ou estender `LogCollector`).

```ts
// src/collectors/log-collector.ts
static async collectActiveSessions(target: SSHTarget): Promise<RawLogEntry[]> {
  const result = await SSHCollector.run(target,
    `last -F -n 50 -w 2>/dev/null | head -50`,
    10_000,
  );
  if (!result.success || !result.stdout.trim()) return [];

  return result.stdout.trim().split('\n')
    .filter(line => line.match(/^\w+\s+\S+\s+\S+/))
    .map(line => ({
      serverId: target.id,
      serverName: target.name,
      source: 'wtmp',  // adicionar 'wtmp' às sources do normalizer
      timestamp: new Date(),
      line,
    }));
}
```

**Normalizer (`src/pipeline/normalizer.ts`)** — novo case:

```ts
case 'wtmp': {
  // Format: user pts/0 1.2.3.4 Mon May 30 14:22:01 2026 - still logged in (12+03:45)
  // OR: user pts/0 1.2.3.4 Mon May 30 14:22:01 2026 - Mon May 30 18:30:00 2026 (04:08)
  const stillOpen = line.match(/^(\S+)\s+\S+\s+(\S+).*still logged in.*\((\d+)\+/);
  if (stillOpen) {
    const days = parseInt(stillOpen[3]);
    if (days >= 1) {  // sessão aberta há mais de 24h
      return {
        eventType: 'long_running_session',
        severity: days >= 7 ? 'high' : 'medium',
        userName: stillOpen[1],
        sourceIp: stillOpen[2],
        metadata: { sessionDaysOpen: days },
        // ...
      };
    }
  }
  break;
}
```

**Frequência:** 1× a cada 30 min (não tem urgência sub-minuto). Adicionar a um worker novo `SessionAuditWorker` ou ao `IntelligenceWorker`.

**Custo:** 3h.

---

### 2.3 `journalctl -u sshd` — fallback testado em prod

**Estado atual:** o `LogCollector.collectAuthLogs` já tenta `journalctl` antes do `tail`. Falta:
- Confirmar que `sshd` (não `ssh`) é o nome correto em RHEL/Fedora
- Adicionar cursor persistente para evitar re-leitura de eventos antigos

**Patch sugerido** (`src/collectors/log-collector.ts`):

```ts
private static lastCursor = new Map<number, string>();  // serverId → cursor

static async collectAuthLogs(target: SSHTarget, sinceMinutes = 5): Promise<RawLogEntry[]> {
  const cursor = this.lastCursor.get(target.id);
  const cursorArg = cursor ? `--after-cursor='${cursor}'` : `--since '${sinceMinutes}min ago'`;

  const result = await SSHCollector.run(target,
    `sudo journalctl -u ssh -u sshd ${cursorArg} --no-pager -o short-iso --show-cursor 2>/dev/null`,
    20_000,
  );
  // ...
  // Capturar `-- cursor: s=abc...` da última linha e salvar no Map
}
```

**Benefício:** elimina dupla-contagem de eventos quando o ciclo demora mais que 2min.
**Custo:** 2h.

---

### 2.4 `/proc/net/nf_conntrack` — visibilidade UDP/ICMP completa

**Por que importa:** o Guardian hoje só vê TCP via `netstat`/UFW. C2 via UDP keep-alive longo passa invisível.

**Novo collector** (`src/collectors/conntrack-collector.ts`):

```ts
import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';

export class ConntrackCollector {
  static async collect(target: SSHTarget): Promise<RawLogEntry[]> {
    // Requires kernel: net.netfilter.nf_conntrack_acct=1 for byte counters
    const result = await SSHCollector.run(target,
      `sudo cat /proc/net/nf_conntrack 2>/dev/null | head -500`,
      8_000,
    );
    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(line => line.includes('ESTABLISHED') || line.includes('ASSURED'))
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'conntrack',
        timestamp: new Date(),
        line,
      }));
  }
}
```

**Normalizer:** parsear formato (proto src=X dst=Y sport=N dport=N), filtrar IPs CGNAT, emitir `conntrack_long_session` quando `delta_ms` > 1h em conexão UDP/ICMP para IP externo.

**Regras desbloqueadas:** detecção de C2 via DNS-over-UDP keep-alive, detecção de exfiltração via ICMP tunneling.
**Custo:** 4h.

---

### 2.5 nginx `error.log` — separar do access log

**Onde:** estender `proxy-collector.ts` (que hoje só lê access log).

```ts
// src/collectors/proxy-collector.ts
static async collectErrorLog(target: SSHTarget, sinceMinutes = 5): Promise<RawLogEntry[]> {
  const errorPaths = [
    '/var/log/nginx/error.log',
    '/var/log/apache2/error.log',
    '/var/log/httpd/error_log',  // RHEL
  ];
  const cmd = errorPaths.map(p => `sudo tail -100 ${p} 2>/dev/null`).join(' ; ');
  const result = await SSHCollector.run(target, cmd, 10_000);
  // ...
}
```

**Normalizer:** padrões para detectar tentativas de CVE em apps web (`Permission denied`, `worker process exited on signal 11` = crash repetido pode ser fuzzing).

**Custo:** 2h.

---

### 2.6 `sudo -l` periódico + diff de baseline

**Por que:** detectar escalação silenciosa (alguém ganhou `NOPASSWD ALL` sem `visudo` aparecer no audit).

**Novo worker** (`src/workers/sudo-baseline.worker.ts`) rodando a cada 1h:

```ts
import { SSHCollector } from '../collectors/ssh-collector.js';
import { db, dbDate } from '../database/connection.js';
import { ServerService } from '../services/server.service.js';

// Schema novo: tabela sudo_baselines (server_id, user, sudo_rules_hash, last_seen)
export class SudoBaselineWorker {
  static async snapshot(target: SSHTarget): Promise<void> {
    // Lista usuários reais do sistema
    const users = await SSHCollector.run(target,
      `awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd`, 5_000);

    for (const user of users.stdout.trim().split('\n')) {
      const sudoOut = await SSHCollector.run(target,
        `sudo -lU ${user} 2>/dev/null`, 5_000);
      const hash = createHash('sha256').update(sudoOut.stdout).digest('hex');

      // Comparar com baseline anterior; se mudou → emit security_event
      // categoria: privilege_escalation, severity: high
    }
  }
}
```

**Regra desbloqueada:** `sudo_baseline_drift` (high) — alguém ganhou permissão sudo nova entre snapshots.
**Custo:** 5h (worker + schema + diff + teste).

---

### 2.7 Auditd (`/var/log/audit/audit.log`) — base para detecção de evasão

**Decisão de escopo:** **NÃO** ler `audit.log` cru (volume gigantesco). Em vez disso, instalar regras específicas + ler só os eventos filtrados.

**Estratégia:**
1. Adicionar à instalação do `add-server` um arquivo `/etc/audit/rules.d/guardian.rules`:
   ```
   -a always,exit -F arch=b64 -S execve -F exit=0 -F key=guardian_exec
   -w /etc/passwd -p wa -k guardian_passwd
   -w /etc/shadow -p wa -k guardian_shadow
   -w /etc/sudoers -p wa -k guardian_sudoers
   -w /root/.ssh -p wa -k guardian_ssh_keys
   ```
2. Estender `audit-collector.ts` para ler com `ausearch -k guardian_*` (filtro por nossas keys).
3. Normalizer: novo case `auditd` → mapear keys para event types.

**Custo:** 8h (regras + collector + integração com instalador).

---

### 2.8 Logs de aplicação configuráveis por servidor

**Schema:** adicionar coluna `app_log_paths jsonb DEFAULT '[]'` em `soc_servers`. Cada entry: `{ "name": "myapp-error", "path": "/var/log/myapp/error.log", "regex_pattern": "..." }`.

**Collector genérico** (`src/collectors/app-log-collector.ts`):

```ts
static async collectAll(target: SSHTarget): Promise<RawLogEntry[]> {
  const paths = target.appLogPaths ?? [];
  const results: RawLogEntry[] = [];
  for (const cfg of paths) {
    const r = await SSHCollector.run(target,
      `sudo tail -100 ${cfg.path} 2>/dev/null`, 8_000);
    // emitir como source: cfg.name
  }
  return results;
}
```

**Custo:** 3h (CRUD básico — UI no dashboard fica para Fase 2).

---

## 3. Fase 2 — Média prioridade

| Item | Implementação | Custo |
|------|--------------|-------|
| **`/proc/net/tcp` direto** | Novo collector lendo `/proc/net/tcp` + `/tcp6`, parseando hex de IP/porta. Mais difícil de rootkit evadir. | 4h |
| **PAM `faillock`** | `faillock --user X` em loop pelos usuários, comparar com baseline. | 2h |
| **DNS reverso (PTR) em IPs suspeitos** | Adicionar resolução DNS reversa ao `Enricher` quando AbuseIPDB score >= 50. Cachear 24h. | 2h |
| **`inotify` em tempo real (FIM)** | Instalar `inotifywait` no servidor monitorado, escrever em FIFO, `tail -F` via SSH. Trade-off: agente leve. | 8h |
| **Container stdout/stderr** | `docker logs --since 5m <container>` para containers marcados crítico. | 3h |
| **`/var/log/btmp` (lastb)** | `sudo lastb -F -n 50` — falhas de senha em login local. | 1h |
| **Apache/nginx status endpoint** | HTTP poll em `/nginx_status` e `/server-status` (auth via IP whitelist). | 3h |
| **Contadores `iptables -L -nv`** | Snapshot a cada 1h, alertar quando regra nova aparece com counter crescendo. | 4h |
| **Logs OpenVPN/WireGuard** | `journalctl -u openvpn -u wg-quick@wg0` — só onde existe. | 2h |
| **Escalação via `su`** | Pattern de regex em `auth.log`: `pam_unix(su:session): session opened`. | 1h |

**Total Fase 2:** ~30h (2-3 sprints).

---

## 4. Fase 3 — Baixa prioridade

| Item | Implementação | Custo |
|------|--------------|-------|
| **Correlação tempo real loadavg/meminfo ↔ eventos** | Já coletados; criar regra que dispara `resource_anomaly_correlation` quando spike + evento de segurança em janela 5 min. | 2h |
| **`dmesg` para módulo de kernel novo** | `dmesg --since '1 hour ago' \| grep -i 'module\|loaded'`. | 1h |
| **`/var/log/boot.log`** | Detectar reboot inesperado: comparar uptime com baseline. | 1h |
| **SNMP traps** | Setup `snmptrapd`, encaminhar via UDP para coleta. Só onde houver equipamento de rede gerenciado. | 6h |
| **S3/cloud audit logs** | Cliente AWS/GCP via env credenciais opcionais. Fora do escopo "agentless". | 12h+ |

---

## 5. Convenções a respeitar

Ao implementar qualquer item desta lista, **seguir o padrão existente**:

1. **`SSHCollector.run(target, command, timeoutMs)`** — nunca usar `child_process` direto
2. **Sanitização**: nunca interpolar input do usuário no `command`. Hoje todos os comandos são literais
3. **Fallback graceful**: `2>/dev/null || echo ''` no fim de cada comando — collectors nunca devem propagar erro de SSH
4. **`RawLogEntry`** com `source` único (`'auth.log'`, `'wtmp'`, `'conntrack'`, etc.) — adicionar case correspondente no `normalizer.ts`
5. **Idempotência**: collectors são chamados a cada 2 min — usar cursor (ex.: `journalctl --after-cursor`) ou janela temporal para evitar duplicatas
6. **DDL-in-code**: schema novo vai em `initDatabase()` com `CREATE TABLE IF NOT EXISTS` + `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`. Sem migration runner
7. **Logger estruturado**: `logger.info({ server, count }, 'Collected X')` — nunca string concat
8. **Testes**: pelo menos um teste em `tests/` para o normalizer do novo formato (sem precisar de SSH real)

---

## 6. Ordem de merge sugerida (revisada após auditoria)

A ordem importa porque alguns itens dependem de outros:

```
PR0 — DECISÃO: Tier 0 antes ou dívida documentada?  (B1)
       ↓
PR1 — Schema (os_family + collector_state) (1.1, B2)
       ↓
PR1.5 — Sudoers allowlist novos comandos (RHEL/conntrack/nginx-error/auditd)
       ↓
PR2 — Hook persistência OS no Discovery + OSDetector standalone (1.2, 1.3)
       ↓
PR3 — /var/log/secure (RHEL) (2.1)         ← desbloqueia ~30% dos servidores
       ↓
PR4 — Cursor persistente em journalctl (2.3)  ← usa collector_state agora
       ↓
PR5 — last -F + long_running_session (2.2)
       ↓
PR6 — nginx error.log (extensão do proxy-collector existente) (2.5)
       ↓
PR7 — conntrack collector (2.4)             ← alta complexidade, isolar
       ↓
PR8 — sudo baseline worker (2.6)            ← schema novo (sudo_baselines)
       ↓
PR9 — auditd bootstrap + integration (2.7)  ← afeta install.sh + add-server flow
       ↓
PR10 — app log paths configuráveis (2.8)    ← schema + UI dashboard
       ↓
[Fase 2: PRs paralelos podem ir]
```

**Marco mínimo viável (MVP) para fechar gap RHEL:** PR0 (decisão) + PR1 + PR1.5 + PR2 + PR3 + PR4. **~11h** (era 5h no plano v1 — auditoria adicionou 6h de pré-requisitos não mapeados).

Depois disso, qualquer servidor RHEL/Fedora cadastrado já é monitorado igual a um Ubuntu.

---

## 7. Estimativa total

| Fase | Itens | Esforço (v1) | Esforço (v2 pós-auditoria) |
|------|-------|--------------|---------------------------|
| Pré-req crítico (Tier 0 + sudoers + auditd bootstrap) | 3 bloqueadores | (não mapeado) | **+11h** |
| Pré-req schema (OS detection + collector_state) | 1+1 | 1h | 2h |
| Fase 1 (alta prioridade) | 8 | 29h | 29h |
| Fase 2 (média) | 10 | 30h | 30h |
| Fase 3 (baixa) | 5 | 22h+ | 22h+ |
| **Total** | **27** | **~82h** | **~94h** (~2.5 semanas full-time) |

**Recomendação atualizada:** MVP **mínimo seguro** = PR0+PR1+PR1.5+PR2+PR3+PR4 = **~11h**. Já fecha cegueira RHEL **e** elimina duplicação por restart. Esse é o melhor ponto de retorno por hora antes de descer pra collectors específicos.

---

## 8. Riscos e mitigações

| Risco | Mitigação |
|-------|-----------|
| Volume excessivo de eventos (auditd cru, conntrack em servidor com 10k conexões) | Filtrar no servidor antes de transmitir (ausearch -k, head -500) |
| Comandos SSH novos exigindo sudo NOPASSWD | Documentar no instalador — adicionar à allowlist do `guardian-shell` (Tier 0) |
| Quebra em servidores legados sem `osFamily` populado | Default `'debian'` no schema — mantém comportamento atual até primeira detecção |
| Cursor de journalctl perdido em restart do Guardian | **(B2)** Persistir em tabela `collector_state(server_id, source, cursor)` — não em memória |
| Regex nova no normalizer com falso positivo | Cobertura de teste obrigatória em `tests/normalizer.test.ts` antes de merge |

---

## 9. Achados da auditoria (2026-05-31, v2)

Esta seção documenta o que mudou entre v1 e v2 do plano após auditoria do código real (`src/collectors/`, `src/services/server.service.ts`, `src/database/connection.ts`, `src/discovery/`).

### ✅ Premissas confirmadas
- `SSHTarget` (`ssh-collector.ts:7-14`) é interface aberta — adicionar `osFamily?` não quebra os 25+ consumidores
- `SSHCollector.runMulti` existe (`ssh-collector.ts:56-59`) e funciona como descrito (`commands.join(' && ')`)
- DDL idempotente já é padrão: `connection.ts:211-214,237,396` usam `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
- `EventCollectorWorker.collect` (`event-collector.worker.ts:76-90`) roda 13 collectors paralelos em `Promise.all` — basta adicionar os novos à mesma lista
- `Normalizer` (`pipeline/normalizer.ts:79-118`) tem 17 cases hoje, switch/case extensível, default retorna `null`

### ⚠️ Imprecisões corrigidas
- **`ServerService.toSSHTarget` (`server.service.ts:137-146`) é literal** — adicionar `osFamily` exige edição em 2 lugares (interface + função), não 1. Ver §1.2
- **`AuditCollector` filtra por `-m USER_AUTH,...`, não por `-k guardian_*`** — coexiste sem breaking, mas plano agora documenta que adiciona filtro por keys (§2.7)
- **Discovery parseia OS mas descarta** — `parseOS()` em `system.ts:54-59` extrai `{ name, version, id }` mas resultado fica só no `ProbeResult`. Plano agora explicita o hook de persistência

### 🔴 Bloqueadores que faltavam
- **B1 — Tier 0 não implementado** — guardian-shell wrapper + sudoers allowlist são planejados mas não merged. Decisão necessária antes do PR1
- **B2 — `collector_state` table não existe** — cursor estava em `Map` volátil no plano v1. Schema obrigatório agora (§B2 acima)
- **B3 — auditd não vem em Ubuntu** — `server-readiness.ts:44-45` marca como `required: false`. PR9 precisa bootstrap em `install.sh` + write das regras durante `/add-server`

### Ajuste de escopo
| Estimativa | v1 | v2 |
|------------|-----|-----|
| MVP RHEL (decisão Tier 0 + schema + 3 collectors) | 5h | **11h** |
| Fase 1 completa | 29h | 29h |
| **Total geral** | **82h** | **94h** |
