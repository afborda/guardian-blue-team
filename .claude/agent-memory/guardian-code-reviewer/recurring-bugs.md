# Bugs recorrentes

Última atualização: 2026-05-29

Bugs vistos 2+ vezes — viraram regra inegociável. Quando vejo padrão similar num diff, sinalizo direto como 🔴.

## 1. Estado em memória que devia ser persistido

**Visto em:**
- `discovery.worker.ts` (corrigido 2026-05-29 commit ADR-006) — Map em memória de baselines, container restart perdia estado, gerava "Re-Discovery: changes detected" toda vez como falso positivo

**Padrão do bug:**
```typescript
class FooWorker {
  private baselines = new Map<string, Baseline>();  // 🔴 perdido em restart
  
  async run() {
    if (!this.baselines.has(server.name)) {
      this.baselines.set(server.name, await captureBaseline(server));
    }
  }
}
```

**Fix:**
```typescript
// Criar tabela DB com schema apropriado
await db.insert(discoveryBaselines)
  .values({ serverName: server.name, services: ..., capturedAt: dbDate(new Date()) })
  .onConflictDoUpdate({...});
```

**Como detectar em review:**
- `new Map<...>()` ou `new Set<...>()` como propriedade de classe Worker/Service
- Pergunta: o que acontece se container reinicia? Se for "perde dado importante" → 🔴

## 2. Boolean direto em Drizzle insert/update

**Visto em:**
- Vários commits antigos antes de `dbTrue`/`dbFalse` serem padronizados

**Padrão do bug:**
```typescript
await db.insert(t).values({ active: true });  // 🔴 SQLite issue
```

**Fix:** sempre `dbTrue`/`dbFalse`.

## 3. `StrictHostKeyChecking=accept-new`

**Visto em:**
- `ssh-collector.ts` (atual — é dívida do modelo legacy, ADR-009 vai substituir)

**Padrão:**
```typescript
const args = ['-o', 'StrictHostKeyChecking=accept-new', ...];
```

**Por quê é problema:** TOFU (trust on first use) abre janela de MITM no primeiro contato.

**Como detectar:** grep por `StrictHostKeyChecking` em qualquer código novo. Se for `accept-new` ou `no` → 🔴 a não ser que esteja documentado como compat com legacy.

## 4. `child_process` cru pra SSH

**Visto em:**
- Drafts antigos antes de `SSHCollector.run` ser padronizado

**Padrão:**
```typescript
import { spawn } from 'node:child_process';
const proc = spawn('ssh', [user, '@', host, ...]);  // 🔴 reinventa wrapper
```

**Fix:** usa `SSHCollector.run(target, cmd, timeoutMs)`.

## 5. Promise não-awaited (floating)

**Visto em:**
- Plugins de notifier (multiple times) — `notifier.send(msg)` sem await

**Padrão:**
```typescript
notifier.send(msg);  // 🔴 promise flutuante
return ok();
```

**Fix:**
```typescript
await notifier.send(msg);
// ou se for fire-and-forget intencional:
notifier.send(msg).catch((err) => logger.warn({ err }, 'notify failed'));
```

## 6. Catch vazio engolindo erro

**Visto em:**
- Várias áreas, principalmente em workers e dashboard endpoints

**Padrão:**
```typescript
try {
  await riskyThing();
} catch {}  // 🔴 erro silenciosamente desaparece
```

**Fix:**
```typescript
try {
  await riskyThing();
} catch (err) {
  logger.warn({ err }, 'riskyThing failed');
  // ou rethrow se for crítico:
  throw err;
}
```

## 7. SQL injection via template literal não-tagged

**Visto em:**
- Drafts iniciais de queries customizadas

**Padrão:**
```typescript
await db.execute(`SELECT * FROM events WHERE ip = '${ip}'`);  // 🔴 SQL injection
```

**Fix:** usa Drizzle helpers (`eq`, `and`, `or`, `inArray`) ou `sql` template tag (que escapa).

## 8. Hardcoded `/var/log/auth.log`

**Visto em:**
- Antigo collector pré-multi-OS

**Padrão:**
```typescript
const logPath = '/var/log/auth.log';  // 🔴 RHEL é /var/log/secure
```

**Fix:** depende de `os_family` do servidor (vem do schema, ver Tier 0).

## Como atualizar este arquivo

- Bug visto 2 vezes: anota aqui com data + commits onde apareceu
- Bug crítico (causou outage ou near-miss): anota mesmo na 1ª vez
- Bug obsoleto (impossível pelo design atual): move pra "Histórico" mas mantém referência
