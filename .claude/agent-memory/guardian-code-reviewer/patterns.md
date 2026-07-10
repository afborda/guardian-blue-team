# Padrões inegociáveis

Última atualização: 2026-05-29

Versão expandida do system prompt do agent. Lê isto quando estiver revisando.

## Imports / ESM

**Errado:**
```typescript
import { foo } from './bar';
```

**Certo:**
```typescript
import { foo } from './bar.js';
```

**Por quê:** Node ESM exige extensão explícita. tsup preserva. Sem `.js`, build quebra silenciosamente em runtime.

## Validação de IP

**Errado (qualquer um destes):**
- Regex frouxo tipo `/\d+\.\d+\.\d+\.\d+/` que aceita `999.1.1.1`
- Não validar antes de interpolar em comando shell
- Usar `net.isIP()` sem checar família (aceita IPv6 quando IPv4 era esperado)

**Certo:**
```typescript
import { isValidIp } from '../utils/sanitize.js';

if (!isValidIp(ip)) {
  throw new Error(`Invalid IP: ${ip}`);
}
const cmd = `ufw deny from ${ip}`;
```

## Compat DB (PG vs SQLite)

**Errado:**
```typescript
await db.insert(table).values({
  active: true,                    // SQLite armazena como integer 1/0, drizzle pode dar conflito
  createdAt: new Date(),           // SQLite quer ISO string
  updatedAt: sql`now()`,           // SQLite não tem now()
});
```

**Certo:**
```typescript
import { db, dbTrue, dbFalse, dbDate, dbNow } from '../database/connection.js';

await db.insert(table).values({
  active: dbTrue,
  createdAt: dbDate(new Date()),
  updatedAt: dbNow(),
});
```

## SSH execution

**Errado:**
- Construir target string manualmente
- Usar `child_process.spawn('ssh', ...)` direto
- Hardcode de `ssh-key-path`

**Certo:**
```typescript
const target = ServerService.toSSHTarget(server);
const result = await SSHCollector.run(target, 'ufw status', 10_000);
if (!result.success) {
  logger.warn({ err: result.error, server: server.name }, 'ufw status failed');
}
```

## Logger estruturado

**Errado:**
```typescript
logger.info('Server ' + server.name + ' failed: ' + err.message);
console.log('debug:', x);
```

**Certo:**
```typescript
logger.info({ server: server.name, err }, 'server check failed');
logger.debug({ x }, 'state at checkpoint');
```

**Por quê:** pino indexa o objeto. Concatenação destrói buscabilidade nos logs.

## Onconflict

**Errado (race condition):**
```typescript
const existing = await db.select().from(t).where(eq(t.id, id));
if (existing.length === 0) {
  await db.insert(t).values({...});
} else {
  await db.update(t).set({...}).where(eq(t.id, id));
}
```

**Certo:**
```typescript
await db.insert(t)
  .values({...})
  .onConflictDoUpdate({
    target: t.id,
    set: {...}
  });
```

## Idempotência de workers

**Errado:**
```typescript
class FooWorker {
  async run() {
    // sem proteção contra reentrância
    const items = await fetchItems();
    for (const item of items) {
      await db.insert(...);  // duplica se rodar 2x sobrepondo
    }
  }
}
```

**Certo:**
```typescript
class FooWorker {
  private running = false;

  async run() {
    if (this.running) return;
    this.running = true;
    try {
      const items = await fetchItems();
      for (const item of items) {
        await db.insert(...).onConflictDoNothing();
      }
    } finally {
      this.running = false;
    }
  }
}
```

## Silent failures (sempre 🔴 crítico)

Procure:
- `.catch(() => {})` — engole erro sem log
- `try { ... } catch {}` vazio
- `if (!result) return;` sem log
- Promises não-awaited

**Errado:**
```typescript
await fetch(url).catch(() => {});
```

**Certo:**
```typescript
await fetch(url).catch((err) => logger.warn({ err, url }, 'fetch failed'));
```

## Sanitização shell

**Errado:**
```typescript
const cmd = `grep ${userInput} /var/log/auth.log`;
await ssh.run(cmd);
```

**Certo:**
```typescript
if (!isValidPattern(userInput)) throw new Error('invalid pattern');
const cmd = `grep ${shellEscape(userInput)} /var/log/auth.log`;
```

## Drizzle queries

**Errado:**
```typescript
await db.execute(sql`SELECT * FROM events WHERE ip = '${ip}'`);  // SQL injection
```

**Certo:**
```typescript
await db.select().from(events).where(eq(events.ip, ip));
// ou se precisar SQL raw:
await db.execute(sql`SELECT * FROM events WHERE ip = ${ip}`);  // tagged template já escapa
```

## Async no top-level

**Errado:**
```typescript
// foo.ts (top-level)
const config = await loadConfig();
export const FOO = config.foo;
```

**Certo:**
```typescript
// foo.ts
let config: Config | undefined;
export async function init() {
  config = await loadConfig();
}
export function getFoo() {
  if (!config) throw new Error('not initialized');
  return config.foo;
}
```

## Anti-padrões a sinalizar imediatamente

- Hardcoded `/var/log/auth.log` sem detecção de OS (Ubuntu vs RHEL)
- `StrictHostKeyChecking=no` ou `=accept-new` em código novo
- `--no-verify`, `--no-gpg-sign` em git commands
- `process.env.X` lido em runtime fora de `config/environment.ts`
- Senha/token logado mesmo em debug
- `setTimeout` sem clearTimeout em shutdown
- Map/Set em memória pra estado que precisa persistir (use DB — bug do `discovery_baselines` 2026-05-29)

## Checklist completo (use TODO list pra cada PR)

Para cada arquivo modificado em `src/`:

1. [ ] Imports usam `.js` extension (ESM-only)
2. [ ] IPs validados com `isValidIp` antes de shell
3. [ ] Datas via `dbDate(new Date())`
4. [ ] Booleans via `dbTrue`/`dbFalse`
5. [ ] SSH via `SSHCollector.run`, não `spawn` cru
6. [ ] Logger estruturado com contexto
7. [ ] `await` em todas Promises (ou `.catch()` explícito com log)
8. [ ] Worker idempotente (`this.running` guard)
9. [ ] Sanitização em comandos shell
10. [ ] Drizzle queries usam helpers (não SQL raw com user input)
11. [ ] Sem `console.log`, sem `any` injustificado
12. [ ] Tratamento de erro consistente com o resto do arquivo

## Quando este arquivo deve mudar

- Padrão novo emerge no projeto: adiciona aqui
- Time muda convenção: atualiza tabelas certo/errado
- Bug recorrente vira padrão: move pra `recurring-bugs.md` mas referencia aqui
