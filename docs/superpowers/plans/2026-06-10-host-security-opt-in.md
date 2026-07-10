# Guardian "local" pseudo-target opt-in Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the chronic `DNS log collection failed via SSH` / `Sudo log collection failed via SSH` warnings (server=`local`, every ~2 minutes) by making the Guardian-host self-target opt-in: only added to the collection loop when `HOST_SSH_KEY_PATH` is configured.

**Architecture:** `HostSecurityService.getDefaultTarget()` currently always returns a synthetic target named `local`, which `EventCollectorWorker.collect()` blindly appends to `allTargets`. With no `HOST_SSH_KEY_PATH` set (the prod config), every collector tries SSH against `127.0.0.1:22` as `ubuntu` and fails. We change `getDefaultTarget()` to return `SSHTarget | null` (null when no key path is configured), and update both callers (`event-collector.worker.ts`, `host-security.service.ts:getSnapshot`) to handle the null case. Backward compat: deployments with `HOST_SSH_KEY_PATH` set keep working unchanged.

**Tech Stack:** TypeScript, vitest, Node ESM, Drizzle ORM (Postgres in prod, SQLite for dev), tsup bundler.

---

## Context (read once, do not skip)

**Where the bug lives:**
- `guardian/src/services/host-security.service.ts:30` — `getDefaultTarget()` always returns a target.
- `guardian/src/workers/event-collector.worker.ts:80` — appends it to `allTargets` unconditionally.
- `guardian/src/services/host-security.service.ts:42` — `getSnapshot(target, hours)` falls back to `getDefaultTarget()` when `target` is `undefined`.

**Where it must keep working:**
- `guardian/src/workers/daily-report.worker.ts:134` — calls `HostSecurityService.getSnapshot(target, 24)` with a real server target from `ServerService.toSSHTarget(server)`. **It never relies on the fallback** — only the type. Untouched by this change.

**Test infra:**
- Tests live in `guardian/tests/`, framework is vitest. `tests/setup.ts` mocks `config`, `db`, `logger` globally — see lines 1–50 of that file. The mock already has `hostSecurity: { sshHost: '127.0.0.1', sshPort: 22, sshUser: 'ubuntu', sshKeyPath: null }`. Tests can override per-file via `vi.mocked(config)`.
- Existing pattern: see `guardian/tests/collectors.test.ts` and `guardian/tests/normalizer.test.ts` for how unit tests in this repo look.

**Prod deploy path:**
- Code lives at `/root/guardian` on host alias `hetzner` (138.201.56.177).
- `git pull && docker compose up -d --build guardian` rebuilds and restarts only the `guardian` service (not `guardian-db` or `guardian-trivy`). Container is healthy when `docker exec guardian wget -qO- http://localhost:3334/health` returns `{"status":"ok"}`.
- Verification = tail logs for ≥3 minutes and confirm zero `server=local` warns.

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `guardian/src/services/host-security.service.ts` | Modify | `getDefaultTarget()` returns `SSHTarget \| null`. `getSnapshot()` handles null target via the existing `empty` snapshot. |
| `guardian/src/workers/event-collector.worker.ts` | Modify | After fetching `guardianHost`, only append to `allTargets` when non-null. |
| `guardian/tests/host-security.test.ts` | Create | Unit test covering both branches of `getDefaultTarget()` plus the null-handling in `getSnapshot()`. |
| `guardian/tests/event-collector.test.ts` | Create | Unit test on the `allTargets` shape — extract a small pure helper if the worker doesn't already expose one. |

---

## Task 1: Failing test for `HostSecurityService.getDefaultTarget()`

**Files:**
- Create: `guardian/tests/host-security.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// guardian/tests/host-security.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HostSecurityService } from '../src/services/host-security.service.js';
import { config } from '../src/config/environment.js';

describe('HostSecurityService.getDefaultTarget', () => {
  beforeEach(() => {
    // The global mock in tests/setup.ts exposes config as a plain object.
    // We mutate the hostSecurity slice in place so changes are visible
    // to the imported HostSecurityService.
    config.hostSecurity = {
      sshHost: '127.0.0.1',
      sshPort: 22,
      sshUser: 'ubuntu',
      sshKeyPath: null,
    };
  });

  it('returns null when HOST_SSH_KEY_PATH is not configured', () => {
    config.hostSecurity.sshKeyPath = null;
    expect(HostSecurityService.getDefaultTarget()).toBeNull();
  });

  it('returns a target with name "local" when HOST_SSH_KEY_PATH is set', () => {
    config.hostSecurity.sshKeyPath = '/home/node/.ssh/guardian_ed25519';
    const target = HostSecurityService.getDefaultTarget();
    expect(target).not.toBeNull();
    expect(target).toMatchObject({
      id: 0,
      name: 'local',
      host: '127.0.0.1',
      sshPort: 22,
      sshUser: 'ubuntu',
      sshKeyPath: '/home/node/.ssh/guardian_ed25519',
    });
  });

  it('getSnapshot returns an empty unavailable snapshot when called with no target and no key configured', async () => {
    config.hostSecurity.sshKeyPath = null;
    const snap = await HostSecurityService.getSnapshot(undefined, 24);
    expect(snap.available).toBe(false);
    expect(snap.serverName).toBe('local');
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd guardian && npx vitest run tests/host-security.test.ts
```

Expected: at least the first test FAILs with something like `expected "local" to be null` (because today `getDefaultTarget()` always returns a target). The second test should already PASS. The third test currently PASSes too (because the existing fallback returns the bad target and the SSH then fails) — but it depends on SSH attempts; if it actually tries to SSH it may behave unpredictably. Document the actual failure output before moving on; if the third test passes accidentally, that's fine — Task 3 makes it explicit.

- [ ] **Step 3: Commit (test only, intentionally failing)**

```bash
cd guardian
git add tests/host-security.test.ts
git commit -m "test: add failing tests for HostSecurityService opt-in behavior"
```

---

## Task 2: Make `getDefaultTarget()` return `SSHTarget | null`

**Files:**
- Modify: `guardian/src/services/host-security.service.ts:29-39`

- [ ] **Step 1: Edit `getDefaultTarget()` and `getSnapshot()` to handle null**

Replace lines 29–52 (the class header through the start of `getSnapshot`'s body) with:

```ts
export class HostSecurityService {
  /**
   * Returns a synthetic target representing the Guardian host itself.
   * Returns null when HOST_SSH_KEY_PATH is unset — opt-in via config.
   * Without a key path, SSH would fail anyway and produce log spam.
   */
  static getDefaultTarget(): SSHTarget | null {
    if (!config.hostSecurity.sshKeyPath) return null;
    return {
      id: 0,
      name: 'local',
      host: config.hostSecurity.sshHost,
      sshPort: config.hostSecurity.sshPort,
      sshUser: config.hostSecurity.sshUser,
      sshKeyPath: config.hostSecurity.sshKeyPath,
    };
  }

  static async getSnapshot(target?: SSHTarget, hours = 24): Promise<HostSecuritySnapshot> {
    const t = target ?? this.getDefaultTarget();
    const now = new Date();
    const from = new Date(Date.now() - hours * 3600 * 1000);

    const empty: HostSecuritySnapshot = {
      serverName: t?.name ?? 'local',
      bannedIpsNow: 0, jailCounts: {}, failedLoginsTotal: 0,
      failedLoginsByUser: [], failedLoginsByIp: [], successfulLogins: 0,
      blockedByPort: [], blockedTotal: 0, uniqueAttackerIps: 0,
      period: { from, to: now }, available: false,
    };

    if (!t) return empty;
```

The rest of the method body (the `try { ... } catch { ... }`) stays unchanged because `t` is now narrowed to `SSHTarget`.

- [ ] **Step 2: Run the test to verify it passes**

```bash
cd guardian && npx vitest run tests/host-security.test.ts
```

Expected: all 3 tests PASS.

- [ ] **Step 3: Run typecheck — make sure null narrowing works**

```bash
cd guardian && npm run type-check
```

Expected: zero TypeScript errors. If errors mention `getDefaultTarget()` returning `null`, see Task 3 — those callers need updating.

- [ ] **Step 4: Commit**

```bash
cd guardian
git add src/services/host-security.service.ts
git commit -m "feat: HostSecurityService.getDefaultTarget returns null when no key configured"
```

---

## Task 3: Failing test for `EventCollectorWorker` target list

**Files:**
- Create: `guardian/tests/event-collector.test.ts`

**Note:** `EventCollectorWorker.collect()` does ~20 things and is hard to test in isolation. We extract a small pure helper `buildCollectionTargets()` (Task 4) and test that. This step writes the failing test that drives the extraction.

- [ ] **Step 1: Write the failing test**

```ts
// guardian/tests/event-collector.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventCollectorWorker } from '../src/workers/event-collector.worker.js';
import { config } from '../src/config/environment.js';

describe('EventCollectorWorker.buildCollectionTargets', () => {
  const fakeServer = {
    id: 1,
    name: 'hetzner-prod',
    host: '172.26.0.1',
    sshPort: 49222,
    sshUser: 'root',
    sshKeyPath: '/home/node/.ssh/guardian_ed25519',
  };

  beforeEach(() => {
    config.hostSecurity = {
      sshHost: '127.0.0.1',
      sshPort: 22,
      sshUser: 'ubuntu',
      sshKeyPath: null,
    };
  });

  it('returns only registered servers when HOST_SSH_KEY_PATH is unset', () => {
    // Cast: ServerService.toSSHTarget expects a full server row with optional
    // tags/enabled/etc. The helper only reads id+name+host+ssh* — fakeServer is enough.
    const targets = EventCollectorWorker.buildCollectionTargets([fakeServer as never]);
    expect(targets).toHaveLength(1);
    expect(targets[0].name).toBe('hetzner-prod');
    expect(targets.find(t => t.name === 'local')).toBeUndefined();
  });

  it('appends the local pseudo-target when HOST_SSH_KEY_PATH is set', () => {
    config.hostSecurity.sshKeyPath = '/some/key';
    const targets = EventCollectorWorker.buildCollectionTargets([fakeServer as never]);
    expect(targets).toHaveLength(2);
    expect(targets.find(t => t.name === 'local')).toBeDefined();
  });

  it('returns just the local target when no DB servers and key is set', () => {
    config.hostSecurity.sshKeyPath = '/some/key';
    const targets = EventCollectorWorker.buildCollectionTargets([]);
    expect(targets).toHaveLength(1);
    expect(targets[0].name).toBe('local');
  });

  it('returns an empty list when no DB servers and no key', () => {
    const targets = EventCollectorWorker.buildCollectionTargets([]);
    expect(targets).toEqual([]);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd guardian && npx vitest run tests/event-collector.test.ts
```

Expected: FAIL with `EventCollectorWorker.buildCollectionTargets is not a function` (because the helper doesn't exist yet).

- [ ] **Step 3: Commit**

```bash
cd guardian
git add tests/event-collector.test.ts
git commit -m "test: add failing tests for EventCollectorWorker target list"
```

---

## Task 4: Extract `buildCollectionTargets()` and gate the local target

**Files:**
- Modify: `guardian/src/workers/event-collector.worker.ts:65-86`

- [ ] **Step 1: Add the static helper and use it in `collect()`**

In `event-collector.worker.ts`, add an import for `SSHTarget` if not present (it's already imported transitively, but be explicit):

```ts
import type { SSHTarget } from '../collectors/ssh-collector.js';
```

Then add this new method to the `EventCollectorWorker` class (before `collect`):

```ts
  /**
   * Build the list of SSH targets the event collector iterates over.
   * Includes all enabled DB servers, plus the Guardian host self-target
   * IFF HOST_SSH_KEY_PATH is configured (otherwise SSH would always fail).
   * Exposed as a public static for unit testing.
   */
  static buildCollectionTargets(
    servers: Array<Parameters<typeof ServerService.toSSHTarget>[0]>
  ): Array<{ id: number; name: string; target: SSHTarget }> {
    const fromDb = servers.map(s => ({
      id: s.id,
      name: s.name,
      target: ServerService.toSSHTarget(s),
    }));
    const guardianHost = HostSecurityService.getDefaultTarget();
    if (!guardianHost) return fromDb;
    return [...fromDb, { id: guardianHost.id, name: guardianHost.name, target: guardianHost }];
  }
```

Then in `collect()` (line 65–86), replace lines 78–84 with:

```ts
      const allTargets = this.buildCollectionTargets(servers);
```

(Remove the now-unused inline `guardianHost` construction and the manual `allTargets` array literal.)

- [ ] **Step 2: Run the test to verify it passes**

```bash
cd guardian && npx vitest run tests/event-collector.test.ts
```

Expected: all 4 tests PASS.

- [ ] **Step 3: Run the full test suite — make sure nothing else broke**

```bash
cd guardian && npm run test
```

Expected: PASS (count should be old-pass-count + 7 new passes, no failures, no skips beyond pre-existing).

- [ ] **Step 4: Run typecheck and lint**

```bash
cd guardian && npm run type-check && npm run lint
```

Expected: both green.

- [ ] **Step 5: Run the build to make sure tsup is happy**

```bash
cd guardian && npm run build
```

Expected: emits `dist/` cleanly. If the bundler complains about the generic on `buildCollectionTargets`, simplify the return type to use the same anonymous tuple shape as before — the test only inspects `name`/`id`, so the type doesn't need to be perfect.

- [ ] **Step 6: Commit**

```bash
cd guardian
git add src/workers/event-collector.worker.ts
git commit -m "feat: gate Guardian host self-target on HOST_SSH_KEY_PATH presence

The event collector unconditionally appended a synthetic 'local' target
to the iteration list, which on container deploys without an explicit
HOST_SSH_KEY_PATH would always fail SSH (defaults: 127.0.0.1:22 ubuntu)
and emit two warnings every 2 minutes. Now opt-in via config.

Extracted buildCollectionTargets() for unit testability.
"
```

---

## Task 5: Push and deploy

**Files:** none

- [ ] **Step 1: Push to origin**

```bash
cd guardian && git push origin main
```

Expected: push succeeds. Branch `main` advances by 4 commits (one per Task 1/2/3/4).

- [ ] **Step 2: Pull on Hetzner and rebuild only the guardian service**

```bash
ssh hetzner '
  cd /root/guardian \
  && git pull --ff-only \
  && docker compose up -d --build guardian
'
```

Expected: `git pull` reports the same 4 new commits; `docker compose` rebuilds the image and recreates only the `guardian` container; `guardian-db` and `guardian-trivy` stay untouched.

- [ ] **Step 3: Wait for healthy + verify warns are gone**

```bash
ssh hetzner '
  for i in 1 2 3 4 5 6; do
    sleep 30
    h=$(docker inspect guardian --format "{{.State.Health.Status}}" 2>/dev/null)
    echo "t=$((i*30))s health=$h"
    if [ "$h" = "healthy" ]; then break; fi
  done
'
```

Expected: container becomes `healthy` within 60–120s.

```bash
# Tail logs for 3 minutes and look for the offending warns
ssh hetzner 'timeout 200 docker logs -f guardian --tail 0 2>&1 | grep -E "server.*local.*(DNS|Sudo) log collection failed"' || true
```

Expected: **zero matches**. The command times out after 200s with empty output (timeout exits 124, which is fine — `|| true` swallows it).

If matches appear, the change didn't take. Rollback: `ssh hetzner 'cd /root/guardian && git reset --hard HEAD~4 && docker compose up -d --build guardian'` and investigate.

- [ ] **Step 4: Confirm event collection still works**

```bash
ssh hetzner 'docker logs guardian --tail 5 2>&1 | grep "Event collection cycle complete"'
```

Expected: at least one line within the last 2 minutes showing `events: <some-number>` and `servers: 1` (the `hetzner-prod` server, no longer counting `local`).

- [ ] **Step 5: Done — no commit needed; deploy verification only.**

---

## Risks & rollback

- **Risk:** The mock in `tests/setup.ts` is a factory that returns a plain object with `config`; mutating its properties from a test (`config.hostSecurity.sshKeyPath = '...'`) should propagate, but if the factory is invoked per import (Vitest behavior depends on setup), state can leak between tests. Mitigation: the `beforeEach` resets the slice; if isolation breaks, switch to per-test `vi.doMock` or read config via a getter.
- **Risk:** TypeScript narrowing on `target ?? this.getDefaultTarget()` may fail because `?? null` doesn't narrow to non-null after the `if (!t) return empty` guard in older `tsc` versions. Mitigation: assign to a fresh `const` after the guard: `const sshTarget = t!;` or split into two statements.
- **Risk:** Build emits the bundle but `dist/index.js` retains the old `getDefaultTarget` reference if tsup caches aggressively. Mitigation: `rm -rf guardian/dist && npm run build`.
- **Rollback (post-deploy):** `ssh hetzner 'cd /root/guardian && git reset --hard <prev-sha> && docker compose up -d --build guardian'`. The `<prev-sha>` is the parent of the first commit landed (Task 1). Capture it before pushing.

---

## Out of scope (intentionally)

- The 6 untracked files in `guardian/` (hardening plans + image docs + `scripts/poc-v2/`) — leave them alone, separate concern.
- Adding telemetry for the Trivy timeout on `jupyter/scipy-notebook` — separate fix.
- Rotating the AbuseIPDB key — pending user action.
- Deleting `~/Documents/study/guardian-blue-team/` — pending user confirmation.
- Re-enabling `synthfin`/`ovh-spark`/`ovh-automabothub` SOC servers — separate sessions.
