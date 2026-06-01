import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/collectors/ssh-collector.js', () => ({
  SSHCollector: {
    run: vi.fn(),
    runMulti: vi.fn(),
    isReachable: vi.fn(),
  },
}));
vi.mock('../../src/services/ssh-fingerprint.service.js', () => ({
  SSHFingerprintService: {
    capture: vi.fn().mockResolvedValue('SHA256:testfingerprint123'),
    writeKnownHostsFile: vi.fn().mockResolvedValue(undefined),
    persist: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock('../../src/utils/ssh-keygen.js', () => ({
  generateED25519KeyPair: vi.fn().mockResolvedValue({
    publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5test',
    privateKeyPath: '/data/ssh/guardian-1.key',
    publicKeyPath: '/data/ssh/guardian-1.key.pub',
  }),
}));
vi.mock('node:fs/promises', () => ({
  readFile: vi.fn().mockResolvedValue('#!/bin/bash\necho guardian-shell'),
  writeFile: vi.fn(),
  mkdir: vi.fn(),
}));

import { SSHCollector } from '../../src/collectors/ssh-collector.js';
import { ServerUpgradeService } from '../../src/services/server-upgrade.service.js';
import { db } from '../../src/database/connection.js';
import type { ServerInfo } from '../../src/services/server.service.js';

const mockServer: ServerInfo = {
  id: 1,
  name: 'test-server',
  host: '10.0.0.1',
  sshPort: 22,
  sshUser: 'ubuntu',
  sshKeyPath: '/data/key.pem',
  tags: [],
  enabled: true,
  lastSeenAt: null,
  falcoInstalledAt: null,
  installMode: null,
  sshFingerprint: null,
  guardianShellVersion: null,
  upgradedAt: null,
  lastHeartbeatAt: null,
  osFamily: 'ubuntu',
  createdAt: new Date(),
};

const sshOk = { stdout: 'ok', success: true, durationMs: 10 };
const sshFail = { stdout: '', success: false, durationMs: 10, error: 'SSH_ERROR' };
const guardianNoTemplate = { stdout: '', success: false, durationMs: 5, error: 'GUARDIAN_NO_TEMPLATE' };

function mockRunSequence(responses: Array<typeof sshOk>) {
  const mock = vi.mocked(SSHCollector.run);
  mock.mockReset();
  responses.forEach((r) => mock.mockResolvedValueOnce(r));
}

describe('ServerUpgradeService.upgrade — happy path', () => {
  beforeEach(() => vi.clearAllMocks());

  it('completes all 10 steps and persists upgrade in DB', async () => {
    // pre-flight, create-user, install-pubkey, install-shell, install-sudoers,
    // patch-allowusers (check + sed), smoke echo ok, smoke allowed cmd, smoke blocked cmd, cleanup
    mockRunSequence([
      { stdout: 'NAME=Ubuntu', success: true, durationMs: 20 }, // pre-flight
      sshOk,   // create-guardian-user
      sshOk,   // install-pubkey
      sshOk,   // install-guardian-shell
      sshOk,   // install-sudoers
      { stdout: 'AllowUsers ubuntu', success: true, durationMs: 5 }, // patch-allowusers: check
      sshOk,   // patch-allowusers: sed + reload
      { stdout: 'ok\n', success: true, durationMs: 5 },  // smoke: echo ok
      sshOk,   // smoke: allowed cmd
      guardianNoTemplate, // smoke: blocked cmd
      sshOk,   // cleanup
    ]);

    const result = await ServerUpgradeService.upgrade(mockServer);

    expect(result.success).toBe(true);
    expect(result.rolledBack).toBe(false);
    expect(db.update).toHaveBeenCalled();
    const okSteps = result.steps.filter((s) => s.status === 'ok');
    expect(okSteps.length).toBeGreaterThanOrEqual(9);
  });
});

describe('ServerUpgradeService.upgrade — pre-flight failure', () => {
  beforeEach(() => vi.clearAllMocks());

  it('aborts immediately without rollback when pre-flight fails', async () => {
    mockRunSequence([sshFail]);
    const result = await ServerUpgradeService.upgrade(mockServer);
    expect(result.success).toBe(false);
    expect(result.rolledBack).toBe(false);
    expect(result.steps[0].name).toBe('pre-flight');
    expect(result.steps[0].status).toBe('failed');
    expect(db.update).not.toHaveBeenCalled();
  });
});

describe('ServerUpgradeService.upgrade — smoke test failure', () => {
  beforeEach(() => vi.clearAllMocks());

  it('triggers rollback when smoke test fails', async () => {
    mockRunSequence([
      { stdout: 'NAME=Ubuntu', success: true, durationMs: 20 }, // pre-flight
      sshOk,   // create-guardian-user (marks guardianUserCreated)
      sshOk,   // install-pubkey
      sshOk,   // install-guardian-shell (marks guardianShellInstalled)
      sshOk,   // install-sudoers (marks sudoersInstalled)
      { stdout: '', success: true, durationMs: 5 }, // patch-allowusers: check (no AllowUsers line)
      sshFail, // smoke: echo ok fails → triggers rollback
      // rollback calls: rm sudoers, rm shell, userdel (allowUserPatched=false so no sed)
      sshOk, sshOk, sshOk,
    ]);

    const result = await ServerUpgradeService.upgrade(mockServer);
    expect(result.success).toBe(false);
    expect(result.rolledBack).toBe(true);
    expect(db.update).not.toHaveBeenCalled();

    // Rollback should have run 3 cleanup commands
    const totalCalls = vi.mocked(SSHCollector.run).mock.calls.length;
    expect(totalCalls).toBeGreaterThan(5);
  });
});

describe('ServerUpgradeService.rollback', () => {
  beforeEach(() => vi.clearAllMocks());

  it('runs all 3 cleanup commands when all flags are set', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue(sshOk);
    const target = { id: 1, name: 'test', host: '10.0.0.1', sshPort: 22, sshUser: 'ubuntu', sshKeyPath: null };
    await ServerUpgradeService.rollback(target, {
      guardianUserCreated: true,
      guardianShellInstalled: true,
      sudoersInstalled: true,
      allowUserPatched: false,
    });
    expect(SSHCollector.run).toHaveBeenCalledTimes(3);
  });

  it('skips commands for flags that are false', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue(sshOk);
    const target = { id: 1, name: 'test', host: '10.0.0.1', sshPort: 22, sshUser: 'ubuntu', sshKeyPath: null };
    await ServerUpgradeService.rollback(target, {
      guardianUserCreated: false,
      guardianShellInstalled: true,
      sudoersInstalled: false,
      allowUserPatched: false,
    });
    expect(SSHCollector.run).toHaveBeenCalledTimes(1);
  });

  it('also reverts AllowUsers when allowUserPatched is true', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue(sshOk);
    const target = { id: 1, name: 'test', host: '10.0.0.1', sshPort: 22, sshUser: 'ubuntu', sshKeyPath: null };
    await ServerUpgradeService.rollback(target, {
      guardianUserCreated: true,
      guardianShellInstalled: true,
      sudoersInstalled: true,
      allowUserPatched: true,
    });
    expect(SSHCollector.run).toHaveBeenCalledTimes(4);
  });
});
