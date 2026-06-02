import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../src/collectors/ssh-collector.js', () => ({
  SSHCollector: {
    run: vi.fn(),
    buildArgs: vi.fn().mockReturnValue(['-o', 'BatchMode=yes', '-p', '22', 'guardian@host']),
  },
}));

vi.mock('../../src/services/server.service.js', () => ({
  ServerService: {
    toSSHTarget: vi.fn((s) => ({
      id: s.id,
      name: s.name,
      host: s.host,
      sshPort: s.sshPort,
      sshUser: s.sshUser,
      sshKeyPath: s.sshKeyPath,
      installMode: s.installMode,
      sshFingerprint: s.sshFingerprint,
    })),
    getEnabled: vi.fn(),
  },
}));

vi.mock('../../src/security/guardian-shell-version.js', () => ({
  EXPECTED_SHELL_VERSION: 'bf89f0ceb434f0c5',
}));

vi.mock('node:fs', () => ({
  existsSync: vi.fn().mockReturnValue(true),
  readFileSync: vi.fn().mockReturnValue('#!/usr/bin/env bash\n# guardian-shell content\necho ok\n'),
}));

vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));

vi.mock('node:util', () => ({
  promisify: (fn: unknown) => fn,
}));

import { SSHCollector } from '../../src/collectors/ssh-collector.js';
import { ServerService } from '../../src/services/server.service.js';
import { GuardianShellSyncService } from '../../src/services/guardian-shell-sync.service.js';
import { GuardianShellSyncWorker } from '../../src/workers/guardian-shell-sync.worker.js';
import type { ServerInfo } from '../../src/services/server.service.js';

const mockServer: ServerInfo = {
  id: 5,
  name: 'server-1',
  host: 'OVH_IP_1',
  sshPort: 49222,
  sshUser: 'guardian',
  sshKeyPath: '/data/ssh/guardian-5.key',
  installMode: 'guardian',
  sshFingerprint: 'SHA256:abc123',
  tags: [],
  enabled: true,
  lastSeenAt: null,
  guardianShellVersion: null,
  upgradedAt: null,
  lastHeartbeatAt: null,
  osFamily: 'debian',
};

const mockLegacyServer: ServerInfo = {
  ...mockServer,
  id: 7,
  name: 'legacy-server',
  installMode: 'legacy',
};

describe('GuardianShellSyncService.check()', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('retorna already_current quando versão remota bate com EXPECTED_SHELL_VERSION', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue({
      stdout: "VERSION='bf89f0ceb434f0c5'\n",
      success: true,
      durationMs: 50,
    });

    const result = await GuardianShellSyncService.check(mockServer);

    expect(result.action).toBe('already_current');
    expect(result.fromVersion).toBe('bf89f0ceb434f0c5');
    expect(result.toVersion).toBe('bf89f0ceb434f0c5');
    expect(result.serverId).toBe(5);
    expect(result.serverName).toBe('server-1');
  });

  it('retorna already_current para VERSION sem aspas', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue({
      stdout: 'VERSION=bf89f0ceb434f0c5\n',
      success: true,
      durationMs: 30,
    });

    const result = await GuardianShellSyncService.check(mockServer);
    expect(result.action).toBe('already_current');
  });

  it('chama reinstall e retorna updated quando versão difere', async () => {
    vi.mocked(SSHCollector.run)
      .mockResolvedValueOnce({ stdout: "VERSION='2.0.0'\n", success: true, durationMs: 40 })
      .mockResolvedValueOnce({ stdout: 'ok\n', success: true, durationMs: 20 });

    const { execFile } = await import('node:child_process');
    vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, cb) => {
      if (cb) cb(null, '', '');
      return {} as ReturnType<typeof execFile>;
    });

    const result = await GuardianShellSyncService.check(mockServer);

    expect(result.action).toBe('updated');
    expect(result.fromVersion).toBe('2.0.0');
    expect(result.toVersion).toBe('bf89f0ceb434f0c5');
  });

  it('retorna failed quando SSH falha na verificação', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue({
      stdout: '',
      success: false,
      durationMs: 200,
      error: 'Connection refused',
    });

    const result = await GuardianShellSyncService.check(mockServer);

    expect(result.action).toBe('failed');
    expect(result.error).toBe('Connection refused');
    expect(result.fromVersion).toBeNull();
  });
});

describe('GuardianShellSyncService — VERSION=unknown', () => {
  beforeEach(() => vi.clearAllMocks());

  it('trata VERSION=unknown como versão nula (drift → reinstala)', async () => {
    vi.mocked(SSHCollector.run)
      .mockResolvedValueOnce({ stdout: "VERSION=unknown\n", success: true, durationMs: 30 })
      .mockResolvedValueOnce({ stdout: 'ok\n', success: true, durationMs: 20 });

    const { execFile } = await import('node:child_process');
    vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, cb) => {
      if (cb) cb(null, '', '');
      return {} as ReturnType<typeof execFile>;
    });

    const result = await GuardianShellSyncService.check(mockServer);
    expect(result.action).toBe('updated');
    expect(result.fromVersion).toBeNull();
  });
});

describe('GuardianShellSyncService.reinstall() — smoke-test falha', () => {
  beforeEach(() => vi.clearAllMocks());

  it('retorna failed sem lançar quando smoke-test retorna valor errado', async () => {
    vi.mocked(SSHCollector.run)
      .mockResolvedValueOnce({ stdout: "VERSION='2.0.0'\n", success: true, durationMs: 30 })
      .mockResolvedValueOnce({ stdout: 'BLOCKED\n', success: false, durationMs: 20, error: 'exit 126' });

    const { execFile } = await import('node:child_process');
    vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, cb) => {
      if (cb) cb(null, '', '');
      return {} as ReturnType<typeof execFile>;
    });

    const result = await GuardianShellSyncService.check(mockServer);

    expect(result.action).toBe('failed');
    expect(result.error).toBeDefined();
  });

  it('retorna failed sem lançar quando execFile falha no heredoc', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue({
      stdout: "VERSION='old'\n",
      success: true,
      durationMs: 30,
    });

    const { execFile } = await import('node:child_process');
    vi.mocked(execFile).mockImplementation((_cmd, _args, _opts, cb) => {
      if (cb) cb(new Error('SSH timeout'), '', '');
      return {} as ReturnType<typeof execFile>;
    });

    const result = await GuardianShellSyncService.check(mockServer);

    expect(result.action).toBe('failed');
    expect(() => GuardianShellSyncService.check(mockServer)).not.toThrow();
  });
});

describe('GuardianShellSyncWorker', () => {
  beforeEach(() => vi.clearAllMocks());

  it('não processa servidores com installMode !== guardian', async () => {
    vi.mocked(ServerService.getEnabled).mockResolvedValue([mockLegacyServer]);
    const checkSpy = vi.spyOn(GuardianShellSyncService, 'check');

    // Aciona sync diretamente via método privado
    await (GuardianShellSyncWorker as unknown as { sync(): Promise<void> }).sync?.();

    expect(checkSpy).not.toHaveBeenCalled();
  });

  it('chama check() para cada servidor guardian', async () => {
    vi.mocked(ServerService.getEnabled).mockResolvedValue([mockServer]);
    vi.spyOn(GuardianShellSyncService, 'check').mockResolvedValue({
      serverId: 5,
      serverName: 'server-1',
      action: 'already_current',
      fromVersion: 'bf89f0ceb434f0c5',
      toVersion: 'bf89f0ceb434f0c5',
      durationMs: 50,
    });

    await (GuardianShellSyncWorker as unknown as { sync(): Promise<void> }).sync?.();

    expect(GuardianShellSyncService.check).toHaveBeenCalledWith(mockServer);
  });
});
