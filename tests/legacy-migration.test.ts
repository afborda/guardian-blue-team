import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../src/services/server.service.js', () => ({
  ServerService: {
    getEnabled: vi.fn(),
  },
}));
vi.mock('../src/services/server-upgrade.service.js', () => ({
  ServerUpgradeService: {
    upgrade: vi.fn(),
  },
}));
// suppress Telegram fetch calls
vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));

import { ServerService } from '../src/services/server.service.js';
import { ServerUpgradeService } from '../src/services/server-upgrade.service.js';
import { LegacyMigrationWorker } from '../src/workers/legacy-migration.worker.js';

const legacyServer = {
  id: 5, name: 'server-1', host: 'OVH_IP_1', sshPort: 22,
  sshUser: 'ubuntu', sshKeyPath: '/data/key.pem',
  installMode: null as null, enabled: true,
  tags: [], lastSeenAt: null, falcoInstalledAt: null,
  sshFingerprint: null, guardianShellVersion: null,
  upgradedAt: null, lastHeartbeatAt: null, osFamily: 'ubuntu', createdAt: new Date(),
};

const guardianServer = { ...legacyServer, id: 6, name: 'ovh-auto', installMode: 'guardian' as const };

describe('LegacyMigrationWorker.runCycle', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('skips when LEGACY_MIGRATION_ENABLED=false (default in tests)', async () => {
    vi.mocked(ServerService.getEnabled).mockResolvedValue([legacyServer]);
    await LegacyMigrationWorker.runCycle();
    expect(ServerUpgradeService.upgrade).not.toHaveBeenCalled();
  });
});

describe('LegacyMigrationWorker.upgradeOne', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls upgrade and notifies success', async () => {
    vi.mocked(ServerUpgradeService.upgrade).mockResolvedValue({
      success: true, serverId: 5, rolledBack: false,
      steps: [{ name: 'pre-flight', status: 'ok', durationMs: 10 }],
      totalDurationMs: 500,
    });

    await LegacyMigrationWorker.upgradeOne(legacyServer);

    expect(ServerUpgradeService.upgrade).toHaveBeenCalledWith(legacyServer);
    // Two Telegram messages: "iniciando" + "✅ migrado"
    expect(global.fetch).toHaveBeenCalledTimes(2);
    const body = JSON.parse((vi.mocked(global.fetch).mock.calls[1][1] as RequestInit).body as string);
    expect(body.text).toContain('✅');
    expect(body.text).toContain('server-1');
  });

  it('notifies failure and includes error when upgrade fails', async () => {
    vi.mocked(ServerUpgradeService.upgrade).mockResolvedValue({
      success: false, serverId: 5, rolledBack: true,
      steps: [
        { name: 'pre-flight', status: 'ok', durationMs: 5 },
        { name: 'create-guardian-user', status: 'failed', durationMs: 3, detail: 'SSH_ERROR' },
      ],
      totalDurationMs: 100,
      error: 'create-guardian-user failed',
    });

    await LegacyMigrationWorker.upgradeOne(legacyServer);

    expect(global.fetch).toHaveBeenCalledTimes(2);
    const body = JSON.parse((vi.mocked(global.fetch).mock.calls[1][1] as RequestInit).body as string);
    expect(body.text).toContain('❌');
    expect(body.text).toContain('rollback aplicado');
    expect(body.text).toContain('SSH_ERROR');
  });

  it('notifies failure without rollback marker when rolledBack=false', async () => {
    vi.mocked(ServerUpgradeService.upgrade).mockResolvedValue({
      success: false, serverId: 5, rolledBack: false,
      steps: [{ name: 'pre-flight', status: 'failed', durationMs: 5 }],
      totalDurationMs: 10,
      error: 'pre-flight failed',
    });

    await LegacyMigrationWorker.upgradeOne(legacyServer);

    const body = JSON.parse((vi.mocked(global.fetch).mock.calls[1][1] as RequestInit).body as string);
    expect(body.text).not.toContain('rollback');
  });
});
