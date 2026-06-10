import { describe, it, expect, beforeEach } from 'vitest';
import { EventCollectorWorker } from '../src/workers/event-collector.worker.js';
import { config } from '../src/config/environment.js';
import type { ServerInfo } from '../src/services/server.service.js';

describe('EventCollectorWorker.buildCollectionTargets', () => {
  const fakeServer: ServerInfo = {
    id: 1,
    name: 'hetzner-prod',
    host: '172.26.0.1',
    sshPort: 49222,
    sshUser: 'root',
    sshKeyPath: '/home/node/.ssh/guardian_ed25519',
    tags: ['production'],
    enabled: true,
    lastSeenAt: null,
    installMode: null,
    sshFingerprint: null,
    guardianShellVersion: null,
    upgradedAt: null,
    lastHeartbeatAt: null,
    osFamily: null,
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
    const targets = EventCollectorWorker.buildCollectionTargets([fakeServer]);
    expect(targets).toHaveLength(1);
    expect(targets[0].name).toBe('hetzner-prod');
    expect(targets.find(t => t.name === 'local')).toBeUndefined();
  });

  it('appends the local pseudo-target when HOST_SSH_KEY_PATH is set', () => {
    config.hostSecurity.sshKeyPath = '/some/key';
    const targets = EventCollectorWorker.buildCollectionTargets([fakeServer]);
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
