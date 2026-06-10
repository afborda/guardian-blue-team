import { describe, it, expect, beforeEach } from 'vitest';
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
