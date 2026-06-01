import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SSHFingerprintService } from '../../src/services/ssh-fingerprint.service.js';

vi.mock('node:child_process', () => ({
  execFile: vi.fn(),
}));
vi.mock('node:fs/promises', () => ({
  writeFile: vi.fn().mockResolvedValue(undefined),
  mkdir: vi.fn().mockResolvedValue(undefined),
}));

import { execFile } from 'node:child_process';
import { db } from '../../src/database/connection.js';

const mockExecFile = execFile as unknown as ReturnType<typeof vi.fn>;

// Simulate promisify behaviour: execFile is called with (cmd, args, opts, callback).
// We make it call the last argument as callback(null, { stdout, stderr }).
function stubKeyscan(stdout: string) {
  mockExecFile.mockImplementation(
    (_cmd: string, _args: string[], _opts: unknown, cb: (err: null, r: { stdout: string }) => void) => {
      cb(null, { stdout });
    },
  );
}

const VALID_KEYSCAN_OUTPUT =
  '54.36.100.35 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBq9foobarBazQuuxdeadbeefAABBCCDDEEFF==\n';

describe('SSHFingerprintService.capture', () => {
  beforeEach(() => vi.clearAllMocks());

  it('parses ed25519 key and returns SHA256:<base64> format', async () => {
    stubKeyscan(VALID_KEYSCAN_OUTPUT);
    const fp = await SSHFingerprintService.capture('54.36.100.35', 22);
    expect(fp).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it('throws when no ed25519 key found', async () => {
    stubKeyscan('# no keys\n');
    await expect(SSHFingerprintService.capture('1.2.3.4', 22)).rejects.toThrow(
      'Could not capture ed25519 fingerprint',
    );
  });

  it('returns deterministic fingerprint for same key', async () => {
    stubKeyscan(VALID_KEYSCAN_OUTPUT);
    const fp1 = await SSHFingerprintService.capture('host', 22);
    stubKeyscan(VALID_KEYSCAN_OUTPUT);
    const fp2 = await SSHFingerprintService.capture('host', 22);
    expect(fp1).toBe(fp2);
  });
});

describe('SSHFingerprintService.persist', () => {
  it('calls db.update with the fingerprint', async () => {
    const fp = 'SHA256:abc123def456';
    await SSHFingerprintService.persist(7, fp);
    expect(db.update).toHaveBeenCalled();
  });
});

describe('SSHFingerprintService.writeKnownHostsFile', () => {
  it('calls ssh-keyscan and writes the file', async () => {
    stubKeyscan(VALID_KEYSCAN_OUTPUT);
    const { writeFile } = await import('node:fs/promises');
    await SSHFingerprintService.writeKnownHostsFile(5, '1.2.3.4', 22);
    expect(writeFile).toHaveBeenCalledWith(
      expect.stringContaining('guardian-5.known_hosts'),
      VALID_KEYSCAN_OUTPUT,
      expect.objectContaining({ mode: 0o600 }),
    );
  });
});
