import { describe, it, expect, vi, beforeEach } from 'vitest';
import { HealthCollector } from '../src/collectors/health-collector.js';
import { SystemCollector } from '../src/collectors/system-collector.js';
import { PerformanceCollector } from '../src/collectors/performance-collector.js';

vi.mock('../src/collectors/ssh-collector.js', () => ({
  SSHCollector: {
    run: vi.fn(),
    runMulti: vi.fn(),
  },
}));

vi.mock('../src/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { SSHCollector } from '../src/collectors/ssh-collector.js';

const mockTarget = { id: 1, name: 'test-srv', host: '10.0.0.1', sshPort: 22, sshUser: 'ubuntu', sshKeyPath: null };

describe('HealthCollector', () => {
  beforeEach(() => vi.clearAllMocks());

  it('parses valid health output', async () => {
    const stdout = [
      '0.52 0.48 0.41 2/234 12345',
      '---HSEP---',
      '4',
      '---HSEP---',
      '              total        used        free      shared  buff/cache   available\nMem:     8000000000  3000000000  2000000000   100000000  3000000000  4500000000\nSwap:    2000000000   500000000  1500000000',
      '---HSEP---',
      'Mounted on  Use% Avail\n/           45%  50G\n/data       72%  100G',
      '---HSEP---',
      '86400.55 172000.12',
      '---HSEP---',
      'SwapTotal:       1953124 kB\nSwapFree:        1453124 kB',
    ].join('\n');

    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout, success: true, durationMs: 200 });

    const result = await HealthCollector.collect(mockTarget);

    expect(result).not.toBeNull();
    expect(result!.load1).toBe(0.52);
    expect(result!.load5).toBe(0.48);
    expect(result!.load15).toBe(0.41);
    expect(result!.cpuCount).toBe(4);
    expect(result!.memTotalBytes).toBe(8000000000);
    expect(result!.memUsedBytes).toBe(3000000000);
    expect(result!.memAvailableBytes).toBe(4500000000);
    expect(result!.uptimeSeconds).toBe(86400);
    expect(result!.disks).toHaveLength(2);
    expect(result!.disks[0].mountpoint).toBe('/');
    expect(result!.disks[0].usedPercent).toBe(45);
  });

  it('returns null on SSH failure', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout: '', success: false, durationMs: 100 });
    const result = await HealthCollector.collect(mockTarget);
    expect(result).toBeNull();
  });

  it('returns null on parse error', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout: 'garbage', success: true, durationMs: 100 });
    const result = await HealthCollector.collect(mockTarget);
    expect(result).toBeNull();
  });
});

describe('SystemCollector', () => {
  beforeEach(() => vi.clearAllMocks());

  it('parses valid system output', async () => {
    const stdout = [
      '2024-01-15T10:30:00+0000 kernel: Out of memory: Killed process 1234\n2024-01-15T10:31:00+0000 kernel: ext4 error on /dev/sda1',
      '---SSEP---',
      'Jan 15 10:30:00 server systemd[1]: Failed to start Docker\nJan 15 10:31:00 server nginx[999]: error reading upstream',
      '---SSEP---',
      '● docker.service loaded failed failed Docker\n● nginx.service loaded failed failed Nginx',
    ].join('\n');

    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout, success: true, durationMs: 150 });

    const result = await SystemCollector.collect(mockTarget);

    expect(result).not.toBeNull();
    expect(result!.kernelErrors).toHaveLength(2);
    expect(result!.kernelErrors[0].message).toContain('Out of memory');
    expect(result!.journalErrors).toHaveLength(2);
    expect(result!.failedUnits).toContain('docker.service');
    expect(result!.failedUnits).toContain('nginx.service');
  });

  it('returns null on SSH failure', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout: '', success: false, durationMs: 100 });
    const result = await SystemCollector.collect(mockTarget);
    expect(result).toBeNull();
  });

  it('handles empty sections gracefully', async () => {
    const stdout = '---SSEP---\n---SSEP---\n';
    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout, success: true, durationMs: 100 });

    const result = await SystemCollector.collect(mockTarget);
    expect(result).not.toBeNull();
    expect(result!.kernelErrors).toHaveLength(0);
    expect(result!.journalErrors).toHaveLength(0);
    expect(result!.failedUnits).toHaveLength(0);
  });
});

describe('PerformanceCollector', () => {
  beforeEach(() => vi.clearAllMocks());

  it('computes disk and network deltas', async () => {
    const diskBefore = '   8       0 sda 100 0 2000 0 50 0 1000 0 0 0 0 0 0 0 0';
    const diskAfter  = '   8       0 sda 110 0 4000 0 60 0 3000 0 0 0 0 0 0 0 0';
    const netBefore  = '  eth0: 1000000 100 0 0 0 0 0 0 500000 50 0 0 0 0 0 0';
    const netAfter   = '  eth0: 1010000 110 0 0 0 0 0 0 505000 55 0 0 0 0 0 0';

    const stdout = [
      diskBefore,
      '---PSEP---',
      'Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n' + netBefore,
      '---PSEP---',
      '',
      '---PSEP---',
      diskAfter,
      '---PSEP---',
      'Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n' + netAfter,
    ].join('\n');

    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout, success: true, durationMs: 1200 });

    const result = await PerformanceCollector.collect(mockTarget);

    expect(result).not.toBeNull();
    expect(result!.diskIo.length).toBeGreaterThan(0);
    const sda = result!.diskIo.find(d => d.device === 'sda');
    expect(sda).toBeDefined();
    expect(sda!.readBps).toBe((4000 - 2000) * 512);
    expect(sda!.writeBps).toBe((3000 - 1000) * 512);
  });

  it('returns null on SSH failure', async () => {
    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout: '', success: false, durationMs: 100 });
    const result = await PerformanceCollector.collect(mockTarget);
    expect(result).toBeNull();
  });

  it('excludes loop devices', async () => {
    const diskBefore = '   7       0 loop0 100 0 2000 0 50 0 1000 0 0 0 0 0 0 0 0\n   8       0 sda 100 0 2000 0 50 0 1000 0 0 0 0 0 0 0 0';
    const diskAfter  = '   7       0 loop0 110 0 4000 0 60 0 3000 0 0 0 0 0 0 0 0\n   8       0 sda 110 0 4000 0 60 0 3000 0 0 0 0 0 0 0 0';

    const stdout = [
      diskBefore,
      '---PSEP---',
      '',
      '---PSEP---',
      '',
      '---PSEP---',
      diskAfter,
      '---PSEP---',
      '',
    ].join('\n');

    vi.mocked(SSHCollector.run).mockResolvedValue({ stdout, success: true, durationMs: 1200 });

    const result = await PerformanceCollector.collect(mockTarget);
    expect(result).not.toBeNull();
    expect(result!.diskIo.find(d => d.device === 'loop0')).toBeUndefined();
    expect(result!.diskIo.find(d => d.device === 'sda')).toBeDefined();
  });
});
