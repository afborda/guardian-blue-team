import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';

export interface RawHealthMetrics {
  serverId: number;
  serverName: string;
  collectedAt: Date;
  load1: number;
  load5: number;
  load15: number;
  cpuCount: number;
  memTotalBytes: number;
  memUsedBytes: number;
  memAvailableBytes: number;
  swapTotalBytes: number;
  swapUsedBytes: number;
  disks: Array<{ mountpoint: string; usedPercent: number; availableBytes: number }>;
  uptimeSeconds: number;
}

export class HealthCollector {
  static async collect(target: SSHTarget): Promise<RawHealthMetrics | null> {
    const result = await SSHCollector.run(target, [
      'cat /proc/loadavg',
      'echo "---HSEP---"',
      'nproc',
      'echo "---HSEP---"',
      'free -b',
      'echo "---HSEP---"',
      'df --output=target,pcent,avail -x tmpfs -x devtmpfs 2>/dev/null || df -h',
      'echo "---HSEP---"',
      'cat /proc/uptime',
      'echo "---HSEP---"',
      'grep -E "SwapTotal|SwapFree" /proc/meminfo',
    ].join(' && '), 15_000);

    if (!result.success) {
      logger.debug({ server: target.name }, 'Health collection failed');
      return null;
    }

    try {
      return this.parse(target, result.stdout);
    } catch (err) {
      logger.debug({ server: target.name, err }, 'Health parsing failed');
      return null;
    }
  }

  private static parse(target: SSHTarget, stdout: string): RawHealthMetrics {
    const sections = stdout.split('---HSEP---').map(s => s.trim());

    const loadParts = sections[0].split(/\s+/);
    const load1 = parseFloat(loadParts[0]) || 0;
    const load5 = parseFloat(loadParts[1]) || 0;
    const load15 = parseFloat(loadParts[2]) || 0;

    const cpuCount = parseInt(sections[1]) || 1;

    const freeLine = sections[2].split('\n').find(l => l.startsWith('Mem:'));
    let memTotalBytes = 0, memUsedBytes = 0, memAvailableBytes = 0;
    if (freeLine) {
      const parts = freeLine.split(/\s+/);
      memTotalBytes = parseInt(parts[1]) || 0;
      memUsedBytes = parseInt(parts[2]) || 0;
      memAvailableBytes = parseInt(parts[6]) || (memTotalBytes - memUsedBytes);
    }

    const diskLines = sections[3].split('\n').filter(l => l.trim() && !l.startsWith('Mounted') && !l.startsWith('Filesystem'));
    const disks = diskLines.map(line => {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 3) {
        return {
          mountpoint: parts[0],
          usedPercent: parseInt(parts[1]) || 0,
          availableBytes: this.parseSize(parts[2]),
        };
      }
      return null;
    }).filter((d): d is NonNullable<typeof d> => d !== null);

    const uptimeParts = sections[4].split(/\s+/);
    const uptimeSeconds = Math.floor(parseFloat(uptimeParts[0]) || 0);

    let swapTotalBytes = 0, swapUsedBytes = 0;
    const swapLines = sections[5]?.split('\n') ?? [];
    for (const line of swapLines) {
      const match = line.match(/(\w+):\s+(\d+)\s+kB/);
      if (match) {
        const kb = parseInt(match[2]) * 1024;
        if (match[1] === 'SwapTotal') swapTotalBytes = kb;
        if (match[1] === 'SwapFree') swapUsedBytes = swapTotalBytes - kb;
      }
    }
    if (swapUsedBytes < 0) swapUsedBytes = 0;

    return {
      serverId: target.id,
      serverName: target.name,
      collectedAt: new Date(),
      load1, load5, load15, cpuCount,
      memTotalBytes, memUsedBytes, memAvailableBytes,
      swapTotalBytes, swapUsedBytes,
      disks,
      uptimeSeconds,
    };
  }

  private static parseSize(str: string): number {
    const num = parseFloat(str);
    if (isNaN(num)) return 0;
    if (str.endsWith('G')) return num * 1024 * 1024 * 1024;
    if (str.endsWith('M')) return num * 1024 * 1024;
    if (str.endsWith('K')) return num * 1024;
    return num;
  }
}
