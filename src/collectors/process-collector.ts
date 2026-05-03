import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';

export interface ProcessInfo {
  pid: number;
  user: string;
  cpu: number;
  mem: number;
  command: string;
}

export class ProcessCollector {
  static async collectTopProcesses(target: SSHTarget): Promise<ProcessInfo[]> {
    const result = await SSHCollector.run(target,
      "ps aux --sort=-%cpu 2>/dev/null | head -15 | tail -n +2 | awk '{print $2, $1, $3, $4, $11}'",
      10_000
    );

    if (!result.success) return [];

    return result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(line => {
        const [pid, user, cpu, mem, ...cmdParts] = line.split(' ');
        return {
          pid: parseInt(pid ?? '0'),
          user: user ?? '',
          cpu: parseFloat(cpu ?? '0'),
          mem: parseFloat(mem ?? '0'),
          command: cmdParts.join(' ') || '',
        };
      });
  }

  static async detectSuspiciousProcesses(target: SSHTarget): Promise<RawLogEntry[]> {
    const suspiciousPatterns = [
      'xmrig', 'minerd', 'cpuminer', 'cryptonight',
      'kinsing', 'kdevtmpfsi', 'ld-linux',
      'masscan', 'nmap', 'hydra', 'john',
      '.hidden', '/tmp/\\.', '/dev/shm/',
    ];

    const grepPattern = suspiciousPatterns.join('\\|');

    const result = await SSHCollector.run(target,
      `ps aux 2>/dev/null | grep -i '${grepPattern}' | grep -v grep || echo ''`,
      10_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'process',
        timestamp: new Date(),
        line: `SUSPICIOUS_PROCESS: ${line.trim()}`,
      }));
  }

  static async detectHighCPU(target: SSHTarget, thresholdPercent = 90): Promise<RawLogEntry[]> {
    const result = await SSHCollector.run(target,
      `ps aux --sort=-%cpu 2>/dev/null | awk '$3 > ${thresholdPercent} {print}' | head -5`,
      10_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'process',
        timestamp: new Date(),
        line: `HIGH_CPU: ${line.trim()}`,
      }));
  }
}
