import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';

export interface OpenPort {
  port: number;
  protocol: string;
  process: string;
  pid: number;
}

export interface ActiveConnection {
  localAddr: string;
  remoteAddr: string;
  state: string;
  process: string;
}

export class NetworkCollector {
  static async collectListeningPorts(target: SSHTarget): Promise<OpenPort[]> {
    const result = await SSHCollector.run(target,
      "sudo ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4, $6}'",
      10_000
    );

    if (!result.success) return [];

    return result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(line => {
        const [addr, processInfo] = line.split(' ');
        const portMatch = addr?.match(/:(\d+)$/);
        const pidMatch = processInfo?.match(/pid=(\d+)/);
        const nameMatch = processInfo?.match(/\("([^"]+)"/);

        return {
          port: parseInt(portMatch?.[1] ?? '0'),
          protocol: 'tcp',
          process: nameMatch?.[1] ?? 'unknown',
          pid: parseInt(pidMatch?.[1] ?? '0'),
        };
      })
      .filter(p => p.port > 0);
  }

  static async collectEstablishedConnections(target: SSHTarget): Promise<ActiveConnection[]> {
    const result = await SSHCollector.run(target,
      "sudo ss -tnp state established 2>/dev/null | tail -n +2 | head -50 | awk '{print $4, $5, $6}'",
      10_000
    );

    if (!result.success) return [];

    return result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(line => {
        const parts = line.split(' ');
        return {
          localAddr: parts[0] ?? '',
          remoteAddr: parts[1] ?? '',
          state: 'established',
          process: parts[2] ?? '',
        };
      });
  }

  static async detectSuspiciousConnections(target: SSHTarget): Promise<RawLogEntry[]> {
    const result = await SSHCollector.run(target,
      "sudo ss -tnp state established 2>/dev/null | " +
      "awk '{print $5}' | grep -oP '[\\d.]+(?=:)' | " +
      "sort | uniq -c | sort -rn | head -5",
      10_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    const entries: RawLogEntry[] = [];
    for (const line of result.stdout.trim().split('\n').filter(Boolean)) {
      const match = line.trim().match(/^\s*(\d+)\s+([\d.]+)$/);
      if (match && parseInt(match[1]) > 20) {
        entries.push({
          serverId: target.id,
          serverName: target.name,
          source: 'network',
          timestamp: new Date(),
          line: `HIGH_CONN_COUNT: ${match[1]} connections from ${match[2]}`,
        });
      }
    }

    return entries;
  }
}
