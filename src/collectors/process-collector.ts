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

  // Process names (comm field — executable basename, max 15 chars on Linux)
  // Matched as exact lowercase tokens against `comm` to avoid self-detection
  // when the SSH command itself contains these strings as arguments.
  private static readonly suspiciousProcessNames = [
    'xmrig', 'minerd', 'cpuminer', 'cryptonight',
    'kinsing', 'kdevtmpfsi',
    'masscan', 'nmap', 'hydra', 'john',
  ];

  // Path indicators (matched against full cmdline `args`).
  // These signal a process executing from a suspicious location regardless
  // of binary name — common malware persistence pattern.
  private static readonly suspiciousPathPatterns = [
    '/tmp/\\.',      // hidden file under /tmp
    '/dev/shm/',     // tmpfs execution
    '/var/tmp/\\.',  // hidden under /var/tmp
  ];

  static async detectSuspiciousProcesses(target: SSHTarget): Promise<RawLogEntry[]> {
    const nameAlt = this.suspiciousProcessNames.join('|');
    const pathAlt = this.suspiciousPathPatterns.join('|');

    // Pass 1: match by `comm` field (executable name).
    // $$ is the PID of the remote shell running this command — we exclude it
    // and its parent (ssh-spawned bash) so the collector never matches itself.
    const namePass = await SSHCollector.run(target,
      `ps -eo pid,ppid,user,pcpu,pmem,comm,args --no-headers 2>/dev/null | ` +
      `awk -v self=$$ -v parent=$PPID '` +
      `$1 != self && $2 != self && $1 != parent && ` +
      `tolower($6) ~ /^(${nameAlt})$/ { print }'`,
      10_000
    );

    // Pass 2: match by full cmdline against suspicious path indicators.
    // Exclude shell utilities themselves (grep/awk/sh/bash) which may carry
    // the pattern as a literal argument in their command line.
    const pathPass = await SSHCollector.run(target,
      `ps -eo pid,ppid,user,pcpu,pmem,comm,args --no-headers 2>/dev/null | ` +
      `awk -v self=$$ -v parent=$PPID '` +
      `$1 != self && $2 != self && $1 != parent && ` +
      `$6 !~ /^(awk|grep|sed|sh|bash|dash|zsh)$/ && ` +
      `$0 ~ /(${pathAlt})/ { print }'`,
      10_000
    );

    const lines = [
      ...(namePass.success ? namePass.stdout.trim().split('\n') : []),
      ...(pathPass.success ? pathPass.stdout.trim().split('\n') : []),
    ].filter(Boolean);

    if (lines.length === 0) return [];

    return lines.map(line => ({
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
