import { SSHCollector, type SSHTarget } from './ssh-collector.js';

export interface RawLogEntry {
  serverId: number;
  serverName: string;
  source: string;
  timestamp: Date;
  line: string;
}

export class LogCollector {
  static async collectAuthLogs(target: SSHTarget, sinceMinutes = 5): Promise<RawLogEntry[]> {
    const since = new Date(Date.now() - sinceMinutes * 60_000);
    const sinceStr = since.toISOString().replace('T', ' ').slice(0, 19);

    const result = await SSHCollector.run(target,
      `sudo journalctl -u ssh -u sshd --since '${sinceStr}' --no-pager -o short-iso 2>/dev/null || ` +
      `sudo tail -100 /var/log/auth.log 2>/dev/null || echo ''`,
      20_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 10)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'auth.log',
        timestamp: this.parseLogTimestamp(line),
        line,
      }));
  }

  static async collectUfwLogs(target: SSHTarget, sinceMinutes = 5): Promise<RawLogEntry[]> {
    const result = await SSHCollector.run(target,
      `sudo tail -200 /var/log/ufw.log 2>/dev/null || echo ''`,
      10_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    const cutoff = new Date(Date.now() - sinceMinutes * 60_000);

    return result.stdout.trim().split('\n')
      .filter(line => line.includes('[UFW'))
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'ufw',
        timestamp: this.parseLogTimestamp(line),
        line,
      }))
      .filter(entry => entry.timestamp >= cutoff);
  }

  static async collectDockerEvents(target: SSHTarget, sinceMinutes = 5): Promise<RawLogEntry[]> {
    const since = Math.floor((Date.now() - sinceMinutes * 60_000) / 1000);

    const result = await SSHCollector.run(target,
      `docker events --since ${since} --until $(date +%s) --format '{{.Time}} {{.Type}} {{.Action}} {{.Actor.Attributes.name}}' 2>/dev/null || echo ''`,
      10_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'docker',
        timestamp: new Date(),
        line,
      }));
  }

  private static parseLogTimestamp(line: string): Date {
    const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:?\d{2})/);
    if (isoMatch) return new Date(isoMatch[1]);

    const syslogMatch = line.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
    if (syslogMatch) {
      const year = new Date().getFullYear();
      return new Date(`${syslogMatch[1]} ${year}`);
    }

    return new Date();
  }
}
