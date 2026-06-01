import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';

interface AppLogSource {
  source: string;
  command: string;
}

const APP_LOG_SOURCES: AppLogSource[] = [
  {
    source: 'nginx_access',
    command: `sudo tail -n 100 /var/log/nginx/access.log 2>/dev/null || echo ''`,
  },
  {
    source: 'nginx_error',
    command: `sudo tail -n 100 /var/log/nginx/error.log 2>/dev/null || echo ''`,
  },
  {
    source: 'mysql_error',
    command: `sudo journalctl -u mysql -u mysqld -n 50 --no-pager 2>/dev/null || sudo tail -n 50 /var/log/mysql/error.log 2>/dev/null || echo ''`,
  },
  {
    source: 'postgres_log',
    command: `sudo journalctl -u postgresql -n 50 --no-pager 2>/dev/null || echo ''`,
  },
  {
    source: 'redis_log',
    command: `sudo journalctl -u redis -u redis-server -n 50 --no-pager 2>/dev/null || sudo tail -n 50 /var/log/redis/redis-server.log 2>/dev/null || echo ''`,
  },
];

export class AppLogCollector {
  static async collect(target: SSHTarget): Promise<RawLogEntry[]> {
    const results = await Promise.all(
      APP_LOG_SOURCES.map(src => this.collectSource(target, src)),
    );
    return results.flat();
  }

  private static async collectSource(target: SSHTarget, src: AppLogSource): Promise<RawLogEntry[]> {
    const result = await SSHCollector.run(target, src.command, 10_000);
    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 5)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: src.source,
        timestamp: this.parseTimestamp(line),
        line,
      }));
  }

  private static parseTimestamp(line: string): Date {
    // nginx: 15/Jan/2024:10:30:45 +0000
    const nginxMatch = line.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}:\d{2}:\d{2})/);
    if (nginxMatch) {
      const [, day, mon, year, time] = nginxMatch;
      const parsed = new Date(`${mon} ${day} ${year} ${time} UTC`);
      if (!isNaN(parsed.getTime())) return parsed;
    }
    // ISO or journalctl: 2024-01-15T10:30:45
    const isoMatch = line.match(/(\d{4}-\d{2}-\d{2}T[\d:.]+[+-Z][\d:]*)/);
    if (isoMatch) {
      const parsed = new Date(isoMatch[1]);
      if (!isNaN(parsed.getTime())) return parsed;
    }
    return new Date();
  }
}
