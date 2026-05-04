import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';
import type { RawLogEntry } from './log-collector.js';

export class SudoCollector {
  static async collect(target: SSHTarget, lookbackMinutes: number): Promise<RawLogEntry[]> {
    const command =
      `journalctl _COMM=sudo --since '${lookbackMinutes} min ago' --no-pager -o short-iso 2>/dev/null || ` +
      `grep -i sudo /var/log/auth.log | tail -100`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.warn({ server: target.name }, 'Sudo log collection failed via SSH');
      }
      return [];
    }

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 10)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'sudo',
        timestamp: this.parseTimestamp(line),
        line,
      }));
  }

  private static parseTimestamp(line: string): Date {
    // ISO format from journalctl -o short-iso: 2024-01-15T10:30:45+0000
    const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:?\d{2})/);
    if (isoMatch) return new Date(isoMatch[1]);

    // Syslog format: Jan 15 10:30:45
    const syslogMatch = line.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
    if (syslogMatch) {
      const year = new Date().getFullYear();
      return new Date(`${syslogMatch[1]} ${year}`);
    }

    return new Date();
  }
}
