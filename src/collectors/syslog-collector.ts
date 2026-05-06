import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';
import type { RawLogEntry } from './log-collector.js';

export class SyslogCollector {
  static async collect(target: SSHTarget, lookbackMinutes: number): Promise<RawLogEntry[]> {
    const minutes = Math.max(1, Math.floor(Math.abs(lookbackMinutes)));
    const command =
      `journalctl --since '${minutes} min ago' -p err..emerg --no-pager -o short-iso 2>/dev/null | head -200`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.debug({ server: target.name }, 'Syslog collection failed via SSH');
      }
      return [];
    }

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 10)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'syslog',
        timestamp: this.parseTimestamp(line),
        line,
      }));
  }

  private static parseTimestamp(line: string): Date {
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
