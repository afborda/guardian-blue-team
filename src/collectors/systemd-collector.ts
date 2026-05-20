import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';
import type { RawLogEntry } from './log-collector.js';

export class SystemdCollector {
  static async collect(target: SSHTarget, lookbackMinutes: number): Promise<RawLogEntry[]> {
    const minutes = Math.max(1, Math.floor(Math.abs(lookbackMinutes)));

    const command =
      `(systemctl --failed --no-legend --no-pager 2>/dev/null | awk '/\\.service/{print "UNIT_FAILED "$2}'; ` +
      `journalctl -p err --since '${minutes} min ago' --no-pager -o short-iso 2>/dev/null | ` +
      `grep -iE 'systemd|Started|Stopped|Failed|restart' | tail -100) | head -150`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.debug({ server: target.name }, 'Systemd collection failed via SSH');
      }
      return [];
    }

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 5)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'systemd',
        timestamp: this.parseTimestamp(line),
        line,
      }));
  }

  private static parseTimestamp(line: string): Date {
    const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:?\d{2})/);
    if (isoMatch) return new Date(isoMatch[1]);
    return new Date();
  }
}
