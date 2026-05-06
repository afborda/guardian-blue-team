import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';
import type { RawLogEntry } from './log-collector.js';

export class AuditCollector {
  static async collect(target: SSHTarget, lookbackMinutes: number): Promise<RawLogEntry[]> {
    const minutes = Math.max(1, Math.floor(Math.abs(lookbackMinutes)));

    const command =
      `ausearch --start recent -m USER_AUTH,USER_LOGIN,ADD_USER,DEL_USER,USER_CHAUTHTOK,ANOM_LOGIN_FAILURES --format text 2>/dev/null | tail -100 || ` +
      `journalctl _TRANSPORT=audit --since '${minutes} min ago' --no-pager -o short-iso 2>/dev/null | tail -100`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.debug({ server: target.name }, 'Audit log collection failed via SSH');
      }
      return [];
    }

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 10 && !line.startsWith('----'))
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'audit',
        timestamp: this.parseTimestamp(line),
        line,
      }));
  }

  private static parseTimestamp(line: string): Date {
    // ISO from journalctl
    const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:?\d{2})/);
    if (isoMatch) return new Date(isoMatch[1]);

    // ausearch format: time->Wed Jan 15 10:30:45 2024
    const auditMatch = line.match(/time->\w+ (\w+ \d+ [\d:]+ \d{4})/);
    if (auditMatch) return new Date(auditMatch[1]);

    // msg=audit(1705312245.123:456)
    const epochMatch = line.match(/audit\((\d+)\.\d+:\d+\)/);
    if (epochMatch) return new Date(parseInt(epochMatch[1]) * 1000);

    return new Date();
  }
}
