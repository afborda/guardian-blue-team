import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';

const BACKUP_DIR = '/backup/daily';
const BACKUP_PATTERN = 'babarato-*.sql.gz.gpg';
// Minimum expected size: 1 GB compressed (recent dumps have been ~3.3 GB+)
const MIN_SIZE_BYTES = 1_000_000_000;
// Alert if no backup newer than this many hours (cron runs at 03h)
const MAX_AGE_HOURS = 26;

export class BackupCollector {
  static async collect(
    target: SSHTarget,
    serverId: number,
    serverName: string,
  ): Promise<Array<{ serverId: number; serverName: string; source: string; timestamp: Date; line: string }>> {
    const results: Array<{ serverId: number; serverName: string; source: string; timestamp: Date; line: string }> = [];

    try {
      const result = await SSHCollector.run(
        target,
        `find ${BACKUP_DIR} -name '${BACKUP_PATTERN}' -printf '%T@ %s %f\\n' 2>/dev/null | sort -rn | head -1`,
      );

      if (!result.success || !result.stdout.trim()) {
        logger.warn({ serverName, success: result.success, stdout: result.stdout, error: result.error }, 'Backup collector: no backup file found');
        results.push({ serverId, serverName, source: 'backup', timestamp: new Date(), line: `BACKUP_MISSING dir=${BACKUP_DIR}` });
        return results;
      }

      const parts = result.stdout.trim().split(' ');
      const mtimeSec = parseFloat(parts[0]);
      const sizeBytes = parseInt(parts[1], 10);
      const ageHours = (Date.now() / 1000 - mtimeSec) / 3600;

      if (ageHours > MAX_AGE_HOURS) {
        logger.warn({ serverName, ageHours: ageHours.toFixed(1) }, 'Backup collector: backup is too old');
        results.push({ serverId, serverName, source: 'backup', timestamp: new Date(), line: `BACKUP_MISSING age_hours=${ageHours.toFixed(1)} max_age_hours=${MAX_AGE_HOURS}` });
        return results;
      }

      if (sizeBytes < MIN_SIZE_BYTES) {
        logger.warn({ serverName, sizeBytes }, 'Backup collector: backup file too small');
        results.push({ serverId, serverName, source: 'backup', timestamp: new Date(), line: `BACKUP_TOO_SMALL size_bytes=${sizeBytes} min_bytes=${MIN_SIZE_BYTES} age_hours=${ageHours.toFixed(1)}` });
        return results;
      }

      logger.debug({ serverName, sizeBytes, ageHours: ageHours.toFixed(1) }, 'Backup collector: OK');
    } catch (err) {
      logger.error({ err, serverName }, 'Backup collector: SSH error');
    }

    return results;
  }
}
