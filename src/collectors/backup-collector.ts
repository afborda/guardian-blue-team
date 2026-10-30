import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';

const BACKUP_DIR = '/backup/daily';
const BACKUP_PATTERN = 'babarato-*.sql.gz.gpg';
// Minimum expected size: 1 GB compressed (recent dumps have been ~3.3 GB+)
const MIN_SIZE_BYTES = 1_000_000_000;
// Alert if no backup newer than this many hours (cron runs at 03h)
const MAX_AGE_HOURS = 26;
// Evita repetir o mesmo alerta a cada ciclo de 2 min; backup é diário.
const ALERT_COOLDOWN_MS = 6 * 60 * 60 * 1000;

export class BackupCollector {
  private static lastAlertAt = new Map<string, number>();

  private static shouldEmit(serverId: number, kind: string): boolean {
    const key = `${serverId}:${kind}`;
    const last = this.lastAlertAt.get(key) ?? 0;
    if (Date.now() - last < ALERT_COOLDOWN_MS) return false;
    this.lastAlertAt.set(key, Date.now());
    return true;
  }

  static async collect(
    target: SSHTarget,
    serverId: number,
    serverName: string,
  ): Promise<Array<{ serverId: number; serverName: string; source: string; timestamp: Date; line: string }>> {
    const results: Array<{ serverId: number; serverName: string; source: string; timestamp: Date; line: string }> = [];

    try {
      const result = await SSHCollector.run(
        target,
        `if [ -d ${BACKUP_DIR} ]; then find ${BACKUP_DIR} -name '${BACKUP_PATTERN}' -printf '%T@ %s %f\\n' 2>/dev/null | sort -rn | head -1; else echo NO_BACKUP_DIR; fi`,
      );

      if (!result.success) {
        if (this.shouldEmit(serverId, 'ssh')) {
          logger.warn({ serverName, error: result.error }, 'Backup collector: SSH error');
        }
        return results;
      }

      if (result.stdout.trim() === 'NO_BACKUP_DIR') {
        logger.debug({ serverName }, 'Backup collector: diretório de backup não configurado neste host');
        return results;
      }

      if (!result.stdout.trim()) {
        if (this.shouldEmit(serverId, 'missing')) {
          logger.warn({ serverName }, 'Backup collector: nenhum backup encontrado');
          results.push({ serverId, serverName, source: 'backup', timestamp: new Date(), line: `BACKUP_MISSING dir=${BACKUP_DIR}` });
        }
        return results;
      }

      const parts = result.stdout.trim().split(' ');
      const mtimeSec = parseFloat(parts[0]);
      const sizeBytes = parseInt(parts[1], 10);
      const ageHours = (Date.now() / 1000 - mtimeSec) / 3600;

      if (ageHours > MAX_AGE_HOURS) {
        if (this.shouldEmit(serverId, 'old')) {
          logger.warn({ serverName, ageHours: ageHours.toFixed(1) }, 'Backup collector: backup is too old');
          results.push({ serverId, serverName, source: 'backup', timestamp: new Date(), line: `BACKUP_MISSING age_hours=${ageHours.toFixed(1)} max_age_hours=${MAX_AGE_HOURS}` });
        }
        return results;
      }

      if (sizeBytes < MIN_SIZE_BYTES) {
        if (this.shouldEmit(serverId, 'small')) {
          logger.warn({ serverName, sizeBytes }, 'Backup collector: backup file too small');
          results.push({ serverId, serverName, source: 'backup', timestamp: new Date(), line: `BACKUP_TOO_SMALL size_bytes=${sizeBytes} min_bytes=${MIN_SIZE_BYTES} age_hours=${ageHours.toFixed(1)}` });
        }
        return results;
      }

      logger.debug({ serverName, sizeBytes, ageHours: ageHours.toFixed(1) }, 'Backup collector: OK');
    } catch (err) {
      logger.error({ err, serverName }, 'Backup collector: SSH error');
    }

    return results;
  }
}
