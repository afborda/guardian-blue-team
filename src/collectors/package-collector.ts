import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';
import type { RawLogEntry } from './log-collector.js';

export class PackageCollector {
  static async collect(target: SSHTarget, lookbackMinutes: number): Promise<RawLogEntry[]> {
    const minutes = Math.max(1, Math.floor(Math.abs(lookbackMinutes)));

    const command =
      `awk -v d="$(date -d '${minutes} min ago' '+%Y-%m-%d %H:%M' 2>/dev/null || date -v-${minutes}M '+%Y-%m-%d %H:%M')" '$0 > d' /var/log/dpkg.log 2>/dev/null | grep -E 'install|remove|upgrade' | tail -50`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.debug({ server: target.name }, 'Package log collection failed via SSH');
      }
      return [];
    }

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 10)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'package',
        timestamp: this.parseTimestamp(line),
        line,
      }));
  }

  private static parseTimestamp(line: string): Date {
    // dpkg.log format: 2024-01-15 10:30:45 install package:amd64 1.2.3
    const match = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
    if (match) return new Date(match[1]);
    return new Date();
  }
}
