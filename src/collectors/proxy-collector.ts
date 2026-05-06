import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';
import type { RawLogEntry } from './log-collector.js';

export class ProxyCollector {
  static async collect(target: SSHTarget, lookbackMinutes: number): Promise<RawLogEntry[]> {
    const minutes = Math.max(1, Math.floor(Math.abs(lookbackMinutes)));

    const command =
      `docker logs traefik --since ${minutes}m 2>&1 | grep -E '"(4[0-9]{2}|5[0-9]{2})"' | tail -200 2>/dev/null || ` +
      `tail -500 /var/log/nginx/access.log 2>/dev/null | grep -E '"(4[0-9]{2}|5[0-9]{2})"' | tail -200`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.debug({ server: target.name }, 'Proxy log collection failed via SSH');
      }
      return [];
    }

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 10)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'proxy',
        timestamp: this.parseTimestamp(line),
        line,
      }));
  }

  private static parseTimestamp(line: string): Date {
    // Traefik JSON format: "time":"2024-01-15T10:30:45Z"
    const traefikMatch = line.match(/"time":"([^"]+)"/);
    if (traefikMatch) return new Date(traefikMatch[1]);

    // Traefik CLF: 1.2.3.4 - - [15/Jan/2024:10:30:45 +0000]
    const clfMatch = line.match(/\[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2})\s*[+-]\d{4}\]/);
    if (clfMatch) {
      const raw = clfMatch[1].replace(/\//g, ' ').replace(':', ' ');
      return new Date(raw);
    }

    // ISO from journalctl
    const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:?\d{2})/);
    if (isoMatch) return new Date(isoMatch[1]);

    return new Date();
  }
}
