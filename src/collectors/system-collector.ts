import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';

export interface RawSystemMetrics {
  serverId: number;
  serverName: string;
  collectedAt: Date;
  kernelErrors: Array<{ timestamp: string; message: string }>;
  journalErrors: Array<{ timestamp: string; message: string }>;
  failedUnits: string[];
}

export class SystemCollector {
  static async collect(target: SSHTarget): Promise<RawSystemMetrics | null> {
    const result = await SSHCollector.run(target, [
      'dmesg --time-format iso 2>/dev/null | tail -30',
      'echo "---SSEP---"',
      'journalctl -p err --since "5 min ago" --no-pager -o short-iso 2>/dev/null | tail -20',
      'echo "---SSEP---"',
      'systemctl list-units --failed --no-legend --no-pager 2>/dev/null',
    ].join(' && '), 15_000);

    if (!result.success) {
      logger.debug({ server: target.name }, 'System collection failed');
      return null;
    }

    try {
      return this.parse(target, result.stdout);
    } catch (err) {
      logger.debug({ server: target.name, err }, 'System parsing failed');
      return null;
    }
  }

  private static parse(target: SSHTarget, stdout: string): RawSystemMetrics {
    const sections = stdout.split('---SSEP---').map(s => s.trim());

    const kernelErrors = this.parseTimestampedLines(sections[0]);
    const journalErrors = this.parseTimestampedLines(sections[1]);

    const failedUnits = (sections[2] ?? '')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0)
      .map(line => {
        const match = line.match(/^●?\s*(\S+)/);
        return match ? match[1] : line.split(/\s+/)[0];
      })
      .filter(u => u && u.endsWith('.service'));

    return {
      serverId: target.id,
      serverName: target.name,
      collectedAt: new Date(),
      kernelErrors,
      journalErrors,
      failedUnits,
    };
  }

  private static parseTimestampedLines(section: string): Array<{ timestamp: string; message: string }> {
    if (!section) return [];
    return section
      .split('\n')
      .filter(l => l.trim().length > 0)
      .map(line => {
        const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T[\d:.+\-Z]+)\s+(.+)/);
        if (isoMatch) {
          return { timestamp: isoMatch[1], message: isoMatch[2] };
        }
        const shortMatch = line.match(/^(\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+(.+)/);
        if (shortMatch) {
          return { timestamp: shortMatch[1], message: shortMatch[2] };
        }
        return { timestamp: new Date().toISOString(), message: line };
      });
  }
}
