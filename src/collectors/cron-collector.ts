import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';

export interface CronEntry {
  user: string;
  schedule: string;
  command: string;
  source: string;
}

export class CronCollector {
  static async collect(target: SSHTarget): Promise<CronEntry[]> {
    const command =
      `for u in $(cut -f1 -d: /etc/passwd | head -50); do ` +
      `crontab -l -u "$u" 2>/dev/null | grep -v '^#' | grep -v '^$' | sed "s/^/USER:$u /"; ` +
      `done; ` +
      `cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$' | grep -v '^SHELL' | grep -v '^PATH' | grep -v '^MAILTO' | sed 's/^/SYSTEM /'; ` +
      `for f in /etc/cron.d/*; do [ -f "$f" ] && grep -v '^#' "$f" | grep -v '^$' | sed "s|^|CROND:$f |"; done`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.warn({ server: target.name }, 'Cron collection failed via SSH');
      }
      return [];
    }

    return this.parseOutput(result.stdout);
  }

  private static parseOutput(stdout: string): CronEntry[] {
    const entries: CronEntry[] = [];

    for (const line of stdout.split('\n').filter(l => l.trim())) {
      try {
        if (line.startsWith('USER:')) {
          const entry = this.parseUserCrontab(line);
          if (entry) entries.push(entry);
        } else if (line.startsWith('SYSTEM ')) {
          const entry = this.parseSystemCrontab(line);
          if (entry) entries.push(entry);
        } else if (line.startsWith('CROND:')) {
          const entry = this.parseCronD(line);
          if (entry) entries.push(entry);
        }
      } catch { /* skip malformed */ }
    }

    return entries;
  }

  private static parseUserCrontab(line: string): CronEntry | null {
    const match = line.match(/^USER:(\S+)\s+(.+)$/);
    if (!match) return null;
    const parts = match[2].split(/\s+/);
    if (parts.length < 6) return null;
    return {
      user: match[1],
      schedule: parts.slice(0, 5).join(' '),
      command: parts.slice(5).join(' '),
      source: 'user_crontab',
    };
  }

  private static parseSystemCrontab(line: string): CronEntry | null {
    const parts = line.replace(/^SYSTEM\s+/, '').split(/\s+/);
    if (parts.length < 7) return null;
    return {
      user: parts[5],
      schedule: parts.slice(0, 5).join(' '),
      command: parts.slice(6).join(' '),
      source: 'system',
    };
  }

  private static parseCronD(line: string): CronEntry | null {
    const match = line.match(/^CROND:(\S+)\s+(.+)$/);
    if (!match) return null;
    const parts = match[2].split(/\s+/);
    if (parts.length < 7) return null;
    return {
      user: parts[5],
      schedule: parts.slice(0, 5).join(' '),
      command: parts.slice(6).join(' '),
      source: match[1],
    };
  }
}
