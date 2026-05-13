import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';

export interface SSHKeyEntry {
  user: string;
  keyType: string;
  fingerprint: string;
  comment: string;
}

export class SSHKeysCollector {
  static async collect(target: SSHTarget): Promise<SSHKeyEntry[]> {
    const command =
      `for u in root $(getent passwd | awk -F: '$3>=1000&&$3<65534{print $1}'); do ` +
      `d=$(getent passwd "$u" | cut -d: -f6); ` +
      `f="$d/.ssh/authorized_keys"; ` +
      `[ -f "$f" ] && ssh-keygen -lf "$f" 2>/dev/null | sed "s/^/USER:$u /"; ` +
      `done`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.warn({ server: target.name, error: result.error }, 'SSH key collection failed via SSH');
      }
      return [];
    }

    return this.parseOutput(result.stdout);
  }

  private static parseOutput(stdout: string): SSHKeyEntry[] {
    const entries: SSHKeyEntry[] = [];

    for (const line of stdout.split('\n').filter(l => l.trim())) {
      // Format: "USER:username bits fingerprint comment (keytype)"
      const match = line.match(/^USER:(\S+)\s+\d+\s+(\S+)\s+(.+?)\s+\((\w+)\)$/);
      if (match) {
        entries.push({
          user: match[1],
          fingerprint: match[2],
          comment: match[3],
          keyType: match[4],
        });
      }
    }

    return entries;
  }
}
