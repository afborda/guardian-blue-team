import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';

export interface FileHash {
  path: string;
  sha256: string;
  permissions: string;
  owner: string;
}

export class FIMCollector {
  static async collect(target: SSHTarget): Promise<FileHash[]> {
    const paths = CONSTANTS.fim.monitoredPaths.map(p => `"${p}"`).join(' ');

    const command =
      `for f in ${paths}; do ` +
      `[ -f "$f" ] && sha256sum "$f" 2>/dev/null && stat --format="%a %U %n" "$f" 2>/dev/null; ` +
      `done; exit 0`;

    const result = await SSHCollector.run(target, command, CONSTANTS.collection.sshTimeoutMs);

    if (!result.success || !result.stdout.trim()) {
      if (!result.success) {
        logger.warn({ server: target.name, error: result.error }, 'FIM collection failed via SSH');
      }
      return [];
    }

    return this.parseOutput(result.stdout);
  }

  private static parseOutput(output: string): FileHash[] {
    const lines = output.trim().split('\n').filter(Boolean);
    const hashes = new Map<string, string>();
    const stats = new Map<string, { permissions: string; owner: string }>();

    for (const line of lines) {
      // sha256sum output: "hash  path"
      const hashMatch = line.match(/^([a-f0-9]{64})\s+(.+)$/);
      if (hashMatch) {
        hashes.set(hashMatch[2], hashMatch[1]);
        continue;
      }

      // stat output: "permissions owner path"
      const statMatch = line.match(/^(\d{3,4})\s+(\S+)\s+(.+)$/);
      if (statMatch) {
        stats.set(statMatch[3], { permissions: statMatch[1], owner: statMatch[2] });
      }
    }

    const results: FileHash[] = [];
    for (const [path, sha256] of hashes) {
      const stat = stats.get(path);
      results.push({
        path,
        sha256,
        permissions: stat?.permissions ?? 'unknown',
        owner: stat?.owner ?? 'unknown',
      });
    }

    return results;
  }
}
