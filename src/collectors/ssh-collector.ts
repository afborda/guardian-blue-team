import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { logger } from '../utils/logger.js';

const execFileAsync = promisify(execFile);

export interface SSHTarget {
  id: number;
  name: string;
  host: string;
  sshPort: number;
  sshUser: string;
  sshKeyPath: string | null;
}

export interface SSHResult {
  stdout: string;
  success: boolean;
  durationMs: number;
}

export class SSHCollector {
  private static buildArgs(target: SSHTarget): string[] {
    const args = [
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', `UserKnownHostsFile=${process.env.SSH_KNOWN_HOSTS || '/data/known_hosts'}`,
      '-o', 'ConnectTimeout=10',
      '-o', 'LogLevel=ERROR',
      '-o', 'BatchMode=yes',
      '-o', 'ControlMaster=auto',
      '-o', `ControlPath=/tmp/guardian-ssh-%h-%p-%r`,
      '-o', 'ControlPersist=180',
    ];
    if (target.sshKeyPath) args.push('-i', target.sshKeyPath);
    args.push('-p', String(target.sshPort), `${target.sshUser}@${target.host}`);
    return args;
  }

  static async run(target: SSHTarget, command: string, timeoutMs = 15_000): Promise<SSHResult> {
    const start = Date.now();
    try {
      const args = this.buildArgs(target);
      const { stdout } = await execFileAsync('ssh', [...args, command], {
        encoding: 'utf-8',
        timeout: timeoutMs,
      });
      return { stdout, success: true, durationMs: Date.now() - start };
    } catch (error) {
      logger.debug({ server: target.name, err: error }, 'SSH command failed');
      return { stdout: '', success: false, durationMs: Date.now() - start };
    }
  }

  static async runMulti(target: SSHTarget, commands: string[], timeoutMs = 30_000): Promise<SSHResult> {
    const combined = commands.join(' && ');
    return this.run(target, combined, timeoutMs);
  }

  static async isReachable(target: SSHTarget): Promise<boolean> {
    const result = await this.run(target, 'echo ok', 5_000);
    return result.success && result.stdout.trim() === 'ok';
  }
}
