import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { matchTemplate } from '../security/template-matcher.js';
import { logger } from '../utils/logger.js';

const execFileAsync = promisify(execFile);

export interface SSHTarget {
  id: number;
  name: string;
  host: string;
  sshPort: number;
  sshUser: string;
  sshKeyPath: string | null;
  installMode?: 'legacy' | 'guardian' | null;
  sshFingerprint?: string | null;
}

export interface SSHResult {
  stdout: string;
  success: boolean;
  durationMs: number;
  error?: string;
}

export class SSHCollector {
  static buildArgs(target: SSHTarget): string[] {
    const args = [
      '-o', target.sshFingerprint
        ? 'StrictHostKeyChecking=yes'
        : 'StrictHostKeyChecking=accept-new',
      '-o', target.sshFingerprint
        ? `UserKnownHostsFile=${process.env.SSH_KEY_DIR ?? '/data/ssh'}/guardian-${target.id}.known_hosts`
        : `UserKnownHostsFile=${process.env.SSH_KNOWN_HOSTS || '/data/known_hosts'}`,
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

    // Guardian mode: skip commands not in the allowlist before sending over SSH —
    // guardian-shell would reject them (exit 126) anyway. Log warn so the operator
    // sees what was skipped without the server receiving noise.
    if (target.installMode === 'guardian') {
      const match = matchTemplate(command);
      if (!match.templateHash) {
        logger.warn(
          { server: target.name, normalized: match.normalized },
          'guardian-mode skip: command not templatable',
        );
        return {
          stdout: '',
          success: false,
          durationMs: Date.now() - start,
          error: 'GUARDIAN_NO_TEMPLATE',
        };
      }
      // Audit trail: every allowed command dispatched through guardian-shell
      logger.debug(
        { server: target.name, templateHash: match.templateHash, normalized: match.normalized },
        'guardian-mode command dispatched',
      );
    }

    try {
      const args = this.buildArgs(target);
      const { stdout } = await execFileAsync('ssh', [...args, command], {
        encoding: 'utf-8',
        timeout: timeoutMs,
      });
      return { stdout, success: true, durationMs: Date.now() - start };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      logger.debug({ server: target.name, err: error }, 'SSH command failed');
      return { stdout: '', success: false, durationMs: Date.now() - start, error: errMsg };
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
