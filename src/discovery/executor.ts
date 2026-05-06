import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';

const execFileAsync = promisify(execFile);

export interface CommandResult {
  stdout: string;
  success: boolean;
}

export interface Executor {
  run(command: string, timeoutMs?: number): Promise<CommandResult>;
}

export class LocalExecutor implements Executor {
  async run(command: string, timeoutMs = 10_000): Promise<CommandResult> {
    try {
      const { stdout } = await execFileAsync('bash', ['-c', command], {
        encoding: 'utf-8',
        timeout: timeoutMs,
      });
      return { stdout, success: true };
    } catch {
      return { stdout: '', success: false };
    }
  }
}

export class SSHExecutor implements Executor {
  constructor(private target: SSHTarget) {}

  async run(command: string, timeoutMs = 10_000): Promise<CommandResult> {
    const result = await SSHCollector.run(this.target, command, timeoutMs);
    return { stdout: result.stdout, success: result.success };
  }
}
