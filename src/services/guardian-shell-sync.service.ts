import { execFile } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { SSHCollector, SSHTarget } from '../collectors/ssh-collector.js';
import { EXPECTED_SHELL_VERSION } from '../security/guardian-shell-version.js';
import { ServerService, type ServerInfo } from './server.service.js';
import { logger } from '../utils/logger.js';

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));

const VERSION_CHECK_CMD = `grep '^VERSION=' /usr/local/bin/guardian-shell 2>/dev/null || echo 'VERSION=unknown'`;

export interface ShellSyncResult {
  serverId: number;
  serverName: string;
  action: 'updated' | 'already_current' | 'failed';
  fromVersion: string | null;
  toVersion: string;
  durationMs: number;
  error?: string;
}

export class GuardianShellSyncService {
  static async check(server: ServerInfo): Promise<ShellSyncResult> {
    const start = Date.now();
    const target = ServerService.toSSHTarget(server);

    const result = await SSHCollector.run(target, VERSION_CHECK_CMD, 10_000);
    if (!result.success) {
      return {
        serverId: server.id,
        serverName: server.name,
        action: 'failed',
        fromVersion: null,
        toVersion: EXPECTED_SHELL_VERSION,
        durationMs: Date.now() - start,
        error: result.error,
      };
    }

    const fromVersion = parseVersion(result.stdout);
    if (fromVersion === EXPECTED_SHELL_VERSION) {
      return {
        serverId: server.id,
        serverName: server.name,
        action: 'already_current',
        fromVersion,
        toVersion: EXPECTED_SHELL_VERSION,
        durationMs: Date.now() - start,
      };
    }

    return this.reinstall(server, target, fromVersion, start);
  }

  static async reinstall(
    server: ServerInfo,
    target: SSHTarget,
    fromVersion: string | null,
    startMs = Date.now(),
  ): Promise<ShellSyncResult> {
    try {
      // Quando compilado em dist/index.js, __dirname = /app/dist.
      // O guardian-shell.sh é copiado para dist/security/ pelo generate-allowlist.ts.
      const shellPath = resolve(__dirname, 'security/guardian-shell.sh');
      // Fallback para rodar via tsx em src/services/ (desenvolvimento local)
      const shellPathDev = resolve(__dirname, '../../dist/security/guardian-shell.sh');
      const actualShellPath = existsSync(shellPath) ? shellPath : shellPathDev;
      const shellContent = readFileSync(actualShellPath, 'utf-8');

      // Usa heredoc com delimitador quoted ('GUARDIAN_EOF') para evitar
      // expansão de $ e backticks no conteúdo do shell durante a transmissão.
      const heredocCmd =
        `sudo tee /usr/local/bin/guardian-shell > /dev/null << 'GUARDIAN_EOF'\n` +
        shellContent +
        `\nGUARDIAN_EOF\n` +
        `sudo chmod 755 /usr/local/bin/guardian-shell`;

      const args = SSHCollector.buildArgs(target);
      await execFileAsync('ssh', [...args, heredocCmd], {
        encoding: 'utf-8',
        timeout: 30_000,
      });

      // Smoke-test: o novo shell deve aceitar 'echo ok'
      const smoke = await SSHCollector.run(target, 'echo ok', 10_000);
      if (!smoke.success || smoke.stdout.trim() !== 'ok') {
        return {
          serverId: server.id,
          serverName: server.name,
          action: 'failed',
          fromVersion,
          toVersion: EXPECTED_SHELL_VERSION,
          durationMs: Date.now() - startMs,
          error: smoke.error ?? `smoke-test returned: ${smoke.stdout.trim()}`,
        };
      }

      logger.info(
        { server: server.name, fromVersion, toVersion: EXPECTED_SHELL_VERSION },
        'guardian-shell updated',
      );
      return {
        serverId: server.id,
        serverName: server.name,
        action: 'updated',
        fromVersion,
        toVersion: EXPECTED_SHELL_VERSION,
        durationMs: Date.now() - startMs,
      };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      logger.warn({ server: server.name, error }, 'guardian-shell reinstall failed');
      return {
        serverId: server.id,
        serverName: server.name,
        action: 'failed',
        fromVersion,
        toVersion: EXPECTED_SHELL_VERSION,
        durationMs: Date.now() - startMs,
        error,
      };
    }
  }
}

function parseVersion(stdout: string): string | null {
  const match = stdout.match(/^VERSION=(.+)$/m);
  if (!match) return null;
  const v = match[1].trim().replace(/^['"]|['"]$/g, '');
  return v === 'unknown' ? null : v;
}
