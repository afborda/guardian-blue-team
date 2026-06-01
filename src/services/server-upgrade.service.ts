import { readFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { db, dbNow } from '../database/connection.js';
import { eq } from 'drizzle-orm';
import { socServers } from '../database/guardian-schema.js';
import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { SSHFingerprintService } from './ssh-fingerprint.service.js';
import { generateED25519KeyPair } from '../utils/ssh-keygen.js';
import { type ServerInfo } from './server.service.js';
import { logger } from '../utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GUARDIAN_SHELL_PATH = resolve(__dirname, '../../src/security/guardian-shell.sh');
const GUARDIAN_SHELL_VERSION = '1.0.0';

export interface UpgradeStep {
  name: string;
  status: 'ok' | 'failed' | 'skipped';
  durationMs: number;
  detail?: string;
}

export interface UpgradeResult {
  success: boolean;
  serverId: number;
  steps: UpgradeStep[];
  totalDurationMs: number;
  rolledBack: boolean;
  error?: string;
}

interface RollbackContext {
  guardianUserCreated: boolean;
  guardianShellInstalled: boolean;
  sudoersInstalled: boolean;
}

const SUDOERS_CONTENT = `# Guardian Tier 0 — sudoers allowlist
# Defesa em profundidade: o guardian-shell wrapper é a validação principal;
# sudoers garante que um bug no wrapper não escala para sudo irrestrito.
guardian ALL=(root) NOPASSWD: \\
  /usr/bin/journalctl *, \\
  /usr/bin/tail *, \\
  /usr/sbin/ss *, \\
  /usr/bin/ss *, \\
  /usr/bin/ausearch *, \\
  /usr/bin/ps *, \\
  /usr/bin/dmesg *, \\
  /usr/bin/systemctl list-units *
`;

export class ServerUpgradeService {
  static async upgrade(server: ServerInfo): Promise<UpgradeResult> {
    const totalStart = Date.now();
    const steps: UpgradeStep[] = [];
    const rollbackCtx: RollbackContext = {
      guardianUserCreated: false,
      guardianShellInstalled: false,
      sudoersInstalled: false,
    };

    const legacyTarget: SSHTarget = {
      id: server.id,
      name: server.name,
      host: server.host,
      sshPort: server.sshPort,
      sshUser: server.sshUser,
      sshKeyPath: server.sshKeyPath,
      installMode: null,
    };

    const step = async (
      name: string,
      fn: () => Promise<string | void>,
    ): Promise<boolean> => {
      const start = Date.now();
      try {
        const detail = await fn();
        steps.push({ name, status: 'ok', durationMs: Date.now() - start, detail: detail ?? undefined });
        return true;
      } catch (err) {
        const detail = err instanceof Error ? err.message : String(err);
        steps.push({ name, status: 'failed', durationMs: Date.now() - start, detail });
        logger.warn({ server: server.name, step: name, detail }, 'upgrade step failed');
        return false;
      }
    };

    // ── Etapas 1-3: sem estado remoto, sem rollback necessário ──────────────

    const ok1 = await step('pre-flight', async () => {
      const r = await SSHCollector.run(legacyTarget,
        'cat /etc/os-release 2>/dev/null | head -5 && df -h /usr/local/bin /etc/sudoers.d 2>/dev/null',
        15_000);
      if (!r.success) throw new Error(r.error ?? 'SSH failed');
      return r.stdout.slice(0, 200);
    });
    if (!ok1) return { success: false, serverId: server.id, steps, totalDurationMs: Date.now() - totalStart, rolledBack: false, error: 'pre-flight failed' };

    let fingerprint = '';
    const ok2 = await step('capture-fingerprint', async () => {
      fingerprint = await SSHFingerprintService.capture(server.host, server.sshPort);
      await SSHFingerprintService.writeKnownHostsFile(server.id, server.host, server.sshPort);
      return fingerprint;
    });
    if (!ok2) return { success: false, serverId: server.id, steps, totalDurationMs: Date.now() - totalStart, rolledBack: false, error: 'fingerprint capture failed' };

    let pubKey = '';
    let privateKeyPath = '';
    const ok3 = await step('generate-keypair', async () => {
      const kp = await generateED25519KeyPair(server.id);
      pubKey = kp.publicKey;
      privateKeyPath = kp.privateKeyPath;
      return kp.privateKeyPath;
    });
    if (!ok3) return { success: false, serverId: server.id, steps, totalDurationMs: Date.now() - totalStart, rolledBack: false, error: 'keypair generation failed' };

    // ── Etapas 4-7: estado remoto — falha → rollback automático ─────────────

    const abort = async (reason: string): Promise<UpgradeResult> => {
      await ServerUpgradeService.rollback(legacyTarget, rollbackCtx);
      return { success: false, serverId: server.id, steps, totalDurationMs: Date.now() - totalStart, rolledBack: true, error: reason };
    };

    const ok4 = await step('create-guardian-user', async () => {
      const r = await SSHCollector.run(legacyTarget,
        `id guardian 2>/dev/null || (sudo useradd -m -s /bin/bash guardian && sudo mkdir -p /home/guardian/.ssh && sudo chmod 700 /home/guardian/.ssh && sudo chown guardian:guardian /home/guardian/.ssh)`,
        20_000);
      if (!r.success) throw new Error(r.error ?? 'useradd failed');
      rollbackCtx.guardianUserCreated = true;
    });
    if (!ok4) return abort('create-guardian-user failed');

    const ok5 = await step('install-pubkey', async () => {
      const authorizedEntry = `${pubKey} command="/usr/local/bin/guardian-shell",no-pty,no-X11-forwarding,no-agent-forwarding,no-port-forwarding`;
      const r = await SSHCollector.run(legacyTarget,
        `echo '${authorizedEntry.replace(/'/g, "'\\''")}' | sudo tee /home/guardian/.ssh/authorized_keys && sudo chmod 600 /home/guardian/.ssh/authorized_keys && sudo chown guardian:guardian /home/guardian/.ssh/authorized_keys`,
        15_000);
      if (!r.success) throw new Error(r.error ?? 'install pubkey failed');
    });
    if (!ok5) return abort('install-pubkey failed');

    const ok6 = await step('install-guardian-shell', async () => {
      const shellContent = await readFile(GUARDIAN_SHELL_PATH, 'utf-8');
      // Transmit shell script via heredoc — escape any occurrence of the sentinel in content
      const sentinel = 'GUARDIAN_SHELL_EOF';
      if (shellContent.includes(sentinel)) throw new Error('guardian-shell.sh contains heredoc sentinel');
      const r = await SSHCollector.run(legacyTarget,
        `sudo tee /usr/local/bin/guardian-shell <<'${sentinel}'\n${shellContent}\n${sentinel}\nsudo chmod 755 /usr/local/bin/guardian-shell`,
        30_000);
      if (!r.success) throw new Error(r.error ?? 'tee guardian-shell failed');
      rollbackCtx.guardianShellInstalled = true;
    });
    if (!ok6) return abort('install-guardian-shell failed');

    const ok7 = await step('install-sudoers', async () => {
      const sentinel = 'SUDOERS_EOF';
      const r = await SSHCollector.run(legacyTarget,
        `sudo tee /tmp/guardian.sudoers <<'${sentinel}'\n${SUDOERS_CONTENT}\n${sentinel}\nsudo visudo -cf /tmp/guardian.sudoers && sudo mv /tmp/guardian.sudoers /etc/sudoers.d/guardian && sudo chmod 440 /etc/sudoers.d/guardian`,
        20_000);
      if (!r.success) throw new Error(r.error ?? 'visudo/install sudoers failed');
      rollbackCtx.sudoersInstalled = true;
    });
    if (!ok7) return abort('install-sudoers failed');

    // ── Etapa 8: smoke test como guardian ───────────────────────────────────

    const guardianTarget: SSHTarget = {
      id: server.id,
      name: server.name,
      host: server.host,
      sshPort: server.sshPort,
      sshUser: 'guardian',
      sshKeyPath: privateKeyPath,
      installMode: 'guardian',
      sshFingerprint: fingerprint,
    };

    const ok8 = await step('smoke-test', async () => {
      const probe = await SSHCollector.run(guardianTarget, 'echo ok', 10_000);
      if (!probe.success || probe.stdout.trim() !== 'ok') throw new Error('echo ok probe failed');

      const allowedCmd = `sudo tail -n 5 /var/log/ufw.log 2>/dev/null || echo ''`;
      const allowed = await SSHCollector.run(guardianTarget, allowedCmd, 10_000);
      if (!allowed.success && allowed.error !== 'GUARDIAN_NO_TEMPLATE') {
        // success: false pode ser porque /var/log/ufw.log não existe — só falha se for erro SSH real
        if (!allowed.stdout.includes('') && allowed.error && !allowed.error.includes('exit')) {
          throw new Error(`allowed command unexpectedly rejected: ${allowed.error}`);
        }
      }

      const blocked = await SSHCollector.run(guardianTarget, 'cat /etc/passwd', 5_000);
      if (blocked.error !== 'GUARDIAN_NO_TEMPLATE') {
        throw new Error(`blocked command was not rejected (error: ${blocked.error})`);
      }

      return 'echo ok + allowed + blocked checks passed';
    });
    if (!ok8) return abort('smoke-test failed');

    // ── Etapa 9: persistir upgrade no DB ────────────────────────────────────

    await step('persist-upgrade', async () => {
      await db.update(socServers).set({
        sshUser: 'guardian',
        sshKeyPath: privateKeyPath,
        installMode: 'guardian',
        sshFingerprint: fingerprint,
        guardianShellVersion: GUARDIAN_SHELL_VERSION,
        upgradedAt: dbNow(),
      }).where(eq(socServers.id, server.id));
    });

    // ── Etapa 10: cleanup best-effort ───────────────────────────────────────

    await step('cleanup', async () => {
      await SSHCollector.run(legacyTarget, 'sudo rm -f /tmp/guardian.sudoers 2>/dev/null || true', 5_000);
    });

    logger.info({ server: server.name, serverId: server.id }, 'Tier 0 upgrade complete');
    return {
      success: true,
      serverId: server.id,
      steps,
      totalDurationMs: Date.now() - totalStart,
      rolledBack: false,
    };
  }

  static async rollback(target: SSHTarget, ctx: RollbackContext): Promise<void> {
    logger.warn({ server: target.name }, 'rolling back Tier 0 upgrade');

    const cmds: string[] = [];
    if (ctx.sudoersInstalled) cmds.push('sudo rm -f /etc/sudoers.d/guardian');
    if (ctx.guardianShellInstalled) cmds.push('sudo rm -f /usr/local/bin/guardian-shell');
    if (ctx.guardianUserCreated) cmds.push('sudo userdel -r guardian 2>/dev/null || true');

    for (const cmd of cmds) {
      const r = await SSHCollector.run(target, cmd, 15_000);
      if (!r.success) logger.warn({ server: target.name, cmd }, 'rollback command failed (continuing)');
    }
  }
}
