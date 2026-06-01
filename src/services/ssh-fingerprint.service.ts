import { execFile } from 'node:child_process';
import { writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { db } from '../database/connection.js';
import { eq } from 'drizzle-orm';
import { socServers } from '../database/guardian-schema.js';
import { logger } from '../utils/logger.js';

const execFileAsync = promisify(execFile);

const SSH_KEY_DIR = process.env.SSH_KEY_DIR ?? '/data/ssh';

export class SSHFingerprintService {
  /**
   * Captures the ed25519 fingerprint of a remote host.
   * Returns format: "SHA256:<base64>" (matches `ssh -v` output).
   */
  static async capture(host: string, port: number): Promise<string> {
    const { stdout } = await execFileAsync(
      'ssh-keyscan',
      ['-t', 'ed25519', '-p', String(port), host],
      { timeout: 10_000 },
    );

    const keyMatch = stdout.match(/ssh-ed25519 ([A-Za-z0-9+/=]+)/);
    if (!keyMatch) {
      throw new Error(`Could not capture ed25519 fingerprint for ${host}:${port}`);
    }

    const keyBytes = Buffer.from(keyMatch[1], 'base64');
    const sha256 = createHash('sha256').update(keyBytes).digest('base64').replace(/=+$/, '');
    return `SHA256:${sha256}`;
  }

  /**
   * Writes the raw known_hosts entry for the server so SSHCollector can use
   * StrictHostKeyChecking=yes pointing to this file.
   */
  static async writeKnownHostsFile(serverId: number, host: string, port: number): Promise<void> {
    const { stdout } = await execFileAsync(
      'ssh-keyscan',
      ['-t', 'ed25519', '-p', String(port), host],
      { timeout: 10_000 },
    );
    await mkdir(SSH_KEY_DIR, { recursive: true });
    const filePath = `${SSH_KEY_DIR}/guardian-${serverId}.known_hosts`;
    await writeFile(filePath, stdout, { mode: 0o600, encoding: 'utf-8' });
    logger.info({ serverId, filePath }, 'wrote known_hosts file');
  }

  static async persist(serverId: number, fingerprint: string): Promise<void> {
    await db
      .update(socServers)
      .set({ sshFingerprint: fingerprint })
      .where(eq(socServers.id, serverId));
  }
}
