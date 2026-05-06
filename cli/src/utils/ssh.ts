import { execa } from 'execa';
import { existsSync } from 'fs';
import { join } from 'path';

export async function generateSSHKey(dir: string): Promise<{ publicKey: string; privateKeyPath: string }> {
  const keyPath = join(dir, 'id_ed25519');
  if (!existsSync(keyPath)) {
    await execa('ssh-keygen', ['-t', 'ed25519', '-f', keyPath, '-N', '', '-C', 'guardian-monitor']);
  }
  const { stdout: publicKey } = await execa('cat', [`${keyPath}.pub`]);
  return { publicKey: publicKey.trim(), privateKeyPath: keyPath };
}

export async function testSSHConnection(host: string, port: number, user: string, keyPath: string): Promise<boolean> {
  try {
    await execa('ssh', [
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'ConnectTimeout=5',
      '-o', 'BatchMode=yes',
      '-i', keyPath,
      '-p', String(port),
      `${user}@${host}`,
      'echo ok',
    ], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}
