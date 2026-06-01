import { execFile } from 'node:child_process';
import { mkdir, readFile, unlink } from 'node:fs/promises';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const SSH_KEY_DIR = process.env.SSH_KEY_DIR ?? '/data/ssh';

export interface ED25519KeyPair {
  publicKey: string;
  privateKeyPath: string;
  publicKeyPath: string;
}

export async function generateED25519KeyPair(serverId: number): Promise<ED25519KeyPair> {
  await mkdir(SSH_KEY_DIR, { recursive: true });

  const privateKeyPath = `${SSH_KEY_DIR}/guardian-${serverId}.key`;
  const publicKeyPath = `${SSH_KEY_DIR}/guardian-${serverId}.key.pub`;

  // Remove existing key files so ssh-keygen doesn't prompt to overwrite
  await unlink(privateKeyPath).catch(() => {});
  await unlink(publicKeyPath).catch(() => {});

  // ssh-keygen produces the OpenSSH wire format that the ssh client expects.
  // -N '' = no passphrase, -C = comment for identification in authorized_keys.
  await execFileAsync('ssh-keygen', [
    '-t', 'ed25519',
    '-f', privateKeyPath,
    '-N', '',
    '-C', `guardian-${serverId}@guardian-blue-team`,
  ]);

  const publicKey = (await readFile(publicKeyPath, 'utf-8')).trim();

  return { publicKey, privateKeyPath, publicKeyPath };
}
