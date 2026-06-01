import { generateKeyPair } from 'node:crypto';
import { writeFile, mkdir } from 'node:fs/promises';
import { promisify } from 'node:util';

const generateKeyPairAsync = promisify(generateKeyPair);

const SSH_KEY_DIR = process.env.SSH_KEY_DIR ?? '/data/ssh';

export interface ED25519KeyPair {
  publicKey: string;
  privateKeyPath: string;
  publicKeyPath: string;
}

/**
 * Converts a Node.js PEM SPKI public key to OpenSSH wire format.
 *
 * OpenSSH wire format for ed25519:
 *   [4-byte BE length of "ssh-ed25519"][bytes of "ssh-ed25519"]
 *   [4-byte BE length of key (32)][32 bytes raw public key]
 * The raw public key occupies the last 32 bytes of the DER-encoded SPKI.
 */
function pemSpkiToOpenSSH(pemPublicKey: string): string {
  const b64 = pemPublicKey
    .replace(/-----BEGIN PUBLIC KEY-----/, '')
    .replace(/-----END PUBLIC KEY-----/, '')
    .replace(/\s/g, '');
  const der = Buffer.from(b64, 'base64');
  const rawKey = der.subarray(der.length - 32);

  const keyType = Buffer.from('ssh-ed25519');
  const wireFormat = Buffer.allocUnsafe(4 + keyType.length + 4 + rawKey.length);
  let offset = 0;
  wireFormat.writeUInt32BE(keyType.length, offset); offset += 4;
  keyType.copy(wireFormat, offset); offset += keyType.length;
  wireFormat.writeUInt32BE(rawKey.length, offset); offset += 4;
  rawKey.copy(wireFormat, offset);

  return `ssh-ed25519 ${wireFormat.toString('base64')}`;
}

export async function generateED25519KeyPair(serverId: number): Promise<ED25519KeyPair> {
  const { publicKey: pemPub, privateKey: pemPriv } = await generateKeyPairAsync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const openSshPub = pemSpkiToOpenSSH(pemPub as unknown as string);
  const privateKeyPath = `${SSH_KEY_DIR}/guardian-${serverId}.key`;
  const publicKeyPath = `${SSH_KEY_DIR}/guardian-${serverId}.key.pub`;

  await mkdir(SSH_KEY_DIR, { recursive: true });
  await writeFile(privateKeyPath, pemPriv as unknown as string, { mode: 0o600, encoding: 'utf-8' });
  await writeFile(publicKeyPath, `${openSshPub}\n`, { mode: 0o644, encoding: 'utf-8' });

  return { publicKey: openSshPub, privateKeyPath, publicKeyPath };
}
