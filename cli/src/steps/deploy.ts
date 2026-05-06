import * as p from '@clack/prompts';
import { writeFileSync, mkdirSync, existsSync, chmodSync } from 'fs';
import { join } from 'path';
import { generateSSHKey } from '../utils/ssh.js';
import { generateEnvFile, type EnvConfig } from '../templates/env.js';
import { generateComposeFile } from '../templates/compose.js';
import { composeUp, waitForHealthy } from '../utils/docker.js';
import { randomBytes } from 'crypto';
import type { SystemInfo } from '../utils/system.js';
import type { UserConfig } from './prompts.js';

export async function setupAndDeploy(info: SystemInfo, userCfg: UserConfig): Promise<void> {
  const installDir = '/opt/guardian';
  const dataDir = join(installDir, 'data');
  const sshDir = join(dataDir, 'ssh');

  const s = p.spinner();

  // Create directories
  s.start('Creating directories...');
  mkdirSync(sshDir, { recursive: true });
  chmodSync(sshDir, 0o700);
  s.stop('Directories created');

  // Generate SSH key
  s.start('Generating SSH key...');
  const { publicKey, privateKeyPath } = await generateSSHKey(sshDir);
  chmodSync(privateKeyPath, 0o600);
  s.stop('SSH key generated');

  p.note(publicKey, 'Add this key to ~/.ssh/authorized_keys on target servers');

  // Generate config files
  s.start('Generating configuration...');
  const dbPassword = randomBytes(16).toString('hex');
  const dashboardToken = randomBytes(24).toString('base64url');

  const envCfg: EnvConfig = {
    telegramBotToken: userCfg.telegramBotToken,
    telegramChatId: userCfg.telegramChatId,
    aiProvider: userCfg.aiProvider,
    aiApiKey: userCfg.aiApiKey,
    aiModel: userCfg.aiModel,
    domain: userCfg.domain,
    dashboardToken,
    dbPassword,
    sshPort: info.sshPort,
    sshUser: 'root',
    sshKeyPath: '/home/node/.ssh/id_ed25519',
    traefikNetwork: info.traefikNetwork,
    abuseIpDbKey: userCfg.abuseIpDbKey || undefined,
    virusTotalKey: userCfg.virusTotalKey || undefined,
  };

  writeFileSync(join(installDir, '.env'), generateEnvFile(envCfg), { mode: 0o600 });
  writeFileSync(join(installDir, 'docker-compose.yml'), generateComposeFile({
    domain: userCfg.domain,
    traefikNetwork: info.traefikNetwork,
    dbPassword,
  }));
  s.stop('Configuration generated');

  // Pull and start containers
  s.start('Starting Guardian...');
  await composeUp(installDir);
  s.stop('Containers started');

  // Wait for health
  s.start('Waiting for Guardian to be healthy...');
  const healthy = await waitForHealthy('guardian', 45_000);
  if (!healthy) {
    p.log.warn('Guardian did not become healthy within 45s. Check logs: docker compose logs -f');
  } else {
    s.stop('Guardian is healthy!');
  }

  // Test Telegram
  s.start('Testing Telegram connection...');
  try {
    const res = await fetch(`https://api.telegram.org/bot${userCfg.telegramBotToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: userCfg.telegramChatId,
        text: '🛡️ <b>Guardian Blue Team installed!</b>\nSend /help to get started.',
        parse_mode: 'HTML',
      }),
    });
    if (res.ok) {
      s.stop('Telegram message sent!');
    } else {
      s.stop('Telegram test failed — check token/chat ID');
    }
  } catch {
    s.stop('Telegram test failed — network error');
  }

  // Print summary
  const dashboardUrl = info.traefikNetwork
    ? `https://${userCfg.domain}/dashboard?token=${dashboardToken}`
    : `http://localhost:3334/dashboard?token=${dashboardToken}`;

  p.note([
    `Dashboard:  ${dashboardUrl}`,
    `Telegram:   /status to verify`,
    `Logs:       docker compose -f ${installDir}/docker-compose.yml logs -f`,
    `SSH Key:    ${privateKeyPath}.pub`,
    '',
    `Next: add the SSH public key to your servers' authorized_keys,`,
    `then use /add-server in Telegram to register them.`,
  ].join('\n'), 'Guardian is running!');
}
