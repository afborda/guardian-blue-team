import * as p from '@clack/prompts';
import chalk from 'chalk';
import { execa } from 'execa';
import { existsSync, rmSync } from 'fs';

export async function uninstall(): Promise<void> {
  p.intro(chalk.bgRed.white(' 🛡️  Guardian Blue Team — Uninstall '));

  const installDir = '/opt/guardian';
  if (!existsSync(`${installDir}/docker-compose.yml`)) {
    p.cancel('Guardian not found at /opt/guardian.');
    process.exit(0);
  }

  const confirm = await p.confirm({
    message: 'This will remove Guardian containers, volumes, and all data. Continue?',
    initialValue: false,
  });

  if (p.isCancel(confirm) || !confirm) {
    p.cancel('Uninstall cancelled.');
    process.exit(0);
  }

  const s = p.spinner();

  s.start('Stopping containers...');
  try {
    await execa('docker', ['compose', 'down', '-v', '--remove-orphans'], { cwd: installDir });
  } catch { /* may not exist */ }
  s.stop('Containers removed');

  const removeData = await p.confirm({
    message: 'Remove /opt/guardian directory (config + SSH keys)?',
    initialValue: false,
  });

  if (removeData && !p.isCancel(removeData)) {
    s.start('Removing data...');
    rmSync(installDir, { recursive: true, force: true });
    s.stop('Data removed');
  }

  p.outro(chalk.yellow('Guardian has been uninstalled.'));
}
