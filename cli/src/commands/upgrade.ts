import * as p from '@clack/prompts';
import chalk from 'chalk';
import { execa } from 'execa';
import { existsSync } from 'fs';

export async function upgrade(): Promise<void> {
  p.intro(chalk.bgCyan.black(' 🛡️  Guardian Blue Team — Upgrade '));

  const installDir = '/opt/guardian';
  if (!existsSync(`${installDir}/docker-compose.yml`)) {
    p.cancel('Guardian not found at /opt/guardian. Run `guardian install` first.');
    process.exit(1);
  }

  const s = p.spinner();

  s.start('Pulling latest image...');
  await execa('docker', ['compose', 'pull'], { cwd: installDir });
  s.stop('Image updated');

  s.start('Restarting Guardian...');
  await execa('docker', ['compose', 'up', '-d', '--remove-orphans'], { cwd: installDir });
  s.stop('Guardian restarted');

  s.start('Waiting for health check...');
  await new Promise(r => setTimeout(r, 5000));
  try {
    const { stdout } = await execa('docker', ['inspect', '--format', '{{.State.Health.Status}}', 'guardian']);
    if (stdout.trim() === 'healthy') {
      s.stop('Guardian is healthy!');
    } else {
      s.stop(`Status: ${stdout.trim()} — check logs if issues persist`);
    }
  } catch {
    s.stop('Could not check health status');
  }

  p.outro(chalk.green('Upgrade complete!'));
}
