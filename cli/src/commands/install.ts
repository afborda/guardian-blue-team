import * as p from '@clack/prompts';
import chalk from 'chalk';
import { detectEnvironment, validatePrerequisites } from '../steps/detect-env.js';
import { collectConfig } from '../steps/prompts.js';
import { setupAndDeploy } from '../steps/deploy.js';

export async function install(): Promise<void> {
  p.intro(chalk.bgCyan.black(' 🛡️  Guardian Blue Team Installer v2.0 '));

  const info = await detectEnvironment();

  const errors = validatePrerequisites(info);
  if (errors.length > 0) {
    for (const err of errors) {
      p.log.error(err);
    }
    p.cancel('Prerequisites not met. Fix the issues above and try again.');
    process.exit(1);
  }

  const userCfg = await collectConfig(info);

  await setupAndDeploy(info, userCfg);

  p.outro(chalk.green('Installation complete! Send /help in Telegram to get started.'));
}
