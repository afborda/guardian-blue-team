import * as p from '@clack/prompts';
import chalk from 'chalk';
import { detectSystem, type SystemInfo } from '../utils/system.js';

export async function detectEnvironment(): Promise<SystemInfo> {
  const s = p.spinner();
  s.start('Detecting environment...');

  const info = await detectSystem();
  s.stop('Environment detected');

  const checks: string[] = [];
  checks.push(`${chalk.dim('OS:')} ${info.distro}`);
  checks.push(`${chalk.dim('Arch:')} ${info.arch} | ${info.cores} cores | ${info.memoryGB}GB RAM | ${info.diskFreeGB}GB free`);

  if (info.dockerInstalled) {
    checks.push(`${chalk.green('✔')} Docker ${info.dockerVersion}`);
  } else {
    checks.push(`${chalk.red('✖')} Docker not found`);
  }

  if (info.dockerComposeInstalled) {
    checks.push(`${chalk.green('✔')} Docker Compose`);
  }

  if (info.traefikNetwork) {
    checks.push(`${chalk.green('✔')} Traefik network: ${chalk.cyan(info.traefikNetwork)}`);
  }

  if (info.sshPort !== 22) {
    checks.push(`${chalk.dim('SSH port:')} ${info.sshPort}`);
  }

  p.note(checks.join('\n'), 'System Info');

  return info;
}

export function validatePrerequisites(info: SystemInfo): string[] {
  const errors: string[] = [];

  if (!info.dockerInstalled) {
    errors.push('Docker is required. Install: https://docs.docker.com/get-docker/');
  }

  if (!info.dockerComposeInstalled) {
    errors.push('Docker Compose v2 is required. Update Docker or install the compose plugin.');
  }

  if (info.diskFreeGB < 2) {
    errors.push(`Only ${info.diskFreeGB}GB disk free. Need at least 2GB.`);
  }

  return errors;
}
