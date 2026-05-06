#!/usr/bin/env node
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { install } from './commands/install.js';
import { uninstall } from './commands/uninstall.js';
import { upgrade } from './commands/upgrade.js';

yargs(hideBin(process.argv))
  .scriptName('guardian')
  .command('install', 'Install Guardian Blue Team', {}, install)
  .command('upgrade', 'Upgrade to the latest version', {}, upgrade)
  .command('uninstall', 'Remove Guardian and all data', {}, uninstall)
  .demandCommand(1, 'Run `guardian install` to get started')
  .strict()
  .help()
  .parse();
