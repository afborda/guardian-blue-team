import { LocalExecutor } from './executor.js';
import { runAllProbes } from './probes/index.js';
import { analyzeSnapshot } from './analyzer.js';
import { generateConfig, type GeneratedConfig } from './config-generator.js';
import { formatTerminalPresentation } from './presenter.js';
import { writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

async function main() {
  const args = process.argv.slice(2);
  const apiKey = getArg(args, '--api-key');
  const installDir = getArg(args, '--dir') || process.cwd();
  const telegramToken = getArg(args, '--telegram-token');
  const telegramChatId = getArg(args, '--telegram-chat-id');
  const domain = getArg(args, '--domain');

  if (apiKey) {
    process.env.GEMINI_API_KEY = apiKey;
  }

  console.log('\n  Guardian Auto-Discovery starting...\n');
  console.log('  Scanning: network, proxy, docker, security, system');
  console.log('  This may take up to 60 seconds...\n');

  const exec = new LocalExecutor();
  const hostname = (await exec.run('hostname')).stdout.trim() || 'localhost';

  const snapshot = await runAllProbes(exec, { host: hostname, port: 22, user: 'root' }, 'local');

  const probeStatus = Object.entries(snapshot.probes)
    .map(([name, probe]) => `  ${probe.success ? '+' : 'x'} ${name} (${probe.durationMs}ms)`)
    .join('\n');
  console.log(`Probes completed in ${snapshot.scanDurationMs}ms:\n${probeStatus}\n`);

  console.log('  Analyzing with AI...\n');
  const result = await analyzeSnapshot(snapshot);

  const config = generateConfig(result, {
    geminiApiKey: apiKey,
    telegramToken,
    telegramChatId,
    domain,
  });

  console.log(formatTerminalPresentation(snapshot, result, config));

  const action = await prompt('Your choice [V/A/E/Q]: ');

  switch (action.toLowerCase()) {
    case 'v':
      console.log('\n--- .env ---');
      console.log(config.envContent);
      if (config.composeContent) {
        console.log('\n--- docker-compose.yml ---');
        console.log(config.composeContent);
      }
      const action2 = await prompt('\n[A] Apply    [Q] Quit: ');
      if (action2.toLowerCase() === 'a') {
        applyConfig(installDir, config);
      }
      break;
    case 'a':
      applyConfig(installDir, config);
      break;
    case 'e':
      console.log('\n.env will be written. Edit it manually, then run: docker compose up -d');
      writeWithBackup(join(installDir, '.env'), config.envContent);
      console.log(`Written to ${join(installDir, '.env')}`);
      break;
    case 'q':
    default:
      console.log('Aborted. No changes made.');
      break;
  }

  const outputPath = join(installDir, '.guardian-discovery.json');
  writeFileSync(outputPath, JSON.stringify({ snapshot, result }, null, 2));
}

function applyConfig(dir: string, config: GeneratedConfig): void {
  writeWithBackup(join(dir, '.env'), config.envContent);
  console.log('.env written');

  if (config.composeContent) {
    writeWithBackup(join(dir, 'docker-compose.yml'), config.composeContent);
    console.log('docker-compose.yml written');
  }

  if (config.systemdContent) {
    writeFileSync(join(dir, 'guardian.service'), config.systemdContent);
    console.log('guardian.service written');
  }

  if (config.proxyContent) {
    writeFileSync(join(dir, 'guardian-proxy.conf'), config.proxyContent);
    console.log('guardian-proxy.conf written (add to your proxy config)');
  }

  console.log('\nConfiguration applied! Run: docker compose up -d');
}

function writeWithBackup(path: string, content: string): void {
  if (existsSync(path)) {
    copyFileSync(path, path + '.bak');
  }
  writeFileSync(path, content);
}

function getArg(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function prompt(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

main().catch(err => {
  console.error('Discovery failed:', err.message);
  process.exit(1);
});
