/**
 * PR7 — Migração real para Tier 0: ovh-spark + ovh-automabothub
 *
 * Uso:
 *   SSH_KEY_DIR=/data/ssh npx tsx scripts/migrate-production.ts
 *
 * Requer DATABASE_URL no .env para persistir o upgrade.
 * Rodar com: set -a && source .env && set +a && npx tsx scripts/migrate-production.ts
 */

import { initDatabase } from '../src/database/connection.js';
import { ServerUpgradeService } from '../src/services/server-upgrade.service.js';
import type { ServerInfo } from '../src/services/server.service.js';

const SSH_KEY_DIR = process.env.SSH_KEY_DIR ?? '/data/ssh';
const SSH_KEY_PATH = process.env.SSH_KEY_PATH ?? '/home/node/.ssh/guardian_ed25519';
process.env.SSH_KEY_DIR = SSH_KEY_DIR;

const SERVERS: ServerInfo[] = [
  {
    id: 5,
    name: 'ovh-spark',
    host: '54.36.100.35',
    sshPort: 49222,
    sshUser: 'ubuntu',
    sshKeyPath: SSH_KEY_PATH,
    tags: [],
    enabled: true,
    lastSeenAt: null,
    installMode: null,
    sshFingerprint: null,
    guardianShellVersion: null,
    upgradedAt: null,
    lastHeartbeatAt: null,
    osFamily: 'ubuntu',
    falcoInstalledAt: null,
    createdAt: new Date(),
  },
  {
    id: 6,
    name: 'ovh-automabothub',
    host: '51.79.84.65',
    sshPort: 49222,
    sshUser: 'ubuntu',
    sshKeyPath: SSH_KEY_PATH,
    tags: [],
    enabled: true,
    lastSeenAt: null,
    installMode: null,
    sshFingerprint: null,
    guardianShellVersion: null,
    upgradedAt: null,
    lastHeartbeatAt: null,
    osFamily: 'ubuntu',
    falcoInstalledAt: null,
    createdAt: new Date(),
  },
];

async function upgradeServer(server: ServerInfo): Promise<boolean> {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  Migrando: ${server.name} (${server.host}:${server.sshPort})`);
  console.log(`${'═'.repeat(60)}\n`);

  const result = await ServerUpgradeService.upgrade(server);

  for (const step of result.steps) {
    const icon = step.status === 'ok' ? '✅' : step.status === 'skipped' ? '⏭️ ' : '❌';
    const detail = step.detail ? `\n     └ ${step.detail.slice(0, 120)}` : '';
    console.log(`  ${icon} ${step.name.padEnd(24)} ${step.durationMs}ms${detail}`);
  }

  console.log(`\n  Sucesso:     ${result.success}`);
  console.log(`  Rolled back: ${result.rolledBack}`);
  console.log(`  Total:       ${result.totalDurationMs}ms`);
  if (result.error) console.log(`  Erro:        ${result.error}`);

  if (!result.success) {
    console.error(`\n⚠️  Upgrade de ${server.name} falhou. Servidor continua em modo legacy.`);
  } else {
    console.log(`\n✅ ${server.name} migrado para Tier 0 com sucesso.`);
  }
  return result.success;
}

async function main(): Promise<void> {
  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║   Guardian PR7 — Migração para Tier 0 (produção)        ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`\nSSH_KEY_DIR: ${SSH_KEY_DIR}`);
  console.log(`SSH_KEY_PATH: ${SSH_KEY_PATH}`);
  console.log(`Servidores:  ${SERVERS.map(s => s.name).join(', ')}\n`);

  await initDatabase();

  let successCount = 0;
  for (const server of SERVERS) {
    const ok = await upgradeServer(server);
    if (ok) successCount++;
  }

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  Resultado final: ${successCount}/${SERVERS.length} servidores migrados`);
  console.log(`${'═'.repeat(60)}\n`);
  process.exit(successCount === SERVERS.length ? 0 : 1);
}

main().catch(err => {
  console.error('Erro fatal:', err);
  process.exit(1);
});
