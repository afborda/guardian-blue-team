/**
 * PR6 — Script de teste manual do ciclo completo de upgrade Tier 0.
 *
 * Uso:
 *   SSH_KEY_DIR=/tmp/guardian-test-ssh npx tsx scripts/test-upgrade.ts
 *
 * O script não usa o banco — constrói um ServerInfo diretamente do .env
 * ou dos argumentos hardcodados abaixo.
 */

process.env.SSH_KEY_DIR = process.env.SSH_KEY_DIR ?? '/tmp/guardian-test-ssh';

// Stub mínimo do DB para não exigir DATABASE_URL
import { ServerUpgradeService } from '../src/services/server-upgrade.service.js';
import type { ServerInfo } from '../src/services/server.service.js';

// ── Configuração do servidor de teste ──────────────────────────────────────
const SERVER: ServerInfo = {
  id: 999,                          // ID fictício — não toca no DB real
  name: 'ovh-spark-pr6-test',
  host: '54.36.100.35',
  sshPort: 49222,
  sshUser: 'ubuntu',
  sshKeyPath: process.env.HOME + '/.ssh/ovh_vps',
  tags: [],
  enabled: true,
  lastSeenAt: null,
  installMode: null,
  sshFingerprint: null,
  guardianShellVersion: null,
  upgradedAt: null,
  lastHeartbeatAt: null,
  osFamily: null,
};

async function main(): Promise<void> {
  console.log('\n═══════════════════════════════════════════════════════');
  console.log('  Guardian PR6 — Teste de upgrade Tier 0');
  console.log(`  Servidor: ${SERVER.name} (${SERVER.host}:${SERVER.sshPort})`);
  console.log(`  SSH_KEY_DIR: ${process.env.SSH_KEY_DIR}`);
  console.log('═══════════════════════════════════════════════════════\n');

  const result = await ServerUpgradeService.upgrade(SERVER);

  console.log('\n─── Resultado por etapa ───────────────────────────────');
  for (const step of result.steps) {
    const icon = step.status === 'ok' ? '✅' : step.status === 'skipped' ? '⏭️' : '❌';
    console.log(`${icon} ${step.name.padEnd(28)} ${step.durationMs}ms${step.detail ? `\n   └ ${step.detail}` : ''}`);
  }

  console.log('\n─── Resumo ────────────────────────────────────────────');
  console.log(`  Sucesso:      ${result.success}`);
  console.log(`  Rolled back:  ${result.rolledBack}`);
  console.log(`  Tempo total:  ${result.totalDurationMs}ms`);
  if (result.error) console.log(`  Erro:         ${result.error}`);
  console.log('═══════════════════════════════════════════════════════\n');

  if (!result.success) process.exit(1);
}

main().catch(err => {
  console.error('Erro fatal:', err);
  process.exit(1);
});
