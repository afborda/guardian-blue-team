/**
 * Trigger manual da auditoria semanal (WeeklyAuditWorker) — mesma sequência de
 * inicialização usada pelo index.ts (DB + plugins + notifiers), mas sem subir
 * o servidor Express nem os demais workers.
 *
 * Uso (dentro do container guardian):
 *   docker exec guardian node dist/scripts/weekly-audit-now.js --dry-run   # só imprime
 *   docker exec guardian node dist/scripts/weekly-audit-now.js --test      # envia marcada [teste]
 *   docker exec guardian node dist/scripts/weekly-audit-now.js             # envio normal
 */
import { initDatabase } from '../database/connection.js';
import { config } from '../config/environment.js';
import { registerBuiltinPlugins, PluginManager } from '../plugins/index.js';
import { WeeklyAuditWorker } from '../workers/weekly-audit.worker.js';
import { logger } from '../utils/logger.js';

const args = new Set(process.argv.slice(2));

async function main(): Promise<void> {
  await initDatabase();
  registerBuiltinPlugins();
  await PluginManager.loadNotifiers(config.notifiers);

  await WeeklyAuditWorker.sendReport({
    test: args.has('--test'),
    dryRun: args.has('--dry-run'),
  });
}

main()
  .then(() => {
    logger.info('weekly-audit-now: done');
    process.exit(0);
  })
  .catch(err => {
    logger.error({ err }, 'weekly-audit-now failed');
    process.exit(1);
  });
