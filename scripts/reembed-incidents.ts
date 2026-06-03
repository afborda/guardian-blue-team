/**
 * Re-embed incident_memory rows after switching the embedding model.
 *
 * Usage:
 *   npm run reembed-incidents              # re-embed all rows with stale dimension
 *   npm run reembed-incidents -- --all     # force re-embed everything
 *   npm run reembed-incidents -- --dry-run # report what would change, don't write
 */

import { db, closeConnection, testConnection } from '../src/database/connection.js';
import { incidentMemory } from '../src/database/schema.js';
import { eq } from 'drizzle-orm';
import { EmbeddingService } from '../src/services/embedding.service.js';
import { config } from '../src/config/environment.js';
import { logger } from '../src/utils/logger.js';

interface Stats {
  total: number;
  alreadyCorrect: number;
  reembedded: number;
  failed: number;
  skippedNoText: number;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const force = args.includes('--all');
  const dryRun = args.includes('--dry-run');

  const activeModel = config.ai.openaiApiKey && config.ai.strategy !== 'local-only'
    ? config.ai.openaiEmbedModel
    : config.ai.ollamaEmbedModel;

  logger.info({
    model: activeModel,
    backend: config.ai.openaiApiKey ? 'openai' : 'ollama',
    expectedDim: EmbeddingService.expectedDimension(),
    force,
    dryRun,
  }, 'reembed-incidents starting');

  const dbOk = await testConnection();
  if (!dbOk) {
    logger.error('Database unreachable — aborting');
    process.exit(1);
  }

  const embedOk = await EmbeddingService.isAvailable();
  if (!embedOk) {
    logger.error({ model: activeModel }, 'Embedding backend not available');
    process.exit(1);
  }

  const expectedDim = EmbeddingService.expectedDimension();
  if (!expectedDim) {
    logger.warn({ model: activeModel },
      'Unknown model dimensions — use --all to re-embed everything.');
    if (!force) process.exit(1);
  }

  const all = await db.select({
    id: incidentMemory.id,
    title: incidentMemory.title,
    category: incidentMemory.category,
    resolution: incidentMemory.resolution,
    tags: incidentMemory.tags,
    embedding: incidentMemory.embedding,
    embeddingModel: incidentMemory.embeddingModel,
  }).from(incidentMemory);

  const stats: Stats = {
    total: all.length,
    alreadyCorrect: 0,
    reembedded: 0,
    failed: 0,
    skippedNoText: 0,
  };

  for (const row of all) {
    const currentDim = Array.isArray(row.embedding) ? row.embedding.length : 0;
    const dimWrong = expectedDim ? currentDim !== expectedDim : true;
    const modelWrong = row.embeddingModel !== activeModel;
    const needsReembed = force || dimWrong || modelWrong;
    if (!needsReembed) {
      stats.alreadyCorrect++;
      continue;
    }

    const text = `${row.title} ${row.category ?? ''} ${row.resolution ?? ''} ${(row.tags ?? []).join(' ')}`.trim();
    if (!text) {
      stats.skippedNoText++;
      continue;
    }

    if (dryRun) {
      logger.info({
        id: row.id, currentDim, target: expectedDim,
        currentModel: row.embeddingModel ?? '<null>', targetModel: activeModel,
        reason: dimWrong ? 'dim-mismatch' : modelWrong ? 'model-mismatch' : 'forced',
      }, 'would re-embed');
      stats.reembedded++;
      continue;
    }

    const newEmbedding = await EmbeddingService.generate(text);
    if (!newEmbedding) {
      logger.warn({ id: row.id }, 'embedding generation returned null');
      stats.failed++;
      continue;
    }

    await db.update(incidentMemory)
      .set({ embedding: newEmbedding, embeddingModel: activeModel })
      .where(eq(incidentMemory.id, row.id));

    stats.reembedded++;
    if (stats.reembedded % 25 === 0) {
      logger.info({ done: stats.reembedded, remaining: stats.total - stats.reembedded - stats.alreadyCorrect }, 'progress');
    }
  }

  logger.info(stats, 'reembed-incidents complete');
  await closeConnection();
}

main().catch(err => {
  logger.error({ err }, 'reembed-incidents failed');
  process.exit(1);
});
