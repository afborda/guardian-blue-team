/**
 * Re-embed incident_memory rows after switching the embedding model.
 *
 * When OLLAMA_EMBED_MODEL changes (e.g. nomic-embed-text 768d → bge-m3 1024d),
 * existing embeddings become useless: cosineSimilarity bails on dimension
 * mismatch, so RAG silently degrades to keyword fallback. This script
 * regenerates every embedding with the currently-configured model.
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

  logger.info({
    model: config.ai.ollamaEmbedModel,
    expectedDim: EmbeddingService.expectedDimension(),
    force,
    dryRun,
  }, 'reembed-incidents starting');

  const dbOk = await testConnection();
  if (!dbOk) {
    logger.error('Database unreachable — aborting');
    process.exit(1);
  }

  const ollamaOk = await EmbeddingService.isAvailable();
  if (!ollamaOk) {
    logger.error({ model: config.ai.ollamaEmbedModel },
      'Ollama embed model not available — pull it first: ollama pull <model>');
    process.exit(1);
  }

  const expectedDim = EmbeddingService.expectedDimension();
  if (!expectedDim) {
    logger.warn({ model: config.ai.ollamaEmbedModel },
      'Unknown model — cannot pre-filter by dimension. Use --all to re-embed everything.');
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

  const currentModel = config.ai.ollamaEmbedModel;

  for (const row of all) {
    const currentDim = Array.isArray(row.embedding) ? row.embedding.length : 0;
    // Reembed when: forced; OR dimension wrong; OR row's stored model name
    // doesn't match the configured model. The model-name check catches the
    // case where two distinct models happen to share dimensionality (e.g.
    // bge-m3 ↔ mxbai-embed-large, both 1024d) — comparing dim alone would
    // silently mix vector spaces and quietly degrade RAG retrieval.
    const dimWrong = expectedDim ? currentDim !== expectedDim : true;
    const modelWrong = row.embeddingModel !== currentModel;
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
        currentModel: row.embeddingModel ?? '<null>', targetModel: currentModel,
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
      .set({ embedding: newEmbedding, embeddingModel: currentModel })
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
