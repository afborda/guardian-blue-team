import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

// bge-m3 produces 1024d vectors; nomic-embed-text produced 768d.
// Stale embeddings from prior models are filtered by dimension match in findSimilar.
export const EMBEDDING_DIMENSIONS: Readonly<Record<string, number>> = {
  'bge-m3': 1024,
  'nomic-embed-text': 768,
  'mxbai-embed-large': 1024,
};

export class EmbeddingService {
  private static readonly TIMEOUT_MS = 30_000;

  /** Expected dimension for the currently configured embed model. */
  static expectedDimension(): number | null {
    const modelKey = config.ai.ollamaEmbedModel.split(':')[0]; // strip ":latest" tag if present
    return EMBEDDING_DIMENSIONS[modelKey] ?? null;
  }

  static async generate(text: string): Promise<number[] | null> {
    if (!config.ai.ollamaUrl || config.ai.strategy === 'api-only') return null;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

      const response = await fetch(`${config.ai.ollamaUrl}/api/embeddings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: config.ai.ollamaEmbedModel, prompt: text }),
        signal: controller.signal,
      });

      clearTimeout(timeout);
      if (!response.ok) return null;

      const data = await response.json() as { embedding?: number[] };
      return data.embedding ?? null;
    } catch (err) {
      logger.debug({ err }, 'Embedding generation failed (Ollama may be unavailable)');
      return null;
    }
  }

  static cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length || a.length === 0) return 0;
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    const denominator = Math.sqrt(normA) * Math.sqrt(normB);
    return denominator === 0 ? 0 : dotProduct / denominator;
  }

  static async isAvailable(): Promise<boolean> {
    if (!config.ai.ollamaUrl || config.ai.strategy === 'api-only') return false;
    try {
      const res = await fetch(`${config.ai.ollamaUrl}/api/tags`, { method: 'GET' });
      if (!res.ok) return false;
      const data = await res.json() as { models?: Array<{ name: string }> };
      const expected = config.ai.ollamaEmbedModel.split(':')[0];
      return data.models?.some(m => m.name.split(':')[0] === expected) ?? false;
    } catch {
      return false;
    }
  }
}
