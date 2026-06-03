import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

// Dimensions by model name (used to detect stale embeddings after model swap).
// Stale embeddings are filtered by dimension match in findSimilar.
export const EMBEDDING_DIMENSIONS: Readonly<Record<string, number>> = {
  'text-embedding-3-small': 1536,
  'text-embedding-3-large': 3072,
  'text-embedding-ada-002': 1536,
  'bge-m3': 1024,
  'nomic-embed-text': 768,
  'mxbai-embed-large': 1024,
};

export class EmbeddingService {
  private static readonly TIMEOUT_MS = 30_000;

  static expectedDimension(): number | null {
    // OpenAI takes priority when key is present
    if (config.ai.openaiApiKey && config.ai.strategy !== 'local-only') {
      const key = config.ai.openaiEmbedModel.split(':')[0];
      return EMBEDDING_DIMENSIONS[key] ?? null;
    }
    const key = config.ai.ollamaEmbedModel.split(':')[0];
    return EMBEDDING_DIMENSIONS[key] ?? null;
  }

  static async generate(text: string): Promise<number[] | null> {
    if (config.ai.openaiApiKey && config.ai.strategy !== 'local-only') {
      return this.generateOpenAI(text);
    }
    if (config.ai.ollamaUrl && config.ai.strategy !== 'api-only') {
      return this.generateOllama(text);
    }
    return null;
  }

  private static async generateOpenAI(text: string): Promise<number[] | null> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

      const response = await fetch('https://api.openai.com/v1/embeddings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.ai.openaiApiKey}`,
        },
        body: JSON.stringify({
          model: config.ai.openaiEmbedModel,
          input: text,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);
      if (!response.ok) return null;

      const data = await response.json() as { data?: Array<{ embedding: number[] }> };
      return data.data?.[0]?.embedding ?? null;
    } catch (err) {
      logger.debug({ err }, 'OpenAI embedding failed');
      return null;
    }
  }

  private static async generateOllama(text: string): Promise<number[] | null> {
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
      logger.debug({ err }, 'Ollama embedding failed');
      return null;
    }
  }

  static cosineSimilarity(a: number[], b: number[]): number {
    if (a.length !== b.length || a.length === 0) return 0;
    let dotProduct = 0, normA = 0, normB = 0;
    for (let i = 0; i < a.length; i++) {
      dotProduct += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dotProduct / denom;
  }

  static async isAvailable(): Promise<boolean> {
    if (config.ai.openaiApiKey && config.ai.strategy !== 'local-only') return true;
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
