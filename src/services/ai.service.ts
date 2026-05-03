import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

export interface AIResponse {
  text: string;
  provider: 'gemini' | 'ollama';
}

export class AIService {
  static isAvailable(): boolean {
    return !!config.ai.geminiApiKey || !!config.ai.ollamaUrl;
  }

  static async ask(prompt: string, options?: { maxTokens?: number; temperature?: number }): Promise<string | null> {
    if (config.ai.geminiApiKey) {
      return this.callGemini(prompt, options);
    }
    return this.callOllama(prompt, options);
  }

  private static async callGemini(prompt: string, options?: { maxTokens?: number; temperature?: number }): Promise<string | null> {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.ai.geminiModel}:generateContent?key=${config.ai.geminiApiKey}`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: options?.temperature ?? 0.3,
            maxOutputTokens: options?.maxTokens ?? 1024,
          },
        }),
      });

      if (!response.ok) {
        logger.warn({ status: response.status }, 'AI Gemini call failed');
        return this.callOllama(prompt, options);
      }

      const data = await response.json() as { candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }> };
      return data.candidates?.[0]?.content?.parts?.map(p => p.text).filter(Boolean).join('') ?? null;
    } catch (err) {
      logger.error({ err }, 'AI Gemini error, falling back to Ollama');
      return this.callOllama(prompt, options);
    }
  }

  private static async callOllama(prompt: string, options?: { maxTokens?: number; temperature?: number }): Promise<string | null> {
    if (!config.ai.ollamaUrl) return null;

    try {
      const response = await fetch(`${config.ai.ollamaUrl}/api/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: config.ai.ollamaModel,
          prompt,
          stream: false,
          options: {
            temperature: options?.temperature ?? 0.3,
            num_predict: options?.maxTokens ?? 1024,
          },
        }),
      });

      if (!response.ok) {
        logger.warn({ status: response.status }, 'AI Ollama call failed');
        return null;
      }

      const data = await response.json() as { response?: string };
      return data.response ?? null;
    } catch (err) {
      logger.error({ err }, 'AI Ollama error');
      return null;
    }
  }
}
