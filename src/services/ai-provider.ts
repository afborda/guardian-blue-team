import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

export type AIProviderName = 'gemini' | 'openai' | 'claude' | 'ollama';

export interface AIResponse {
  text: string;
  provider: AIProviderName;
  durationMs: number;
}

export class AIProvider {
  static async chat(prompt: string, systemPrompt?: string): Promise<AIResponse | null> {
    const providers = this.getProviderOrder();

    for (const provider of providers) {
      const start = Date.now();
      const text = await this.callProvider(provider, prompt, systemPrompt);
      if (text) {
        return { text, provider, durationMs: Date.now() - start };
      }
    }

    logger.debug('All AI providers failed or unavailable');
    return null;
  }

  static async analyze(data: object, instruction: string): Promise<AIResponse | null> {
    const prompt = `${instruction}\n\nData:\n${JSON.stringify(data, null, 2)}`;
    return this.chat(prompt, 'You are a server infrastructure analyst. Respond in concise JSON when asked for structured data, or short text for explanations.');
  }

  static isAvailable(): boolean {
    return !!(config.ai.geminiApiKey || config.ai.openaiApiKey || config.ai.anthropicApiKey || config.ai.ollamaUrl);
  }

  private static getProviderOrder(): AIProviderName[] {
    if (config.ai.provider !== 'auto') {
      const others: AIProviderName[] = ['ollama', 'gemini', 'openai', 'claude'];
      return [config.ai.provider as AIProviderName, ...others.filter(f => f !== config.ai.provider)];
    }

    // Local-first: always try Ollama before cloud providers
    const order: AIProviderName[] = ['ollama'];
    if (config.ai.geminiApiKey) order.push('gemini');
    if (config.ai.openaiApiKey) order.push('openai');
    if (config.ai.anthropicApiKey) order.push('claude');
    return order;
  }

  static getStatus(): Array<{ name: string; available: boolean; model: string; priority: number }> {
    const order = this.getProviderOrder();
    return order.map((name, i) => ({
      name,
      available: this.isProviderAvailable(name),
      model: this.getModelForProvider(name),
      priority: i + 1,
    }));
  }

  private static isProviderAvailable(name: AIProviderName): boolean {
    switch (name) {
      case 'ollama': return !!config.ai.ollamaUrl;
      case 'gemini': return !!config.ai.geminiApiKey;
      case 'openai': return !!config.ai.openaiApiKey;
      case 'claude': return !!config.ai.anthropicApiKey;
    }
  }

  private static getModelForProvider(name: AIProviderName): string {
    switch (name) {
      case 'ollama': return config.ai.ollamaModel;
      case 'gemini': return config.ai.geminiModel;
      case 'openai': return config.ai.openaiModel;
      case 'claude': return config.ai.anthropicModel;
    }
  }

  private static async callProvider(provider: AIProviderName, prompt: string, systemPrompt?: string): Promise<string | null> {
    try {
      switch (provider) {
        case 'gemini': return await this.callGemini(prompt, systemPrompt);
        case 'openai': return await this.callOpenAI(prompt, systemPrompt);
        case 'claude': return await this.callClaude(prompt, systemPrompt);
        case 'ollama': return await this.callOllama(prompt, systemPrompt);
      }
    } catch (err) {
      logger.debug({ provider, err }, 'AI provider call failed');
      return null;
    }
  }

  private static async callGemini(prompt: string, systemPrompt?: string): Promise<string | null> {
    if (!config.ai.geminiApiKey) return null;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.ai.geminiModel}:generateContent`;
    const body: any = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 2048, temperature: 0.3 },
    };
    if (systemPrompt) {
      body.systemInstruction = { parts: [{ text: systemPrompt }] };
    }

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': config.ai.geminiApiKey },
      body: JSON.stringify(body),
    });

    if (!res.ok) return null;
    const data = await res.json() as any;
    return data.candidates?.[0]?.content?.parts?.[0]?.text ?? null;
  }

  private static async callOpenAI(prompt: string, systemPrompt?: string): Promise<string | null> {
    if (!config.ai.openaiApiKey) return null;

    const messages: any[] = [];
    if (systemPrompt) messages.push({ role: 'system', content: systemPrompt });
    messages.push({ role: 'user', content: prompt });

    const model = config.ai.openaiModel;
    const isNewModel = /^(gpt-5|o[1-9])/.test(model);

    const body: Record<string, unknown> = {
      model,
      messages,
      temperature: 0.3,
    };

    if (isNewModel) {
      body.max_completion_tokens = 2048;
    } else {
      body.max_tokens = 2048;
    }

    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${config.ai.openaiApiKey}`,
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.text().catch(() => '');
      logger.debug({ model, status: res.status, err }, 'OpenAI API error');
      return null;
    }
    const data = await res.json() as any;
    return data.choices?.[0]?.message?.content ?? null;
  }

  private static async callClaude(prompt: string, systemPrompt?: string): Promise<string | null> {
    if (!config.ai.anthropicApiKey) return null;

    const body: any = {
      model: config.ai.anthropicModel,
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    };
    if (systemPrompt) body.system = systemPrompt;

    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': config.ai.anthropicApiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) return null;
    const data = await res.json() as any;
    return data.content?.[0]?.text ?? null;
  }

  private static async callOllama(prompt: string, systemPrompt?: string): Promise<string | null> {
    if (!config.ai.ollamaUrl) return null;

    const res = await fetch(`${config.ai.ollamaUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: config.ai.ollamaModel,
        prompt: systemPrompt ? `${systemPrompt}\n\n${prompt}` : prompt,
        stream: false,
      }),
      signal: AbortSignal.timeout(120_000),
    });

    if (!res.ok) return null;
    const data = await res.json() as any;
    return data.response ?? null;
  }
}
