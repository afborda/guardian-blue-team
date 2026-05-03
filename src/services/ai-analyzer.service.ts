import { db } from '../database/connection.js';
import { abuseIncidents, instances } from '../database/schema.js';
import { eq } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { config } from '../config/environment.js';
import { InstanceProfileService } from './instance-profile.service.js';
import Docker from 'dockerode';

const docker = new Docker();

export interface MetricsData {
  instanceId: string;
  userId: string;
  planLimits: {
    name: string;
    displayName: string;
    maxCpuMillicores: number;
    maxMemoryMb: number;
    storageGb: number;
  };
  last30MinMetrics: {
    avgCPU: number;
    avgMemory: number;
    totalNetworkOut: number;
    totalDiskWrite: number;
    maxConnections: number;
    maxProcesses: number;
    samplesAbove90CpuPct: number;
    samplesAbove90MemPct: number;
    storageMB: number | null;
    totalHttp4xxRequests?: number;
    http4xxRate?: number;
    maxConcurrentRequests?: number;
    topFailedEndpoints?: string[];
  };
  historicalAverage: {
    avgCPU: number;
    avgMemory: number;
    avgNetworkOut: number;
  };
}

export interface AIAnalysisResult {
  isAbuse: boolean;
  confidence: number;
  type: string | null;
  reasoning: string;
  action: 'throttle' | 'suspend' | 'alert' | 'freeze' | 'none';
}

const alertCooldowns = new Map<string, number>();
const COOLDOWN_MS: Record<string, number> = {
  suspend: 2 * 60 * 60 * 1000,
  freeze: 2 * 60 * 60 * 1000,
  alert: 60 * 60 * 1000,
  throttle: 30 * 60 * 1000,
};

function isAlertSuppressed(instanceId: string, type: string, action: string): boolean {
  const key = `${instanceId}:${type}`;
  const lastAt = alertCooldowns.get(key);
  if (!lastAt) return false;
  return Date.now() - lastAt < (COOLDOWN_MS[action] ?? COOLDOWN_MS.alert);
}

function markAlertSent(instanceId: string, type: string): void {
  alertCooldowns.set(`${instanceId}:${type}`, Date.now());
}

const aiResultCache = new Map<string, { result: AIAnalysisResult; expiresAt: number }>();
const AI_CACHE_MS = 30 * 60 * 1000;

function getCachedResult(instanceId: string): AIAnalysisResult | null {
  const entry = aiResultCache.get(instanceId);
  if (!entry || Date.now() > entry.expiresAt) {
    aiResultCache.delete(instanceId);
    return null;
  }
  return entry.result;
}

function setCachedResult(instanceId: string, result: AIAnalysisResult): void {
  if (!result.isAbuse) {
    aiResultCache.set(instanceId, { result, expiresAt: Date.now() + AI_CACHE_MS });
  }
}

export class AIAnalyzerService {
  private get geminiUrl(): string {
    return `https://generativelanguage.googleapis.com/v1beta/models/${config.ai.geminiModel}:generateContent?key=${config.ai.geminiApiKey}`;
  }

  private redactError(msg: string): string {
    return config.ai.geminiApiKey ? msg.replace(config.ai.geminiApiKey, 'REDACTED') : msg;
  }

  async analyzeWithAI(metrics: MetricsData): Promise<AIAnalysisResult> {
    const deterministicResult = this.deterministicRules(metrics);
    if (deterministicResult) return deterministicResult;

    const m = metrics.last30MinMetrics;
    const sustainedHighCpu = m.samplesAbove90CpuPct >= 20;
    const sustainedHighMem = m.samplesAbove90MemPct >= 20;
    const highNetworkAbuse = m.totalNetworkOut > 500 * 1024 * 1024;
    const manyConnections = m.maxConnections > 100;
    const tooManyProcesses = m.maxProcesses > 50;
    const h = metrics.historicalAverage;
    const networkAnomaly = h.avgNetworkOut > 10 * 1024 * 1024
      && m.totalNetworkOut > h.avgNetworkOut * 20
      && m.totalNetworkOut > 50 * 1024 * 1024;

    const shouldCallAI = sustainedHighCpu || sustainedHighMem || highNetworkAbuse || manyConnections || tooManyProcesses || networkAnomaly;

    if (!shouldCallAI) {
      return {
        isAbuse: false,
        confidence: 95,
        type: 'legitimate',
        reasoning: `All metrics within normal range for ${metrics.planLimits.displayName} plan — AI skipped (pre-filter)`,
        action: 'none',
      };
    }

    const cached = getCachedResult(metrics.instanceId);
    if (cached) return cached;

    let profileContext: string | undefined;
    try {
      profileContext = await InstanceProfileService.getProfileContext(metrics.instanceId, {
        instanceId: metrics.instanceId,
        last30MinMetrics: {
          avgCPU: m.avgCPU,
          totalNetworkOut: m.totalNetworkOut,
          avgMemory: m.avgMemory,
        },
        historicalAverage: metrics.historicalAverage,
      });
    } catch { /* non-critical */ }

    const prompt = this.buildAnalysisPrompt(metrics, profileContext);

    if (config.ai.geminiApiKey) {
      try {
        const result = await this.analyzeWithGemini(prompt, metrics.instanceId);
        setCachedResult(metrics.instanceId, result);
        return result;
      } catch (error) {
        logger.warn({ err: error }, `Gemini failed for ${metrics.instanceId}, trying Ollama`);
      }
    }

    try {
      const result = await this.analyzeWithOllama(prompt, metrics.instanceId);
      setCachedResult(metrics.instanceId, result);
      return result;
    } catch (error) {
      logger.warn({ err: error }, `Ollama failed for ${metrics.instanceId}, using fallback rules`);
    }

    return this.fallbackRuleBasedAnalysis(metrics);
  }

  async analyzeBatch(batch: MetricsData[]): Promise<Map<string, AIAnalysisResult>> {
    const results = new Map<string, AIAnalysisResult>();
    const needsAI: MetricsData[] = [];

    for (const m of batch) {
      const det = this.deterministicRules(m);
      if (det) {
        results.set(m.instanceId, det);
      } else {
        needsAI.push(m);
      }
    }

    if (needsAI.length === 0) return results;

    if (config.ai.geminiApiKey) {
      try {
        const batchResults = await this.analyzeWithGeminiBatch(needsAI);
        for (const [id, res] of batchResults) results.set(id, res);
        return results;
      } catch (error) {
        logger.warn({ err: error }, 'Gemini batch error, falling back to individual');
      }
    }

    for (const m of needsAI) {
      const result = await this.analyzeWithAI(m);
      results.set(m.instanceId, result);
    }

    return results;
  }

  deterministicRules(metrics: MetricsData): AIAnalysisResult | null {
    const m = metrics.last30MinMetrics;
    const plan = metrics.planLimits;
    const storageMbLimit = plan.storageGb * 1024;

    const http4xx = m.totalHttp4xxRequests ?? 0;
    const failedEndpoints = m.topFailedEndpoints ?? [];
    const concurrentReqs = m.maxConcurrentRequests ?? 0;
    const http4xxRate = m.http4xxRate ?? 0;

    if (http4xx > 100 && failedEndpoints.length > 20) {
      return {
        isAbuse: true, confidence: 92, type: 'endpoint_scanning',
        reasoning: `${http4xx} requisições falhadas em ${failedEndpoints.length} endpoints — scanning`,
        action: 'throttle',
      };
    }

    if (concurrentReqs > 200 && http4xxRate > 10) {
      return {
        isAbuse: true, confidence: 88, type: 'endpoint_scanning',
        reasoning: `${concurrentReqs} requisições simultâneas + ${http4xxRate.toFixed(1)} 4xx/min — HTTP flood`,
        action: 'throttle',
      };
    }

    if (m.storageMB !== null && m.storageMB >= storageMbLimit) {
      return {
        isAbuse: false, confidence: 100, type: 'storage_limit_reached',
        reasoning: `Storage ${m.storageMB}MB atingiu 100% do limite (${plan.storageGb}GB). Container congelado.`,
        action: 'freeze',
      };
    }

    if (m.storageMB !== null && m.storageMB >= storageMbLimit * 0.95) {
      return {
        isAbuse: false, confidence: 100, type: 'storage_warning',
        reasoning: `Storage em ${((m.storageMB / storageMbLimit) * 100).toFixed(0)}% do limite.`,
        action: 'alert',
      };
    }

    if (m.maxProcesses > 100) {
      return {
        isAbuse: true, confidence: 98, type: 'fork_bomb',
        reasoning: `${m.maxProcesses} processos detectados — limite seguro é 100.`,
        action: 'suspend',
      };
    }

    return null;
  }

  async executeAction(
    instanceId: string,
    userId: string,
    action: 'throttle' | 'suspend' | 'alert' | 'freeze' | 'none',
    type: string,
    reasoning: string,
    subdomain?: string,
    _userEmail?: string,
    _userName?: string,
  ): Promise<void> {
    logger.info(`Executing action '${action}' for ${instanceId} (${subdomain || 'unknown'})`);

    switch (action) {
      case 'suspend':
        await this.suspendInstance(instanceId);
        await this.logIncident(userId, instanceId, type, 'critical', reasoning, true);
        if (!isAlertSuppressed(instanceId, type, action)) {
          markAlertSent(instanceId, type);
          await this.sendTelegramAlert(instanceId, subdomain ?? instanceId, type, reasoning, action);
        }
        await this.updateInstanceStatus(instanceId, 'suspended', `Abuse detected: ${type}`);
        break;

      case 'throttle':
        await this.throttleInstance(instanceId);
        await this.logIncident(userId, instanceId, type, 'high', reasoning, false);
        if (!isAlertSuppressed(instanceId, type, action)) {
          markAlertSent(instanceId, type);
          await this.sendTelegramAlert(instanceId, subdomain ?? instanceId, type, reasoning, action);
        }
        break;

      case 'alert':
        await this.logIncident(userId, instanceId, type, 'medium', reasoning, false);
        if (!isAlertSuppressed(instanceId, type, action)) {
          markAlertSent(instanceId, type);
          await this.sendTelegramAlert(instanceId, subdomain ?? instanceId, type, reasoning, action);
        }
        break;

      case 'freeze':
        await this.freezeInstance(instanceId);
        await this.updateInstanceStatus(instanceId, 'storage_full', reasoning);
        await this.logIncident(userId, instanceId, type, 'critical', reasoning, true);
        if (!isAlertSuppressed(instanceId, type, action)) {
          markAlertSent(instanceId, type);
          await this.sendTelegramAlert(instanceId, subdomain ?? instanceId, type, reasoning, action);
        }
        break;
    }
  }

  private async suspendInstance(instanceId: string): Promise<void> {
    try {
      const container = docker.getContainer(`n8n_${instanceId}`);
      await container.pause();
      logger.info(`Instance ${instanceId} suspended`);
    } catch (error) {
      logger.error({ err: error }, `Failed to suspend ${instanceId}`);
    }
  }

  private async freezeInstance(instanceId: string): Promise<void> {
    try {
      const container = docker.getContainer(`n8n_${instanceId}`);
      await container.pause();
      logger.info(`Instance ${instanceId} frozen (storage 100%)`);
    } catch (error) {
      logger.error({ err: error }, `Failed to freeze ${instanceId}`);
    }
  }

  private async throttleInstance(instanceId: string): Promise<void> {
    try {
      const container = docker.getContainer(`n8n_${instanceId}`);
      await container.update({
        CpuQuota: 10000,
        Memory: 256 * 1024 * 1024,
      });
      logger.info(`Instance ${instanceId} throttled`);
    } catch (error) {
      logger.error({ err: error }, `Failed to throttle ${instanceId}`);
    }
  }

  private async logIncident(
    userId: string, instanceId: string, type: string,
    severity: string, reasoning: string, autoSuspended: boolean,
  ): Promise<void> {
    try {
      await db.insert(abuseIncidents).values({
        userId, instanceId, type, severity, reasoning, autoSuspended,
        metadata: { reasoning },
        createdAt: new Date(),
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to log incident');
    }
  }

  private async updateInstanceStatus(instanceId: string, status: string, reason: string): Promise<void> {
    try {
      await db.update(instances).set({
        status,
        suspendedAt: new Date(),
        suspensionReason: reason,
        updatedAt: new Date(),
      }).where(eq(instances.clientId, instanceId));
    } catch (error) {
      logger.error({ err: error }, `Failed to update instance status for ${instanceId}`);
    }
  }

  private async sendTelegramAlert(
    _instanceId: string, label: string, type: string, reasoning: string, action: string,
  ): Promise<void> {
    const actionLabels: Record<string, string> = {
      suspend: '⏸️ SUSPENSA', throttle: '🐌 LIMITADA', alert: '👀 Monitorando', freeze: '🧊 CONGELADA',
    };
    const message = `🚨 <b>ABUSE DETECTED</b>\n\n` +
      `📦 <code>${label}</code>\n` +
      `🔍 Tipo: ${type}\n` +
      `⚡ Ação: ${actionLabels[action] ?? action}\n\n` +
      `📋 ${reasoning}`;

    try {
      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text: message,
          parse_mode: 'HTML',
        }),
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to send Telegram abuse alert');
    }
  }

  private async analyzeWithGemini(prompt: string, _instanceId: string): Promise<AIAnalysisResult> {
    const response = await fetch(this.geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.3, topP: 0.9, maxOutputTokens: 2048,
          responseMimeType: 'application/json',
          thinkingConfig: { thinkingBudget: 256 },
        },
      }),
    });

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(this.redactError(`Gemini API error: ${response.statusText} - ${errorData}`));
    }

    const data = await response.json() as any;
    const candidate = data.candidates?.[0];
    let aiResponse: string | null = null;

    if (candidate?.content?.parts) {
      for (const part of candidate.content.parts) {
        if (part.text?.includes('"isAbuse"') || part.text?.includes('"confidence"')) {
          aiResponse = part.text;
          break;
        }
        if (part.text) aiResponse = part.text;
      }
    }

    if (!aiResponse) throw new Error('No response from Gemini');
    return this.parseAIResponse(aiResponse);
  }

  private async analyzeWithGeminiBatch(batch: MetricsData[]): Promise<Map<string, AIAnalysisResult>> {
    const results = new Map<string, AIAnalysisResult>();
    const prompt = this.buildBatchPrompt(batch);

    const response = await fetch(this.geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.2, topP: 0.9, maxOutputTokens: 4096,
          responseMimeType: 'application/json',
          thinkingConfig: { thinkingBudget: 512 },
        },
      }),
    });

    if (!response.ok) throw new Error(this.redactError(`Gemini batch error: ${response.statusText}`));

    const data = await response.json() as any;
    const candidate = data.candidates?.[0];
    let aiResponse: string | null = null;
    if (candidate?.content?.parts) {
      for (const part of candidate.content.parts) {
        if (part.text && (part.text.includes('"results"') || part.text.includes('instanceId'))) {
          aiResponse = part.text;
          break;
        }
        if (part.text) aiResponse = part.text;
      }
    }
    if (!aiResponse) throw new Error('No batch response from Gemini');

    const parsed = JSON.parse(aiResponse);
    for (const item of (parsed.results || [])) {
      if (!item.instanceId) continue;
      results.set(item.instanceId, {
        isAbuse: item.isAbuse || false,
        confidence: item.confidence || 0,
        type: item.type || null,
        reasoning: item.reasoning || 'No reasoning provided',
        action: item.action || 'none',
      });
    }
    return results;
  }

  private async analyzeWithOllama(prompt: string, _instanceId: string): Promise<AIAnalysisResult> {
    const response = await fetch(`${config.ai.ollamaUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: config.ai.ollamaModel,
        prompt,
        stream: false,
        format: 'json',
        options: { temperature: 0.1, top_p: 0.9, num_predict: 256 },
      }),
    });

    if (!response.ok) throw new Error(`Ollama API error: ${response.statusText}`);
    const data = await response.json() as any;
    return this.parseAIResponse(data.response);
  }

  private buildAnalysisPrompt(metrics: MetricsData, profileContext?: string): string {
    const plan = metrics.planLimits;
    const m = metrics.last30MinMetrics;

    return `You are a cloud infrastructure abuse detection system for a managed n8n hosting platform.

**Instance on "${plan.displayName}" plan:**
- CPU limit: ${plan.maxCpuMillicores}mc (${(plan.maxCpuMillicores / 1000).toFixed(1)} vCPU)
- Memory limit: ${plan.maxMemoryMb}MB
- Storage limit: ${plan.storageGb}GB

**Metrics (Last 30 min):**
- CPU: ${m.avgCPU.toFixed(1)}% (${m.samplesAbove90CpuPct} samples ≥90%)
- Memory: ${m.avgMemory.toFixed(0)}/${plan.maxMemoryMb}MB (${((m.avgMemory / plan.maxMemoryMb) * 100).toFixed(0)}%)
- Network OUT: ${(m.totalNetworkOut / 1024 / 1024).toFixed(1)}MB
- Connections: ${m.maxConnections}, Processes: ${m.maxProcesses}
- HTTP 4xx: ${m.totalHttp4xxRequests ?? 0}

**Historical (90d):** CPU ${metrics.historicalAverage.avgCPU.toFixed(1)}%, Net ${(metrics.historicalAverage.avgNetworkOut / 1024 / 1024).toFixed(1)}MB
${profileContext ? `\n**Profile:** ${profileContext}\n` : ''}
**Abuse patterns:** crypto_mining (CPU≥90% sustained+low net), torrents (net>500MB+conn>200), ddos (net>2GB), fork_bomb (>100 procs), endpoint_scanning (>100 4xx+>20 endpoints)

Respond JSON only:
{"isAbuse":bool,"confidence":0-100,"type":"crypto_mining|torrents|ddos|endpoint_scanning|fork_bomb|resource_hijacking|anomaly|legitimate","reasoning":"brief","action":"throttle|suspend|alert|none"}`;
  }

  private buildBatchPrompt(batch: MetricsData[]): string {
    const instancesJson = batch.map(metrics => ({
      instanceId: metrics.instanceId,
      plan: metrics.planLimits.name,
      avgCpu: metrics.last30MinMetrics.avgCPU.toFixed(1),
      sustainedHighCpuSamples: metrics.last30MinMetrics.samplesAbove90CpuPct,
      avgMemMB: metrics.last30MinMetrics.avgMemory.toFixed(0),
      networkOutMB: (metrics.last30MinMetrics.totalNetworkOut / 1024 / 1024).toFixed(1),
      maxConnections: metrics.last30MinMetrics.maxConnections,
      maxProcesses: metrics.last30MinMetrics.maxProcesses,
    }));

    return `Analyze ${batch.length} n8n instances for abuse. Only flag REAL abuse (sustained ≥20min).

Instances: ${JSON.stringify(instancesJson)}

Respond JSON: {"results":[{"instanceId":"...","isAbuse":bool,"confidence":0-100,"type":"...","reasoning":"...","action":"throttle|suspend|alert|none"}]}`;
  }

  private parseAIResponse(response: string): AIAnalysisResult {
    try {
      const parsed = JSON.parse(response);
      if (typeof parsed.isAbuse !== 'undefined') {
        return {
          isAbuse: parsed.isAbuse || false,
          confidence: parsed.confidence || 0,
          type: parsed.type || null,
          reasoning: parsed.reasoning || 'No reasoning',
          action: parsed.action || 'none',
        };
      }
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) return this.parseAIResponse(jsonMatch[0]);
    } catch { /* fall through */ }

    return { isAbuse: false, confidence: 0, type: null, reasoning: 'Failed to parse AI response', action: 'none' };
  }

  private fallbackRuleBasedAnalysis(metrics: MetricsData): AIAnalysisResult {
    const m = metrics.last30MinMetrics;

    if (m.samplesAbove90CpuPct >= 20 && m.totalNetworkOut < 100 * 1024 * 1024) {
      return { isAbuse: true, confidence: 85, type: 'crypto_mining', reasoning: 'Sustained high CPU + low network', action: 'suspend' };
    }
    if (m.totalNetworkOut > 500 * 1024 * 1024 && m.maxConnections > 200) {
      return { isAbuse: true, confidence: 90, type: 'torrents', reasoning: 'High network + many connections', action: 'suspend' };
    }
    if (m.totalNetworkOut > 2 * 1024 * 1024 * 1024) {
      return { isAbuse: true, confidence: 80, type: 'ddos', reasoning: 'Extreme outbound network', action: 'throttle' };
    }

    return { isAbuse: false, confidence: 90, type: 'legitimate', reasoning: 'Metrics within normal range', action: 'none' };
  }
}

export default new AIAnalyzerService();
