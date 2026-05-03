import { db } from '../database/connection.js';
import { instanceMetrics, instances, users, plans } from '../database/schema.js';
import { eq, desc, and, gte, sql } from 'drizzle-orm';
import aiAnalyzer from '../services/ai-analyzer.service.js';
import { GuardianDecisionService } from '../services/guardian-decision.service.js';
import { logger } from '../utils/logger.js';
import { config } from '../config/environment.js';

export class AbuseDetectionWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static isRunning = false;
  private static isShuttingDown = false;
  private static readonly INTERVAL_MS = 5 * 60 * 1000;

  static start(): void {
    if (this.intervalId) return;
    this.isShuttingDown = false;

    setTimeout(() => {
      this.runAnalysis().catch(err => logger.error({ err }, 'Initial abuse analysis error'));
    }, 2 * 60 * 1000);

    this.intervalId = setInterval(() => {
      this.runAnalysis().catch(err => logger.error({ err }, 'Abuse analysis error'));
    }, this.INTERVAL_MS);

    logger.info('Abuse detection worker started (every 5min)');
  }

  private static async runAnalysis(): Promise<void> {
    if (this.isShuttingDown || this.isRunning) return;
    this.isRunning = true;
    try {
      await this.analyzeAllInstances();
    } finally {
      this.isRunning = false;
    }
  }

  private static async analyzeAllInstances(): Promise<void> {
    const activeInstances = await db
      .select({
        id: instances.id,
        clientId: instances.clientId,
        subdomain: instances.subdomain,
        userId: instances.userId,
        userName: users.name,
        userEmail: users.email,
        planName: plans.name,
        planDisplayName: plans.displayName,
        maxCpuMillicores: plans.maxCpuMillicores,
        maxMemoryMb: plans.maxMemoryMb,
        storageGb: plans.storageGb,
      })
      .from(instances)
      .leftJoin(users, eq(instances.userId, users.id))
      .innerJoin(plans, eq(instances.planId, plans.id))
      .where(eq(instances.status, 'active'));

    if (activeInstances.length === 0) {
      logger.debug('No active instances, skipping abuse check');
      return;
    }

    logger.info(`Analyzing ${activeInstances.length} active instances`);

    const metricsDataList: Array<{
      metricsData: Parameters<typeof aiAnalyzer.analyzeWithAI>[0];
      instanceInfo: typeof activeInstances[0];
    }> = [];

    for (const instance of activeInstances) {
      try {
        const data = await this.collectInstanceMetrics(
          instance.clientId,
          instance.userId || 'unknown',
          {
            name: instance.planName,
            displayName: instance.planDisplayName ?? instance.planName,
            maxCpuMillicores: instance.maxCpuMillicores ?? 1000,
            maxMemoryMb: instance.maxMemoryMb ?? 1536,
            storageGb: instance.storageGb ?? 10,
          },
        );
        if (data) metricsDataList.push({ metricsData: data, instanceInfo: instance });
      } catch (error) {
        logger.error({ err: error }, `Error collecting metrics for ${instance.clientId}`);
      }
    }

    if (metricsDataList.length === 0) return;

    const BATCH_SIZE = 10;
    for (let i = 0; i < metricsDataList.length; i += BATCH_SIZE) {
      const batch = metricsDataList.slice(i, i + BATCH_SIZE);
      const batchMetrics = batch.map(b => b.metricsData);

      const results = await aiAnalyzer.analyzeBatch(batchMetrics);
      const CRITICAL_TYPES = ['crypto_mining', 'torrents', 'ddos', 'fork_bomb'];

      for (const { metricsData, instanceInfo } of batch) {
        const aiResult = results.get(metricsData.instanceId);
        if (!aiResult) continue;

        const subdomain = instanceInfo.subdomain ?? undefined;
        const userEmail = instanceInfo.userEmail ?? undefined;
        const userName = instanceInfo.userName ?? 'Cliente';

        if (aiResult.action === 'freeze') {
          await aiAnalyzer.executeAction(
            metricsData.instanceId, metricsData.userId, aiResult.action,
            aiResult.type || 'unknown', aiResult.reasoning, subdomain, userEmail, userName,
          );
          continue;
        }

        const isCritical = aiResult.isAbuse
          && aiResult.confidence >= 85
          && CRITICAL_TYPES.includes(aiResult.type ?? '');

        if (isCritical) {
          await aiAnalyzer.executeAction(
            metricsData.instanceId, metricsData.userId, aiResult.action,
            aiResult.type || 'unknown', aiResult.reasoning, subdomain, userEmail, userName,
          );
        } else if (aiResult.isAbuse && aiResult.confidence >= config.abuse.confidenceThreshold) {
          await GuardianDecisionService.proposeAction(
            metricsData.instanceId, metricsData.userId, aiResult, subdomain, userEmail,
          );
        }
      }

      GuardianDecisionService.expireOldDecisions().catch(err =>
        logger.warn({ err }, 'expireOldDecisions error')
      );
    }

    logger.info('Abuse detection cycle completed');
  }

  private static async collectInstanceMetrics(
    instanceId: string, userId: string,
    planLimits: { name: string; displayName: string; maxCpuMillicores: number; maxMemoryMb: number; storageGb: number },
  ) {
    const thirtyMinutesAgo = new Date(Date.now() - 30 * 60 * 1000);

    const recentMetrics = await db
      .select()
      .from(instanceMetrics)
      .where(and(
        eq(instanceMetrics.instanceId, instanceId),
        gte(instanceMetrics.timestamp, thirtyMinutesAgo),
      ))
      .orderBy(desc(instanceMetrics.timestamp));

    if (recentMetrics.length === 0) return null;

    const totalSamples = recentMetrics.length;
    const avgCPU = recentMetrics.reduce((sum, m) => sum + (m.cpuPercent || 0), 0) / totalSamples;
    const avgMemory = recentMetrics.reduce((sum, m) => sum + (m.memoryMB || 0), 0) / totalSamples;
    const totalNetworkOut = recentMetrics.reduce((sum, m) => sum + (m.networkOutMB || 0), 0);
    const totalDiskWrite = recentMetrics.reduce((sum, m) => sum + (m.diskWriteMB || 0), 0);
    const maxConnections = Math.max(...recentMetrics.map(m => m.activeConnections || 0));
    const maxProcesses = Math.max(...recentMetrics.map(m => m.processCount || 0));

    const metricsWithHttp = recentMetrics.filter(m => m.http4xxRate !== null);
    const avgHttp4xxRate = metricsWithHttp.length > 0
      ? metricsWithHttp.reduce((sum, m) => sum + (m.http4xxRate ?? 0), 0) / metricsWithHttp.length
      : null;
    const totalHttp4xxCount = metricsWithHttp.reduce((sum, m) => sum + (m.totalHttp4xxRequests ?? 0), 0);
    const allFailedEndpoints: string[] = recentMetrics.flatMap(m => (m.topFailedEndpoints as string[] | null) ?? []);
    const topFailedEndpoints = [...new Set(allFailedEndpoints)].slice(0, 15);

    const samplesAbove90CpuPct = recentMetrics.filter(m => (m.cpuPercent || 0) >= 90).length;
    const memThreshold = planLimits.maxMemoryMb * 0.9;
    const samplesAbove90MemPct = recentMetrics.filter(m => (m.memoryMB || 0) >= memThreshold).length;
    const latestWithStorage = recentMetrics.find(m => m.storageMB !== null);
    const storageMB = latestWithStorage?.storageMB ?? null;

    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    const historicalMetrics = await db
      .select({
        avgCPU: sql<number>`AVG(${instanceMetrics.cpuPercent})`.as('avg_cpu'),
        avgMemory: sql<number>`AVG(${instanceMetrics.memoryMB})`.as('avg_memory'),
        avgNetworkOut: sql<number>`AVG(${instanceMetrics.networkOutMB})`.as('avg_network_out'),
      })
      .from(instanceMetrics)
      .where(and(
        eq(instanceMetrics.instanceId, instanceId),
        gte(instanceMetrics.timestamp, ninetyDaysAgo),
      ));

    const historical = historicalMetrics[0] || { avgCPU: 0, avgMemory: 0, avgNetworkOut: 0 };

    return {
      instanceId, userId, planLimits,
      last30MinMetrics: {
        avgCPU, avgMemory,
        totalNetworkOut: totalNetworkOut * 1024 * 1024,
        totalDiskWrite: totalDiskWrite * 1024 * 1024,
        maxConnections, maxProcesses,
        samplesAbove90CpuPct, samplesAbove90MemPct,
        storageMB,
        ...(avgHttp4xxRate !== null ? { http4xxRate: avgHttp4xxRate } : {}),
        ...(totalHttp4xxCount > 0 ? { totalHttp4xxRequests: totalHttp4xxCount } : {}),
        topFailedEndpoints,
      },
      historicalAverage: {
        avgCPU: historical.avgCPU || 0,
        avgMemory: historical.avgMemory || 0,
        avgNetworkOut: (historical.avgNetworkOut || 0) * 1024 * 1024,
      },
    };
  }

  static async triggerAnalysis(): Promise<void> {
    return this.runAnalysis();
  }

  static async stop(): Promise<void> {
    this.isShuttingDown = true;
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    const start = Date.now();
    while (this.isRunning && Date.now() - start < 5000) {
      await new Promise(r => setTimeout(r, 100));
    }
    logger.info('Abuse detection worker stopped');
  }
}
