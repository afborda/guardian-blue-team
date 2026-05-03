import { db } from '../database/connection.js';
import { instanceBehaviorProfiles, instanceMetrics } from '../database/schema.js';
import { eq, gte, and } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export class InstanceProfileService {
  static async buildProfile(instanceId: string): Promise<void> {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 3600 * 1000);

    const metrics = await db
      .select()
      .from(instanceMetrics)
      .where(and(
        eq(instanceMetrics.instanceId, instanceId),
        gte(instanceMetrics.timestamp, sevenDaysAgo),
      ));

    if (metrics.length < 10) return;

    const cpuValues = metrics.map(m => m.cpuPercent ?? 0).sort((a, b) => a - b);
    const memValues = metrics.map(m => m.memoryMB ?? 0).sort((a, b) => a - b);
    const netValues = metrics.map(m => m.networkOutMB ?? 0).sort((a, b) => a - b);

    const p95Index = Math.floor(metrics.length * 0.95);
    const p95Cpu = cpuValues[p95Index] ?? 0;
    const p95Mem = memValues[p95Index] ?? 0;
    const p95Net = netValues[p95Index] ?? 0;

    const avgCpu = cpuValues.reduce((a, b) => a + b, 0) / cpuValues.length;
    const avgNet = netValues.reduce((a, b) => a + b, 0) / netValues.length;

    const hourlyCpuAvg = Array.from({ length: 24 }, (_, hour) => {
      const hourMetrics = metrics.filter(m => m.timestamp.getHours() === hour);
      if (hourMetrics.length === 0) return 0;
      return hourMetrics.reduce((sum, m) => sum + (m.cpuPercent ?? 0), 0) / hourMetrics.length;
    });

    const existing = await db
      .select({ id: instanceBehaviorProfiles.id })
      .from(instanceBehaviorProfiles)
      .where(eq(instanceBehaviorProfiles.instanceId, instanceId))
      .limit(1);

    const values = {
      instanceId,
      p95CpuPercent: p95Cpu,
      p95MemoryMB: p95Mem,
      p95NetworkOutMB: p95Net,
      avgCpuPercent: avgCpu,
      avgNetworkOutMB: avgNet,
      hourlyCpuAvg,
      totalSamplesUsed: metrics.length,
      lastCalculatedAt: new Date(),
      updatedAt: new Date(),
    };

    if (existing.length > 0) {
      await db.update(instanceBehaviorProfiles)
        .set(values)
        .where(eq(instanceBehaviorProfiles.instanceId, instanceId));
    } else {
      await db.insert(instanceBehaviorProfiles).values(values);
    }

    logger.debug(`Profile rebuilt for ${instanceId} (${metrics.length} samples)`);
  }

  static async getProfileContext(
    instanceId: string,
    _currentMetrics: {
      instanceId: string;
      last30MinMetrics: { avgCPU: number; totalNetworkOut: number; avgMemory: number };
      historicalAverage: { avgCPU: number; avgMemory: number; avgNetworkOut: number };
    },
  ): Promise<string | undefined> {
    const [profile] = await db
      .select()
      .from(instanceBehaviorProfiles)
      .where(eq(instanceBehaviorProfiles.instanceId, instanceId))
      .limit(1);

    if (!profile) return undefined;

    const hour = new Date().getHours();
    const hourlyAvg = (profile.hourlyCpuAvg as number[])?.[hour] ?? 0;

    return [
      `P95 CPU: ${profile.p95CpuPercent.toFixed(1)}%, P95 Mem: ${profile.p95MemoryMB.toFixed(0)}MB, P95 Net: ${profile.p95NetworkOutMB.toFixed(1)}MB`,
      `Avg CPU for this hour: ${hourlyAvg.toFixed(1)}%`,
      `False positives: ${profile.falsePositiveCount}`,
      `Samples: ${profile.totalSamplesUsed}`,
    ].join(' | ');
  }

  static async markAsFalsePositive(instanceId: string): Promise<void> {
    const [profile] = await db
      .select()
      .from(instanceBehaviorProfiles)
      .where(eq(instanceBehaviorProfiles.instanceId, instanceId))
      .limit(1);

    if (profile) {
      await db.update(instanceBehaviorProfiles)
        .set({
          falsePositiveCount: profile.falsePositiveCount + 1,
          updatedAt: new Date(),
        })
        .where(eq(instanceBehaviorProfiles.instanceId, instanceId));
    }
  }
}
