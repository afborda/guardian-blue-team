import { db, dbDate } from '../database/connection.js';
import { securityEvents, behaviorProfiles } from '../database/schema.js';
import { eq, and, gte } from 'drizzle-orm';
import { logger } from '../utils/logger.js';
import { DockerCollector } from '../collectors/docker-collector.js';
import { ServerService } from '../services/server.service.js';

export interface ContainerProfile {
  containerName: string;
  normalCPU: { mean: number; stdDev: number };
  normalMem: { mean: number; stdDev: number };
  restartCountPerWeek: number;
  avgUptimeHours: number;
  samples: number;
  lastSeen: string;
}

export interface ContainerAnomaly {
  containerName: string;
  anomalyType: 'crashloop' | 'memory_leak' | 'cpu_spike' | 'disappeared';
  score: number;
  message: string;
  severity: 'medium' | 'high' | 'critical';
}

export class ContainerBehaviorProfiler {
  private static readonly PROFILE_TYPE = 'container';
  private static readonly CRASHLOOP_THRESHOLD = 3;
  private static readonly CPU_DEVIATION_THRESHOLD = 3;
  private static readonly MEM_GROWTH_THRESHOLD = 1.5;

  static async buildProfiles(serverId: number): Promise<number> {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const dockerEvents = await db.select({
      eventType: securityEvents.eventType,
      processName: securityEvents.processName,
      timestamp: securityEvents.timestamp,
      metadata: securityEvents.metadata,
    }).from(securityEvents)
      .where(and(
        eq(securityEvents.serverId, serverId),
        eq(securityEvents.source, 'docker'),
        gte(securityEvents.timestamp, dbDate(sevenDaysAgo)),
      ));

    const containerRestarts = new Map<string, number>();
    const containerStarts = new Map<string, Date[]>();

    for (const event of dockerEvents) {
      const meta = event.metadata as Record<string, unknown> | null;
      const name = (meta?.containerName as string) || event.processName || 'unknown';

      if (event.eventType === 'docker_container_restart' || event.eventType === 'docker_container_die') {
        containerRestarts.set(name, (containerRestarts.get(name) ?? 0) + 1);
      }
      if (event.eventType === 'docker_container_start') {
        const starts = containerStarts.get(name) ?? [];
        starts.push(event.timestamp);
        containerStarts.set(name, starts);
      }
    }

    const server = await ServerService.getById(serverId);
    let currentContainers: string[] = [];
    if (server) {
      try {
        const target = ServerService.toSSHTarget(server);
        const containers = await DockerCollector.listContainers(target);
        currentContainers = containers.map(c => c.name);

        for (const container of containers) {
          if (!container.name) continue;
          const profile = await this.getOrCreateProfile(serverId, container.name);
          const updated = this.updateProfileWithSample(profile, container.cpuPercent, this.parseMemMB(container.memUsage));
          updated.restartCountPerWeek = containerRestarts.get(container.name) ?? 0;

          const starts = containerStarts.get(container.name) ?? [];
          if (starts.length >= 2) {
            const sortedStarts = starts.sort((a, b) => a.getTime() - b.getTime());
            const uptimes: number[] = [];
            for (let i = 1; i < sortedStarts.length; i++) {
              uptimes.push((sortedStarts[i].getTime() - sortedStarts[i - 1].getTime()) / 3_600_000);
            }
            updated.avgUptimeHours = uptimes.reduce((a, b) => a + b, 0) / uptimes.length;
          }

          updated.lastSeen = new Date().toISOString();
          await this.upsertProfile(serverId, container.name, updated);
        }
      } catch (err) {
        logger.debug({ err, serverId }, 'Failed to collect live container stats');
      }
    }

    const profileCount = currentContainers.length;
    if (profileCount > 0) {
      logger.debug({ serverId, profileCount }, 'Container behavior profiles updated');
    }
    return profileCount;
  }

  static async detectAnomalies(serverId: number): Promise<ContainerAnomaly[]> {
    const anomalies: ContainerAnomaly[] = [];

    const profiles = await db.select().from(behaviorProfiles)
      .where(and(
        eq(behaviorProfiles.serverId, serverId),
        eq(behaviorProfiles.profileType, this.PROFILE_TYPE),
      ));

    for (const row of profiles) {
      const profile = row.profile as unknown as ContainerProfile;
      if (profile.samples < 5) continue;

      if (profile.restartCountPerWeek >= this.CRASHLOOP_THRESHOLD) {
        const score = Math.min(1, profile.restartCountPerWeek / 10);
        anomalies.push({
          containerName: profile.containerName,
          anomalyType: 'crashloop',
          score,
          message: `${profile.containerName} restarted ${profile.restartCountPerWeek}x in the last week (normal: <${this.CRASHLOOP_THRESHOLD})`,
          severity: profile.restartCountPerWeek >= 6 ? 'critical' : 'high',
        });
      }

      if (profile.avgUptimeHours > 0 && profile.avgUptimeHours < 1) {
        anomalies.push({
          containerName: profile.containerName,
          anomalyType: 'crashloop',
          score: 0.9,
          message: `${profile.containerName} avg uptime only ${profile.avgUptimeHours.toFixed(1)}h — likely crashlooping`,
          severity: 'critical',
        });
      }
    }

    return anomalies;
  }

  static async scoreContainer(serverId: number, containerName: string, currentCPU: number, currentMemMB: number): Promise<{ score: number; factors: string[] }> {
    const row = await db.select().from(behaviorProfiles)
      .where(and(
        eq(behaviorProfiles.serverId, serverId),
        eq(behaviorProfiles.profileType, this.PROFILE_TYPE),
        eq(behaviorProfiles.subjectId, containerName),
      ))
      .then(rows => rows[0]);

    if (!row) return { score: 0.3, factors: ['no_baseline'] };

    const profile = row.profile as unknown as ContainerProfile;
    if (profile.samples < 5) return { score: 0.2, factors: ['insufficient_data'] };

    let score = 0;
    const factors: string[] = [];

    if (profile.normalCPU.stdDev > 0) {
      const cpuDeviation = (currentCPU - profile.normalCPU.mean) / profile.normalCPU.stdDev;
      if (cpuDeviation > this.CPU_DEVIATION_THRESHOLD) {
        score += Math.min(0.4, cpuDeviation / 10);
        factors.push(`cpu_${cpuDeviation.toFixed(1)}σ_above_normal`);
      }
    }

    if (profile.normalMem.mean > 0) {
      const memRatio = currentMemMB / profile.normalMem.mean;
      if (memRatio > this.MEM_GROWTH_THRESHOLD) {
        score += Math.min(0.4, (memRatio - 1) / 3);
        factors.push(`mem_${memRatio.toFixed(1)}x_normal`);
      }
    }

    if (profile.restartCountPerWeek >= this.CRASHLOOP_THRESHOLD) {
      score += 0.3;
      factors.push(`crashloop_${profile.restartCountPerWeek}_restarts`);
    }

    return { score: Math.min(score, 1), factors };
  }

  private static async getOrCreateProfile(serverId: number, containerName: string): Promise<ContainerProfile> {
    const row = await db.select().from(behaviorProfiles)
      .where(and(
        eq(behaviorProfiles.serverId, serverId),
        eq(behaviorProfiles.profileType, this.PROFILE_TYPE),
        eq(behaviorProfiles.subjectId, containerName),
      ))
      .then(rows => rows[0]);

    if (row) return row.profile as unknown as ContainerProfile;

    return {
      containerName,
      normalCPU: { mean: 0, stdDev: 0 },
      normalMem: { mean: 0, stdDev: 0 },
      restartCountPerWeek: 0,
      avgUptimeHours: 0,
      samples: 0,
      lastSeen: new Date().toISOString(),
    };
  }

  private static updateProfileWithSample(profile: ContainerProfile, cpuPercent: number, memMB: number): ContainerProfile {
    const n = profile.samples;
    const newN = n + 1;

    const newCpuMean = (profile.normalCPU.mean * n + cpuPercent) / newN;
    const newCpuStdDev = n > 0
      ? Math.sqrt(((profile.normalCPU.stdDev ** 2) * n + (cpuPercent - newCpuMean) ** 2) / newN)
      : 0;

    const newMemMean = (profile.normalMem.mean * n + memMB) / newN;
    const newMemStdDev = n > 0
      ? Math.sqrt(((profile.normalMem.stdDev ** 2) * n + (memMB - newMemMean) ** 2) / newN)
      : 0;

    return {
      ...profile,
      normalCPU: { mean: Math.round(newCpuMean * 100) / 100, stdDev: Math.round(newCpuStdDev * 100) / 100 },
      normalMem: { mean: Math.round(newMemMean * 100) / 100, stdDev: Math.round(newMemStdDev * 100) / 100 },
      samples: newN,
    };
  }

  private static async upsertProfile(serverId: number, containerName: string, profile: ContainerProfile): Promise<void> {
    const existing = await db.select({ id: behaviorProfiles.id }).from(behaviorProfiles)
      .where(and(
        eq(behaviorProfiles.serverId, serverId),
        eq(behaviorProfiles.profileType, this.PROFILE_TYPE),
        eq(behaviorProfiles.subjectId, containerName),
      ))
      .then(rows => rows[0]);

    if (existing) {
      await db.update(behaviorProfiles)
        .set({
          profile: profile as unknown as Record<string, unknown>,
          sampleCount: profile.samples,
          lastUpdatedAt: new Date(),
        })
        .where(eq(behaviorProfiles.id, existing.id));
    } else {
      await db.insert(behaviorProfiles).values({
        serverId,
        profileType: this.PROFILE_TYPE,
        subjectId: containerName,
        profile: profile as unknown as Record<string, unknown>,
        sampleCount: profile.samples,
      });
    }
  }

  private static parseMemMB(memStr: string): number {
    const match = memStr.match(/([\d.]+)\s*(GiB|MiB|KiB|GB|MB|KB)/i);
    if (!match) return 0;
    const value = parseFloat(match[1]);
    const unit = match[2].toLowerCase();
    if (unit.startsWith('g')) return value * 1024;
    if (unit.startsWith('k')) return value / 1024;
    return value;
  }
}
