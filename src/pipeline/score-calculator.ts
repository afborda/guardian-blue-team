import { db, dbDate } from '../database/connection.js';
import { serverMetrics, serverScores, securityEvents, socIncidents, cveAlerts, vulnerabilities } from '../database/schema.js';
import { eq, gte, lte, and, sql, count } from 'drizzle-orm';

export interface ScoreResult {
  serverId: number;
  healthScore: number;
  securityScore: number;
  qualityScore: number;
  wasteScore: number;
  vulnerabilityScore: number;
  availabilityScore: number;
  overallScore: number;
  details: Record<string, unknown>;
}

export class ScoreCalculator {
  static async computeForServer(serverId: number, periodStart: Date, periodEnd: Date): Promise<ScoreResult> {
    const metrics = await this.getMetricsInWindow(serverId, periodStart, periodEnd);
    const securityData = await this.getSecurityData(serverId, periodStart, periodEnd);
    const vulnData = await this.getVulnData(serverId);

    const healthScore = this.computeHealth(metrics);
    const securityScore = this.computeSecurity(securityData);
    const qualityScore = this.computeQuality(metrics);
    const wasteScore = this.computeWaste(metrics);
    const vulnerabilityScore = this.computeVulnerability(vulnData);
    const availabilityScore = this.computeAvailability(metrics);

    const overallScore = Math.round(
      healthScore * 0.20 +
      securityScore * 0.25 +
      qualityScore * 0.15 +
      wasteScore * 0.10 +
      vulnerabilityScore * 0.20 +
      availabilityScore * 0.10
    );

    return {
      serverId,
      healthScore,
      securityScore,
      qualityScore,
      wasteScore,
      vulnerabilityScore,
      availabilityScore,
      overallScore,
      details: {
        metricsCount: metrics.length,
        healthPenalties: this.getHealthPenalties(metrics),
        securityPenalties: securityData,
        qualityPenalties: this.getQualityPenalties(metrics),
      },
    };
  }

  static async persistScore(result: ScoreResult, periodStart: Date, periodEnd: Date, periodType = 'hourly'): Promise<void> {
    await db.insert(serverScores).values({
      serverId: result.serverId,
      periodStart: dbDate(periodStart),
      periodEnd: dbDate(periodEnd),
      periodType,
      healthScore: result.healthScore,
      securityScore: result.securityScore,
      qualityScore: result.qualityScore,
      wasteScore: result.wasteScore,
      vulnerabilityScore: result.vulnerabilityScore,
      availabilityScore: result.availabilityScore,
      overallScore: result.overallScore,
      scoreDetails: result.details,
    });
  }

  private static async getMetricsInWindow(serverId: number, start: Date, end: Date) {
    return db.select().from(serverMetrics).where(
      and(
        eq(serverMetrics.serverId, serverId),
        gte(serverMetrics.collectedAt, dbDate(start)),
        lte(serverMetrics.collectedAt, dbDate(end)),
      )
    );
  }

  private static async getSecurityData(serverId: number, start: Date, end: Date) {
    const [incidents] = await db
      .select({ count: count() })
      .from(socIncidents)
      .where(and(
        sql`${socIncidents.affectedServers}::text LIKE '%' || ${String(serverId)} || '%'`,
        gte(socIncidents.firstSeenAt, dbDate(start)),
        eq(socIncidents.status, 'open'),
      ));

    const [events] = await db
      .select({ count: count() })
      .from(securityEvents)
      .where(and(
        eq(securityEvents.serverId, serverId),
        gte(securityEvents.timestamp, dbDate(start)),
        lte(securityEvents.timestamp, dbDate(end)),
      ));

    return {
      openIncidents: incidents?.count ?? 0,
      eventCount: events?.count ?? 0,
    };
  }

  private static async getVulnData(serverId: number) {
    const [critical] = await db
      .select({ count: count() })
      .from(cveAlerts)
      .where(and(
        eq(cveAlerts.serverId, serverId),
        eq(cveAlerts.status, 'pending'),
        gte(cveAlerts.cvssScore, 9),
      ));

    const [high] = await db
      .select({ count: count() })
      .from(cveAlerts)
      .where(and(
        eq(cveAlerts.serverId, serverId),
        eq(cveAlerts.status, 'pending'),
        gte(cveAlerts.cvssScore, 7),
      ));

    const [openVulns] = await db
      .select({ count: count() })
      .from(vulnerabilities)
      .where(and(
        eq(vulnerabilities.serverId, serverId),
        eq(vulnerabilities.status, 'open'),
      ));

    return {
      criticalCves: critical?.count ?? 0,
      highCves: high?.count ?? 0,
      openVulnerabilities: openVulns?.count ?? 0,
    };
  }

  private static computeHealth(metrics: any[]): number {
    if (metrics.length === 0) return 50;

    let penalty = 0;
    const latest = metrics[metrics.length - 1];

    const loadRatio = (latest.load1 ?? 0) / Math.max(latest.cpuCount ?? 1, 1);
    if (loadRatio > 2.0) penalty += 40;
    else if (loadRatio > 1.5) penalty += 30;
    else if (loadRatio > 1.0) penalty += 20;
    else if (loadRatio > 0.7) penalty += 10;

    const memPercent = latest.memTotalBytes ? (latest.memUsedBytes / latest.memTotalBytes) * 100 : 0;
    if (memPercent > 95) penalty += 35;
    else if (memPercent > 85) penalty += 20;
    else if (memPercent > 70) penalty += 10;

    const disks = latest.disks ?? [];
    const maxDisk = Math.max(...disks.map((d: any) => d.usedPercent ?? 0), 0);
    if (maxDisk > 95) penalty += 35;
    else if (maxDisk > 85) penalty += 20;
    else if (maxDisk > 70) penalty += 10;

    const swapPercent = latest.swapTotalBytes ? (latest.swapUsedBytes / latest.swapTotalBytes) * 100 : 0;
    if (swapPercent > 80) penalty += 15;
    else if (swapPercent > 50) penalty += 10;

    return Math.max(0, 100 - penalty);
  }

  private static computeSecurity(data: { openIncidents: number; eventCount: number }): number {
    let penalty = 0;
    penalty += Math.min(data.openIncidents * 15, 60);
    if (data.eventCount > 100) penalty += 20;
    else if (data.eventCount > 50) penalty += 10;
    return Math.max(0, 100 - penalty);
  }

  private static computeQuality(metrics: any[]): number {
    if (metrics.length === 0) return 50;

    let penalty = 0;
    const latest = metrics[metrics.length - 1];

    const failedUnits = (latest.failedUnits ?? []).length;
    penalty += Math.min(failedUnits * 10, 40);

    const kernelErrors = latest.kernelErrors ?? 0;
    if (kernelErrors > 10) penalty += 20;
    else if (kernelErrors > 5) penalty += 10;

    const journalErrors = latest.journalErrors ?? 0;
    if (journalErrors > 20) penalty += 15;
    else if (journalErrors > 10) penalty += 10;

    const uptime = latest.uptimeSeconds ?? 0;
    if (uptime < 3600) penalty += 15;
    else if (uptime < 86400) penalty += 5;

    return Math.max(0, 100 - penalty);
  }

  private static computeWaste(metrics: any[]): number {
    if (metrics.length === 0) return 80;

    let penalty = 0;
    const latest = metrics[metrics.length - 1];

    const loadRatio = (latest.load1 ?? 0) / Math.max(latest.cpuCount ?? 1, 1);
    if (loadRatio < 0.05 && metrics.length >= 3) penalty += 15;

    const memPercent = latest.memTotalBytes ? (latest.memUsedBytes / latest.memTotalBytes) * 100 : 50;
    if (memPercent < 10 && metrics.length >= 3) penalty += 15;

    return Math.max(0, 100 - penalty);
  }

  private static computeVulnerability(data: { criticalCves: number; highCves: number; openVulnerabilities: number }): number {
    let penalty = 0;
    penalty += Math.min(data.criticalCves * 25, 50);
    penalty += Math.min(data.highCves * 10, 30);
    penalty += Math.min(data.openVulnerabilities * 5, 20);
    return Math.max(0, 100 - penalty);
  }

  private static computeAvailability(metrics: any[]): number {
    if (metrics.length === 0) return 30;

    let penalty = 0;
    const latest = metrics[metrics.length - 1];
    const uptime = latest.uptimeSeconds ?? 0;

    if (uptime < 86400) penalty += 15;
    else if (uptime < 604800) penalty += 5;

    const failedUnits = (latest.failedUnits ?? []).length;
    penalty += Math.min(failedUnits * 5, 30);

    return Math.max(0, 100 - penalty);
  }

  private static getHealthPenalties(metrics: any[]) {
    if (metrics.length === 0) return { noData: true };
    const latest = metrics[metrics.length - 1];
    return {
      loadRatio: (latest.load1 ?? 0) / Math.max(latest.cpuCount ?? 1, 1),
      memPercent: latest.memTotalBytes ? Math.round((latest.memUsedBytes / latest.memTotalBytes) * 100) : 0,
      maxDiskPercent: Math.max(...(latest.disks ?? []).map((d: any) => d.usedPercent ?? 0), 0),
      swapPercent: latest.swapTotalBytes ? Math.round((latest.swapUsedBytes / latest.swapTotalBytes) * 100) : 0,
    };
  }

  private static getQualityPenalties(metrics: any[]) {
    if (metrics.length === 0) return { noData: true };
    const latest = metrics[metrics.length - 1];
    return {
      failedUnits: (latest.failedUnits ?? []).length,
      kernelErrors: latest.kernelErrors ?? 0,
      journalErrors: latest.journalErrors ?? 0,
      uptimeSeconds: latest.uptimeSeconds ?? 0,
    };
  }
}
