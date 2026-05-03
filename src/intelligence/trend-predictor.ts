import { db, dbDate } from '../database/connection.js';
import { serverMetrics } from '../database/schema.js';
import { eq, gte, and } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export interface TrendAlert {
  serverId: number;
  metric: 'disk' | 'memory';
  mountpoint?: string;
  currentPercent: number;
  dailyGrowthPercent: number;
  daysUntil90: number | null;
  daysUntil100: number | null;
  confidence: number;
}

export class TrendPredictor {
  private static readonly LOOKBACK_DAYS = 7;
  private static readonly ALERT_THRESHOLD_DAYS = 30;

  static async predict(serverId: number): Promise<TrendAlert[]> {
    const since = new Date(Date.now() - this.LOOKBACK_DAYS * 24 * 60 * 60 * 1000);

    const metrics = await db.select().from(serverMetrics).where(
      and(
        eq(serverMetrics.serverId, serverId),
        gte(serverMetrics.collectedAt, dbDate(since)),
      )
    );

    if (metrics.length < 5) return [];

    const alerts: TrendAlert[] = [];

    const memPoints = metrics
      .filter(m => m.memTotalBytes && m.memTotalBytes > 0)
      .map((m, i) => ({
        x: i,
        y: ((m.memUsedBytes ?? 0) / m.memTotalBytes!) * 100,
      }));

    if (memPoints.length >= 5) {
      const reg = this.linearRegression(memPoints);
      if (reg.slope > 0 && reg.r2 > 0.3) {
        const current = memPoints[memPoints.length - 1].y;
        const pointsPerDay = memPoints.length / this.LOOKBACK_DAYS;
        const dailyGrowth = reg.slope * pointsPerDay;
        const daysUntil90 = current < 90 ? (90 - current) / dailyGrowth : null;
        const daysUntil100 = current < 100 ? (100 - current) / dailyGrowth : null;

        if (daysUntil90 !== null && daysUntil90 < this.ALERT_THRESHOLD_DAYS) {
          alerts.push({
            serverId,
            metric: 'memory',
            currentPercent: Math.round(current * 10) / 10,
            dailyGrowthPercent: Math.round(dailyGrowth * 100) / 100,
            daysUntil90: Math.round(daysUntil90),
            daysUntil100: daysUntil100 ? Math.round(daysUntil100) : null,
            confidence: Math.round(reg.r2 * 100) / 100,
          });
        }
      }
    }

    const diskMap = new Map<string, Array<{ x: number; y: number }>>();
    metrics.forEach((m, i) => {
      const disks = (m.disks as any[]) ?? [];
      for (const disk of disks) {
        if (!disk.mountpoint) continue;
        if (!diskMap.has(disk.mountpoint)) diskMap.set(disk.mountpoint, []);
        diskMap.get(disk.mountpoint)!.push({ x: i, y: disk.usedPercent ?? 0 });
      }
    });

    for (const [mountpoint, points] of diskMap.entries()) {
      if (points.length < 5) continue;
      const reg = this.linearRegression(points);
      if (reg.slope <= 0 || reg.r2 <= 0.3) continue;

      const current = points[points.length - 1].y;
      const pointsPerDay = points.length / this.LOOKBACK_DAYS;
      const dailyGrowth = reg.slope * pointsPerDay;
      const daysUntil90 = current < 90 ? (90 - current) / dailyGrowth : null;
      const daysUntil100 = current < 100 ? (100 - current) / dailyGrowth : null;

      if (daysUntil90 !== null && daysUntil90 < this.ALERT_THRESHOLD_DAYS) {
        alerts.push({
          serverId,
          metric: 'disk',
          mountpoint,
          currentPercent: Math.round(current * 10) / 10,
          dailyGrowthPercent: Math.round(dailyGrowth * 100) / 100,
          daysUntil90: Math.round(daysUntil90),
          daysUntil100: daysUntil100 ? Math.round(daysUntil100) : null,
          confidence: Math.round(reg.r2 * 100) / 100,
        });
      }
    }

    if (alerts.length > 0) {
      logger.debug({ serverId, alerts: alerts.length }, 'Trend alerts generated');
    }

    return alerts;
  }

  private static linearRegression(points: Array<{ x: number; y: number }>): { slope: number; intercept: number; r2: number } {
    const n = points.length;
    let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumY2 = 0;

    for (const p of points) {
      sumX += p.x;
      sumY += p.y;
      sumXY += p.x * p.y;
      sumX2 += p.x * p.x;
      sumY2 += p.y * p.y;
    }

    const denom = n * sumX2 - sumX * sumX;
    if (denom === 0) return { slope: 0, intercept: 0, r2: 0 };

    const slope = (n * sumXY - sumX * sumY) / denom;
    const intercept = (sumY - slope * sumX) / n;

    const ssRes = points.reduce((sum, p) => sum + (p.y - (slope * p.x + intercept)) ** 2, 0);
    const meanY = sumY / n;
    const ssTot = points.reduce((sum, p) => sum + (p.y - meanY) ** 2, 0);
    const r2 = ssTot === 0 ? 0 : 1 - ssRes / ssTot;

    return { slope, intercept, r2 };
  }
}
