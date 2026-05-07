import { db, dbDate } from '../database/connection.js';
import { serverMetrics } from '../database/schema.js';
import { eq, gte, and } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export interface Anomaly {
  serverId: number;
  metric: string;
  currentValue: number;
  expectedMean: number;
  stdDev: number;
  deviations: number;
  severity: 'warning' | 'critical';
}

export class AnomalyDetector {
  private static readonly LOOKBACK_DAYS = 7;
  private static readonly THRESHOLD = 2.5;

  static async detect(serverId: number): Promise<Anomaly[]> {
    const since = new Date(Date.now() - this.LOOKBACK_DAYS * 24 * 60 * 60 * 1000);

    const metrics = await db.select().from(serverMetrics).where(
      and(
        eq(serverMetrics.serverId, serverId),
        gte(serverMetrics.collectedAt, dbDate(since)),
      )
    );

    if (metrics.length < 10) return [];

    const latest = metrics[metrics.length - 1];
    const history = metrics.slice(0, -1);
    const anomalies: Anomaly[] = [];

    const checks: Array<{ metric: string; current: number; values: number[] }> = [
      {
        metric: 'load_ratio',
        current: (latest.load1 ?? 0) / Math.max(latest.cpuCount ?? 1, 1),
        values: history.map(m => (m.load1 ?? 0) / Math.max(m.cpuCount ?? 1, 1)),
      },
      {
        metric: 'mem_used_percent',
        current: latest.memTotalBytes ? ((latest.memUsedBytes ?? 0) / latest.memTotalBytes) * 100 : 0,
        values: history.map(m => m.memTotalBytes ? ((m.memUsedBytes ?? 0) / m.memTotalBytes) * 100 : 0),
      },
      {
        metric: 'kernel_errors',
        current: latest.kernelErrors ?? 0,
        values: history.map(m => m.kernelErrors ?? 0),
      },
      {
        metric: 'journal_errors',
        current: latest.journalErrors ?? 0,
        values: history.map(m => m.journalErrors ?? 0),
      },
    ];

    const disks = (latest.disks as any[]) ?? [];
    if (disks.length > 0) {
      const maxDisk = Math.max(...disks.map(d => d.usedPercent ?? 0));
      const histMaxDisks = history.map(m => {
        const d = (m.disks as any[]) ?? [];
        return d.length > 0 ? Math.max(...d.map(x => x.usedPercent ?? 0)) : 0;
      });
      checks.push({ metric: 'disk_max_percent', current: maxDisk, values: histMaxDisks });
    }

    // Network bandwidth anomaly detection
    const networkIo = (latest.networkIo as Array<{ iface: string; rxBps: number; txBps: number }>) ?? [];
    const totalRxBps = networkIo.reduce((sum, n) => sum + n.rxBps, 0);
    const histRxBps = history.map(m => {
      const nio = (m.networkIo as Array<{ iface: string; rxBps: number; txBps: number }>) ?? [];
      return nio.reduce((sum, n) => sum + n.rxBps, 0);
    }).filter(v => v > 0);

    if (histRxBps.length >= 3 && totalRxBps > 0) {
      checks.push({ metric: 'network_rx_bps', current: totalRxBps, values: histRxBps });
    }

    const totalTxBps = networkIo.reduce((sum, n) => sum + n.txBps, 0);
    const histTxBps = history.map(m => {
      const nio = (m.networkIo as Array<{ iface: string; rxBps: number; txBps: number }>) ?? [];
      return nio.reduce((sum, n) => sum + n.txBps, 0);
    }).filter(v => v > 0);

    if (histTxBps.length >= 3 && totalTxBps > 0) {
      checks.push({ metric: 'network_tx_bps', current: totalTxBps, values: histTxBps });
    }

    for (const check of checks) {
      if (check.values.length < 5) continue;

      const { mean, stdDev } = this.computeStats(check.values);
      if (stdDev === 0) continue;

      const deviations = Math.abs(check.current - mean) / stdDev;
      if (deviations >= this.THRESHOLD) {
        anomalies.push({
          serverId,
          metric: check.metric,
          currentValue: Math.round(check.current * 100) / 100,
          expectedMean: Math.round(mean * 100) / 100,
          stdDev: Math.round(stdDev * 100) / 100,
          deviations: Math.round(deviations * 10) / 10,
          severity: deviations >= 4 ? 'critical' : 'warning',
        });
      }
    }

    if (anomalies.length > 0) {
      logger.debug({ serverId, count: anomalies.length }, 'Anomalies detected');
    }

    return anomalies;
  }

  private static computeStats(values: number[]): { mean: number; stdDev: number } {
    const n = values.length;
    const mean = values.reduce((a, b) => a + b, 0) / n;
    const variance = values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / n;
    return { mean, stdDev: Math.sqrt(variance) };
  }
}
