import { ServerService } from '../services/server.service.js';
import { HealthCollector } from '../collectors/health-collector.js';
import { SystemCollector } from '../collectors/system-collector.js';
import { PerformanceCollector } from '../collectors/performance-collector.js';
import { MetricsIngestor, type MetricsBundle } from '../pipeline/metrics-ingestor.js';
import { ScoreCalculator } from '../pipeline/score-calculator.js';
import { logger } from '../utils/logger.js';

export class ScoreCalculatorWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly COLLECTION_INTERVAL_MS = 5 * 60 * 1000;
  private static readonly SCORE_INTERVAL_MS = 60 * 60 * 1000;
  private static scoreIntervalId: NodeJS.Timeout | null = null;
  private static running = false;

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.collectMetrics().catch(err => logger.error({ err }, 'Metrics collection error'));
    }, 30_000);

    this.intervalId = setInterval(() => {
      this.collectMetrics().catch(err => logger.error({ err }, 'Metrics collection error'));
    }, this.COLLECTION_INTERVAL_MS);

    setTimeout(() => {
      this.computeScores().catch(err => logger.error({ err }, 'Score computation error'));
    }, 5 * 60 * 1000);

    this.scoreIntervalId = setInterval(() => {
      this.computeScores().catch(err => logger.error({ err }, 'Score computation error'));
    }, this.SCORE_INTERVAL_MS);

    logger.info('Score calculator worker started (metrics: 5min, scores: 1h)');
  }

  static async collectMetrics(): Promise<void> {
    if (this.running) return;
    this.running = true;

    try {
      const servers = await ServerService.getEnabled();
      if (servers.length === 0) return;

      const bundles: MetricsBundle[] = [];

      for (const server of servers) {
        const target = ServerService.toSSHTarget(server);
        const [health, system, performance] = await Promise.all([
          HealthCollector.collect(target),
          SystemCollector.collect(target),
          PerformanceCollector.collect(target),
        ]);
        bundles.push({ health, system, performance });
      }

      const persisted = await MetricsIngestor.persist(bundles);
      if (persisted > 0) {
        logger.debug({ count: persisted }, 'Infrastructure metrics collected');
      }
    } finally {
      this.running = false;
    }
  }

  static async computeScores(): Promise<void> {
    try {
      const servers = await ServerService.getEnabled();
      if (servers.length === 0) return;

      const now = new Date();
      const periodEnd = now;
      const periodStart = new Date(now.getTime() - 60 * 60 * 1000);

      for (const server of servers) {
        const result = await ScoreCalculator.computeForServer(server.id, periodStart, periodEnd);
        await ScoreCalculator.persistScore(result, periodStart, periodEnd);
        logger.debug({ server: server.name, overall: result.overallScore }, 'Score computed');
      }

      logger.info({ servers: servers.length }, 'Server scores computed');
    } catch (err) {
      logger.error({ err }, 'Score computation failed');
    }
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    if (this.scoreIntervalId) {
      clearInterval(this.scoreIntervalId);
      this.scoreIntervalId = null;
    }
    this.running = false;
    logger.info('Score calculator worker stopped');
  }
}
