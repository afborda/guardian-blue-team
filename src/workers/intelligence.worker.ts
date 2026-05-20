import { ServerService } from '../services/server.service.js';
import { AnomalyDetector } from '../intelligence/anomaly-detector.js';
import { TrendPredictor } from '../intelligence/trend-predictor.js';
import { SSHBehaviorProfiler } from '../intelligence/ssh-behavior.js';
import { ContainerBehaviorProfiler } from '../intelligence/container-behavior.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { logger } from '../utils/logger.js';

export class IntelligenceWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly INTERVAL_MS = 60 * 60 * 1000;

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.run().catch(err => logger.error({ err }, 'Intelligence worker error'));
    }, 10 * 60 * 1000);

    this.intervalId = setInterval(() => {
      this.run().catch(err => logger.error({ err }, 'Intelligence worker error'));
    }, this.INTERVAL_MS);

    logger.info('Intelligence worker started (every 1h)');
  }

  static async run(): Promise<void> {
    try {
      const servers = await ServerService.getEnabled();
      if (servers.length === 0) return;

      let totalAnomalies = 0;
      let totalTrends = 0;
      let totalProfiles = 0;
      let totalContainerProfiles = 0;

      for (const server of servers) {
        const [anomalies, trends, profiles, containerProfiles] = await Promise.all([
          AnomalyDetector.detect(server.id),
          TrendPredictor.predict(server.id),
          SSHBehaviorProfiler.buildProfiles(server.id),
          ContainerBehaviorProfiler.buildProfiles(server.id),
        ]);

        totalAnomalies += anomalies.length;
        totalTrends += trends.length;
        totalProfiles += profiles;
        totalContainerProfiles += containerProfiles;

        const containerAnomalies = await ContainerBehaviorProfiler.detectAnomalies(server.id);
        for (const ca of containerAnomalies) {
          await this.notifyContainerAnomaly(server.name, ca);
        }

        for (const anomaly of anomalies.filter(a => a.severity === 'critical')) {
          await this.notifyAnomaly(server.name, anomaly);
        }

        for (const trend of trends.filter(t => t.daysUntil90 !== null && t.daysUntil90 < 14)) {
          await this.notifyTrend(server.name, trend);
        }
      }

      if (totalAnomalies > 0 || totalTrends > 0 || totalProfiles > 0 || totalContainerProfiles > 0) {
        logger.info({ anomalies: totalAnomalies, trends: totalTrends, sshProfiles: totalProfiles, containerProfiles: totalContainerProfiles }, 'Intelligence cycle complete');
      }
    } catch (err) {
      logger.error({ err }, 'Intelligence worker run failed');
    }
  }

  private static async notifyAnomaly(serverName: string, anomaly: any): Promise<void> {
    const method = anomaly.method ?? 'sigma';
    const unit = method === 'stl' ? 'z' : 'σ';
    await NotifierManager.notify({
      title: `Anomalia em ${serverName}`,
      body: `Métrica: ${anomaly.metric}\nValor atual: ${anomaly.currentValue} (esperado: ~${anomaly.expectedMean})\nDesvio: ${anomaly.deviations}${unit} (${method})`,
      severity: anomaly.severity === 'critical' ? 'high' : 'medium',
      metadata: { server: serverName, metric: anomaly.metric, method },
    });
  }

  private static async notifyTrend(serverName: string, trend: any): Promise<void> {
    const resource = trend.metric === 'disk' ? `Disco (${trend.mountpoint})` : 'Memória';
    await NotifierManager.notify({
      title: `Tendência de esgotamento em ${serverName}`,
      body: `${resource}: ${trend.currentPercent}% (+${trend.dailyGrowthPercent}%/dia)\nEstimativa 90%: ~${trend.daysUntil90} dias\nConfiança: ${Math.round(trend.confidence * 100)}%`,
      severity: trend.daysUntil90 < 7 ? 'high' : 'medium',
      metadata: { server: serverName, metric: trend.metric },
    });
  }

  private static async notifyContainerAnomaly(serverName: string, anomaly: { containerName: string; anomalyType: string; message: string; severity: string }): Promise<void> {
    await NotifierManager.notify({
      title: `Container ${anomaly.anomalyType} em ${serverName}`,
      body: anomaly.message,
      severity: anomaly.severity === 'critical' ? 'high' : 'medium',
      metadata: { server: serverName, container: anomaly.containerName, type: anomaly.anomalyType },
    });
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Intelligence worker stopped');
  }
}
