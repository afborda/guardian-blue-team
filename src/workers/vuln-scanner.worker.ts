import { VulnScanner } from '../vuln-scanner/scanner.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { buildVulnReportSpec } from '../telegram/copy/system.js';
import { logger } from '../utils/logger.js';

export class VulnScannerWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly CHECK_INTERVAL_MS = 60 * 60 * 1000;
  private static lastScanWeek: string | null = null;

  static start(): void {
    if (this.intervalId) return;

    this.intervalId = setInterval(() => {
      this.checkAndScan().catch(err => logger.error({ err }, 'Vuln scanner check error'));
    }, this.CHECK_INTERVAL_MS);

    logger.info('Vuln scanner worker started (weekly on Saturday 09:00 BRT)');
  }

  private static async checkAndScan(): Promise<void> {
    const now = new Date();
    const brt = new Date(now.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
    const day = brt.getDay();
    const hour = brt.getHours();
    const weekKey = `${brt.getFullYear()}-W${Math.ceil((brt.getDate() + 6 - day) / 7)}`;

    if (day === 6 && hour === 9 && this.lastScanWeek !== weekKey) {
      this.lastScanWeek = weekKey;
      await this.runScan();
    }
  }

  static async runScan(): Promise<void> {
    logger.info('Starting weekly vulnerability scan...');

    const results = await VulnScanner.scanAll();
    if (results.length === 0) return;

    await NotifierManager.notifySpec(buildVulnReportSpec({
      servers: results.map(r => ({
        serverName: r.serverName,
        totalFindings: r.totalFindings,
        portsOpen: r.portsOpen,
        portsUnexpected: r.portsUnexpected,
        packagesUpgradable: r.packagesUpgradable,
        securityUpdates: r.securityUpdates,
        dockerIssues: r.dockerIssues,
        runtimeEolCount: r.runtimeEolCount,
      })),
    }));
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Vuln scanner worker stopped');
  }
}
