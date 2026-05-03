import { VulnScanner } from '../vuln-scanner/scanner.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

export class VulnScannerWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly CHECK_INTERVAL_MS = 60 * 60 * 1000; // check every hour
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
    const day = brt.getDay(); // 6 = Saturday
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

    const lines = [
      `🔍 <b>WEEKLY VULNERABILITY REPORT</b>`,
      `📅 ${new Date().toLocaleDateString('pt-BR')}`,
      ``,
    ];

    for (const r of results) {
      const icon = r.totalFindings === 0 ? '✅' : r.totalFindings > 5 ? '🔴' : '🟡';
      lines.push(
        `${icon} <b>${r.serverName}</b>: ${r.totalFindings} finding(s)`,
        `   Portas: ${r.portsOpen} open (${r.portsUnexpected} unexpected)`,
        `   Packages: ${r.packagesUpgradable} upgradable (${r.securityUpdates} security)`,
        `   Docker: ${r.dockerIssues} issue(s)`,
        ``,
      );
    }

    try {
      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text: lines.join('\n'),
          parse_mode: 'HTML',
        }),
      });
    } catch (error) {
      logger.error({ err: error }, 'Failed to send vuln report');
    }
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Vuln scanner worker stopped');
  }
}
