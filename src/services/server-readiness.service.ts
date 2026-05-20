import { SSHCollector } from '../collectors/ssh-collector.js';
import { ServerService } from './server.service.js';
import { logger } from '../utils/logger.js';

export interface ReadinessCheck {
  tool: string;
  checkCmd: string;
  installCmd: string;
  required: boolean;
  description: string;
}

const CHECKS: ReadinessCheck[] = [
  {
    tool: 'ufw',
    checkCmd: 'which ufw',
    installCmd: 'sudo apt-get update -qq && sudo apt-get install -y ufw && sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw allow ssh && sudo ufw --force enable',
    required: true,
    description: 'Firewall (bloqueio de IPs)',
  },
  {
    tool: 'fail2ban',
    checkCmd: 'which fail2ban-client',
    installCmd: 'sudo apt-get update -qq && sudo apt-get install -y fail2ban',
    required: true,
    description: 'Bloqueio inteligente de IPs',
  },
  {
    tool: 'journalctl',
    checkCmd: 'which journalctl',
    installCmd: '',
    required: true,
    description: 'Logs do sistema',
  },
  {
    tool: 'ss',
    checkCmd: 'which ss',
    installCmd: 'sudo apt-get install -y iproute2',
    required: true,
    description: 'Analise de conexoes de rede',
  },
  {
    tool: 'ausearch',
    checkCmd: 'which ausearch',
    installCmd: 'sudo apt-get install -y auditd && sudo systemctl enable auditd && sudo systemctl start auditd',
    required: false,
    description: 'Logs de auditoria',
  },
];

export interface ReadinessResult {
  missing: ReadinessCheck[];
  installed: string[];
}

export interface InstallResult {
  success: string[];
  failed: string[];
}

export class ServerReadinessService {
  static async check(target: ReturnType<typeof ServerService.toSSHTarget>): Promise<ReadinessResult> {
    const missing: ReadinessCheck[] = [];
    const installed: string[] = [];

    for (const check of CHECKS) {
      const result = await SSHCollector.run(target, check.checkCmd, 5_000);
      if (result.success && result.stdout.trim()) {
        installed.push(check.tool);
      } else {
        missing.push(check);
      }
    }

    return { missing, installed };
  }

  static async install(
    target: ReturnType<typeof ServerService.toSSHTarget>,
    tools: ReadinessCheck[],
  ): Promise<InstallResult> {
    const success: string[] = [];
    const failed: string[] = [];

    for (const tool of tools) {
      if (!tool.installCmd) {
        failed.push(tool.tool);
        continue;
      }

      const result = await SSHCollector.run(target, tool.installCmd, 60_000);
      if (result.success) {
        success.push(tool.tool);
        logger.info({ tool: tool.tool, server: target.host }, 'Tool installed successfully');
      } else {
        failed.push(tool.tool);
        logger.warn({ tool: tool.tool, server: target.host, error: result.error }, 'Tool installation failed');
      }
    }

    if (success.includes('fail2ban')) {
      await this.setupFail2banJail(target);
    }

    return { success, failed };
  }

  static async setupFail2banJail(target: ReturnType<typeof ServerService.toSSHTarget>): Promise<boolean> {
    const jailConf = `[guardian-jail]
enabled = true
filter = guardian
banaction = ufw
maxretry = 1
findtime = 1
bantime = -1`;

    const filterConf = `[Definition]
failregex = ^$`;

    const cmds = [
      `echo '${jailConf}' | sudo tee /etc/fail2ban/jail.d/guardian.conf > /dev/null`,
      `echo '${filterConf}' | sudo tee /etc/fail2ban/filter.d/guardian.conf > /dev/null`,
      `sudo systemctl restart fail2ban`,
    ];

    const result = await SSHCollector.run(target, cmds.join(' && '), 15_000);
    if (result.success) {
      logger.info({ server: target.host }, 'fail2ban guardian-jail configured');
    } else {
      logger.warn({ server: target.host, error: result.error }, 'fail2ban jail setup failed');
    }
    return result.success;
  }

  static async checkUpdates(target: ReturnType<typeof ServerService.toSSHTarget>): Promise<{ available: number; security: number }> {
    const result = await SSHCollector.run(target,
      `sudo apt-get update -qq 2>/dev/null && apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0`,
      30_000,
    );

    let available = 0;
    if (result.success) {
      const num = parseInt(result.stdout.trim());
      if (!isNaN(num)) available = num;
    }

    const secResult = await SSHCollector.run(target,
      `apt list --upgradable 2>/dev/null | grep -ci security || echo 0`,
      10_000,
    );

    let security = 0;
    if (secResult.success) {
      const num = parseInt(secResult.stdout.trim());
      if (!isNaN(num)) security = num;
    }

    return { available, security };
  }
}
