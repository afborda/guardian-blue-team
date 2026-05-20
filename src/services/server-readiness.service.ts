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
        logger.warn({ tool: tool.tool, server: target.host, stderr: result.stderr }, 'Tool installation failed');
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
      logger.warn({ server: target.host, stderr: result.stderr }, 'fail2ban jail setup failed');
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

  /**
   * Deploy Falco on the target host as a privileged container that monitors
   * syscalls via modern_eBPF and POSTs alerts to Guardian's webhook.
   *
   * The docker run is idempotent: if an existing `guardian-falco` container is
   * already running we replace it (so re-runs after token rotation work).
   *
   * @param target SSH target (host being monitored)
   * @param guardianBaseUrl public URL of Guardian (where Falco POSTs alerts)
   * @param token shared FALCO_WEBHOOK_TOKEN, sent as X-Falco-Token header
   * @param hostName logical host name (matches soc_servers.name) — sent as
   *                 X-Guardian-Host so the webhook can resolve serverId
   */
  static async installFalco(
    target: ReturnType<typeof ServerService.toSSHTarget> & { id: number },
    guardianBaseUrl: string,
    token: string,
    hostName: string,
  ): Promise<{ success: boolean; error?: string }> {
    const webhookUrl = `${guardianBaseUrl.replace(/\/$/, '')}/webhook/falco`;
    const image = 'falcosecurity/falco-no-driver:0.43.1';

    // Best-effort cleanup of any prior deployment so token/URL changes apply.
    await SSHCollector.run(target, 'sudo docker rm -f guardian-falco 2>/dev/null || true', 15_000);

    // Token + hostName quoted with single quotes. Single quotes work on every
    // POSIX shell (bash/dash/ash/zsh) and disable ALL interpolation inside.
    // Token is validated to not contain ' at config load (environment.ts);
    // hostName comes from soc_servers.name which is constrained by SERVER_NAME_RE.
    const headersArg = `'http_output.headers=X-Falco-Token: ${token},X-Guardian-Host: ${hostName}'`;

    const cmd = [
      `sudo docker pull ${image}`,
      `sudo docker run -d --name guardian-falco --restart unless-stopped \
       --privileged --pid host \
       -v /var/run/docker.sock:/host/var/run/docker.sock \
       -v /dev:/host/dev -v /proc:/host/proc:ro \
       -v /etc:/host/etc:ro -v /usr:/host/usr:ro \
       -v /sys/kernel/debug:/sys/kernel/debug \
       -e HOST_ROOT=/host \
       ${image} \
       /usr/bin/falco --modern-bpf \
       -o http_output.enabled=true \
       -o http_output.url=${webhookUrl} \
       -o http_output.user_agent=falco-${hostName} \
       -o ${headersArg}`,
      // Wait for Falco to actually attach to the kernel — modern_eBPF needs
      // kernel ≥5.8. If the kernel's too old, Falco exits in <1s; sleep+inspect
      // catches that instead of reporting a phantom success.
      'sleep 2',
      `sudo docker inspect -f '{{.State.Running}}' guardian-falco | grep -q true`,
    ].join(' && ');

    const result = await SSHCollector.run(target, cmd, 120_000);
    if (!result.success) {
      logger.warn({ server: target.host, error: result.error }, 'Falco install failed');
      return { success: false, error: result.error };
    }

    await ServerService.markFalcoInstalled(target.id);
    logger.info({ server: target.host, webhookUrl }, 'Falco deployed');
    return { success: true };
  }
}
