import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { logger } from '../utils/logger.js';
import { config } from '../config/environment.js';

const PORT_SERVICES: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
  445: 'SMB', 1433: 'MSSQL', 1521: 'Oracle', 2222: 'SSH-alt',
  3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
  5900: 'VNC', 6379: 'Redis', 6881: 'BitTorrent', 8080: 'HTTP-alt',
  8443: 'HTTPS-alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
};

export interface HostSecuritySnapshot {
  serverName: string;
  bannedIpsNow: number;
  jailCounts: Record<string, number>;
  failedLoginsTotal: number;
  failedLoginsByUser: Array<{ user: string; count: number }>;
  failedLoginsByIp: Array<{ ip: string; count: number }>;
  successfulLogins: number;
  blockedByPort: Array<{ port: number; service: string; count: number }>;
  blockedTotal: number;
  uniqueAttackerIps: number;
  period: { from: Date; to: Date };
  available: boolean;
}

export class HostSecurityService {
  /**
   * Returns a synthetic target representing the Guardian host itself.
   * Returns null when HOST_SSH_KEY_PATH is unset — opt-in via config.
   * Without a key path, SSH would fail anyway and produce log spam.
   */
  static getDefaultTarget(): SSHTarget | null {
    if (!config.hostSecurity.sshKeyPath) return null;
    return {
      id: 0,
      name: 'local',
      host: config.hostSecurity.sshHost,
      sshPort: config.hostSecurity.sshPort,
      sshUser: config.hostSecurity.sshUser,
      sshKeyPath: config.hostSecurity.sshKeyPath,
    };
  }

  static async getSnapshot(target?: SSHTarget, hours = 24): Promise<HostSecuritySnapshot> {
    const t = target ?? this.getDefaultTarget();
    const now = new Date();
    const from = new Date(Date.now() - hours * 3600 * 1000);

    const empty: HostSecuritySnapshot = {
      serverName: t?.name ?? 'local',
      bannedIpsNow: 0, jailCounts: {}, failedLoginsTotal: 0,
      failedLoginsByUser: [], failedLoginsByIp: [], successfulLogins: 0,
      blockedByPort: [], blockedTotal: 0, uniqueAttackerIps: 0,
      period: { from, to: now }, available: false,
    };

    if (!t) return empty;

    try {
      const bannedResult = await SSHCollector.run(t,
        "sudo fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | grep -oP '\\d+' || echo 0"
      );
      if (!bannedResult.success) return empty;
      const bannedIpsNow = parseInt(bannedResult.stdout.trim()) || 0;

      const jailListResult = await SSHCollector.run(t,
        "sudo fail2ban-client status 2>/dev/null | grep 'Jail list' | sed 's/.*:\\s*//' | tr ',' '\\n' | tr -d ' '"
      );
      const jailCounts: Record<string, number> = {};
      for (const jail of jailListResult.stdout.trim().split('\n').filter(Boolean)) {
        const r = await SSHCollector.run(t,
          `sudo fail2ban-client status ${jail} 2>/dev/null | grep 'Currently banned' | grep -oP '\\d+' || echo 0`
        );
        jailCounts[jail] = parseInt(r.stdout.trim()) || 0;
      }

      const failedResult = await SSHCollector.run(t,
        "sudo grep -c 'Failed password\\|Invalid user' /var/log/auth.log 2>/dev/null || echo 0"
      );
      const failedLoginsTotal = parseInt(failedResult.stdout.trim()) || 0;

      const usersResult = await SSHCollector.run(t,
        "sudo grep 'Invalid user\\|Failed password' /var/log/auth.log 2>/dev/null | " +
        "grep -oP '(Invalid user \\K\\S+|Failed password for (invalid user )?\\K\\S+)' | " +
        "sort | uniq -c | sort -rn | head -8 || true"
      );
      const failedLoginsByUser = usersResult.stdout.trim().split('\n')
        .filter(Boolean)
        .map(line => {
          const m = line.trim().match(/^\s*(\d+)\s+(.+)$/);
          return m ? { user: m[2].trim(), count: parseInt(m[1]) } : null;
        })
        .filter((x): x is { user: string; count: number } => x !== null);

      const ipsResult = await SSHCollector.run(t,
        "sudo grep 'Failed password\\|Invalid user' /var/log/auth.log 2>/dev/null | " +
        "grep -oP 'from \\K[0-9.]+' | sort | uniq -c | sort -rn | head -10 || true"
      );
      const failedLoginsByIp = ipsResult.stdout.trim().split('\n')
        .filter(Boolean)
        .map(line => {
          const m = line.trim().match(/^\s*(\d+)\s+([0-9.]+)$/);
          return m ? { ip: m[2], count: parseInt(m[1]) } : null;
        })
        .filter((x): x is { ip: string; count: number } => x !== null);

      const successResult = await SSHCollector.run(t,
        "sudo grep -c 'Accepted' /var/log/auth.log 2>/dev/null || echo 0"
      );
      const successfulLogins = parseInt(successResult.stdout.trim()) || 0;

      const ufwResult = await SSHCollector.run(t,
        "sudo grep 'DPT=' /var/log/ufw.log 2>/dev/null | grep -oP 'DPT=\\K\\d+' | sort | uniq -c | sort -rn | head -10 || true"
      );
      const blockedByPort = ufwResult.stdout.trim().split('\n')
        .filter(Boolean)
        .map(line => {
          const m = line.trim().match(/^\s*(\d+)\s+(\d+)$/);
          if (!m) return null;
          const port = parseInt(m[2]);
          return { port, service: PORT_SERVICES[port] ?? `Port-${port}`, count: parseInt(m[1]) };
        })
        .filter((x): x is { port: number; service: string; count: number } => x !== null);

      const blockedTotalResult = await SSHCollector.run(t,
        "sudo grep -c 'DPT=' /var/log/ufw.log 2>/dev/null || echo 0"
      );
      const blockedTotal = parseInt(blockedTotalResult.stdout.trim()) || 0;

      return {
        serverName: t.name,
        bannedIpsNow, jailCounts, failedLoginsTotal,
        failedLoginsByUser, failedLoginsByIp, successfulLogins,
        blockedByPort, blockedTotal,
        uniqueAttackerIps: failedLoginsByIp.length,
        period: { from, to: now }, available: true,
      };
    } catch (error) {
      logger.warn({ server: t.name, err: error }, 'HostSecurityService: SSH unavailable');
      return empty;
    }
  }
}
