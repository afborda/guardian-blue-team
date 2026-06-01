import type { RawLogEntry } from '../collectors/log-collector.js';

export interface NormalizedEvent {
  serverId: number;
  timestamp: Date;
  source: string;
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  eventType: string;
  sourceIp: string | null;
  destinationPort: number | null;
  userName: string | null;
  processName: string | null;
  rawLog: string;
  metadata: Record<string, unknown>;
}

const AUTH_PATTERNS = [
  {
    regex: /Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)/,
    type: 'ssh_failed_password',
    severity: 'low' as const,
    extract: (m: RegExpMatchArray) => ({ userName: m[1], sourceIp: m[2], destinationPort: 22 }),
  },
  {
    regex: /Invalid user (\S+) from ([\d.]+)/,
    type: 'ssh_invalid_user',
    severity: 'low' as const,
    extract: (m: RegExpMatchArray) => ({ userName: m[1], sourceIp: m[2], destinationPort: 22 }),
  },
  {
    regex: /Accepted (password|publickey) for (\S+) from ([\da-fA-F.:]+) port \d+(?: ssh2: (\S+ \S+))?/,
    type: 'ssh_login_success',
    severity: 'info' as const,
    extract: (m: RegExpMatchArray) => ({
      userName: m[2],
      sourceIp: m[3],
      destinationPort: 22,
      metadata: { authMethod: m[1], fingerprint: m[4] || null },
    }),
  },
  {
    regex: /pam_unix.*session opened for user (\S+)/,
    type: 'session_opened',
    severity: 'info' as const,
    extract: (m: RegExpMatchArray) => ({ userName: m[1], sourceIp: null, destinationPort: null }),
  },
  {
    regex: /BREAK-IN ATTEMPT/i,
    type: 'ssh_breakin_attempt',
    severity: 'high' as const,
    extract: () => ({ userName: null, sourceIp: null, destinationPort: 22 }),
  },
  {
    regex: /pam_unix\(su[:\w]*\):.*authentication failure.*user=(\S+)/,
    type: 'su_auth_failure',
    severity: 'medium' as const,
    extract: (m: RegExpMatchArray) => ({ userName: m[1], sourceIp: null, destinationPort: null }),
  },
  {
    regex: /pam_unix\((passwd|login)[:\w]*\):.*authentication failure.*user=(\S+)/,
    type: 'pam_auth_failure',
    severity: 'medium' as const,
    extract: (m: RegExpMatchArray) => ({ userName: m[2], sourceIp: null, destinationPort: null }),
  },
];

const UFW_PATTERN = /\[UFW (\w+)\].*SRC=([\da-fA-F.:]+)\s.*DPT=(\d+)/;
const UFW_SPT_PATTERN = /SPT=(\d+)/;
const UFW_DST_PATTERN = /DST=([\da-fA-F.:]+)/;

// SRC port belongs to a service that's responding to a query *we* (or our
// downstream NAT) made. These are not scans — UFW just blocks them when the
// conntrack entry has expired or the destination IP is not local (transit
// traffic, BGP weirdness). Including 53 DNS, 123 NTP, 80/443 HTTP(S) replies.
const REPLY_SERVICE_PORTS = new Set([53, 80, 123, 443]);

// CGNAT (RFC 6598) and private ranges. Packets with these as DST landing on
// our public NIC are transit junk — not aimed at us, no point alerting.
function isNonLocalDst(dst: string): boolean {
  if (!dst) return false;
  if (dst.startsWith('100.')) {
    const second = parseInt(dst.split('.')[1] ?? '0', 10);
    if (second >= 64 && second <= 127) return true; // 100.64.0.0/10
  }
  return false;
}

export class EventNormalizer {
  static normalize(entry: RawLogEntry): NormalizedEvent | null {
    switch (entry.source) {
      case 'auth.log':
        return this.normalizeAuth(entry);
      case 'ufw':
        return this.normalizeUfw(entry);
      case 'docker':
        return this.normalizeDocker(entry);
      case 'fim':
        return this.normalizeFim(entry);
      case 'sudo':
        return this.normalizeSudo(entry);
      case 'cron':
        return this.normalizeCron(entry);
      case 'dns':
        return this.normalizeDns(entry);
      case 'ssh-keys':
        return this.normalizeSshKeys(entry);
      case 'syslog':
        return this.normalizeSyslog(entry);
      case 'proxy':
        return this.normalizeProxy(entry);
      case 'package':
        return this.normalizePackage(entry);
      case 'systemd':
        return this.normalizeSystemd(entry);
      case 'audit':
        return this.normalizeAudit(entry);
      case 'container_process':
        return this.normalizeContainerProcess(entry);
      case 'container_network':
        return this.normalizeContainerNetwork(entry);
      case 'container_filesystem':
        return this.normalizeContainerFilesystem(entry);
      case 'container_config':
        return this.normalizeContainerConfig(entry);
      case 'container_image_cve':
        return this.normalizeContainerImageCve(entry);
      case 'login_history':
        return this.normalizeLoginHistory(entry);
      case 'login_failed':
        return this.normalizeLoginFailed(entry);
      case 'who':
        return this.normalizeWho(entry);
      case 'kernel':
        return this.normalizeKernel(entry);
      case 'journal_error':
        return this.normalizeJournalError(entry);
      case 'systemd_failed':
        return this.normalizeSystemdFailed(entry);
      case 'nginx_access':
        return this.normalizeNginxAccess(entry);
      case 'nginx_error':
        return this.normalizeNginxError(entry);
      case 'mysql_error':
      case 'postgres_log':
      case 'redis_log':
        return this.normalizeAppError(entry);
      case 'disk_critical':
        return this.normalizeDiskCritical(entry);
      case 'reboot':
        return this.normalizeReboot(entry);
      default:
        return null;
    }
  }

  static normalizeBatch(entries: RawLogEntry[]): NormalizedEvent[] {
    return entries
      .map(e => this.normalize(e))
      .filter((e): e is NormalizedEvent => e !== null);
  }

  private static normalizeAuth(entry: RawLogEntry): NormalizedEvent | null {
    for (const pattern of AUTH_PATTERNS) {
      const match = entry.line.match(pattern.regex);
      if (match) {
        const extracted = pattern.extract(match);
        return {
          serverId: entry.serverId,
          timestamp: entry.timestamp,
          source: 'auth.log',
          category: 'authentication',
          severity: pattern.severity,
          eventType: pattern.type,
          sourceIp: extracted.sourceIp,
          destinationPort: extracted.destinationPort,
          userName: extracted.userName,
          processName: null,
          rawLog: entry.line,
          metadata: ('metadata' in extracted ? extracted.metadata : {}) as Record<string, unknown>,
        };
      }
    }
    return null;
  }

  private static normalizeUfw(entry: RawLogEntry): NormalizedEvent | null {
    const match = entry.line.match(UFW_PATTERN);
    if (!match) return null;

    const action = match[1];
    const srcIp = match[2];
    const dstPort = parseInt(match[3]);

    const sptMatch = entry.line.match(UFW_SPT_PATTERN);
    const sourcePort = sptMatch ? parseInt(sptMatch[1]) : null;
    const dstMatch = entry.line.match(UFW_DST_PATTERN);
    const dst = dstMatch ? dstMatch[1] : '';

    // Drop service-reply traffic (NTP/DNS/HTTP[S] from SRC) and transit
    // packets aimed at non-local CGNAT destinations. Both are noise, not
    // attacks. Returning null skips the event entirely.
    const isServiceReply = sourcePort !== null && REPLY_SERVICE_PORTS.has(sourcePort);
    const isTransit = isNonLocalDst(dst);
    if (action === 'BLOCK' && (isServiceReply || isTransit)) {
      return null;
    }

    const severity = action === 'BLOCK' ? 'low' : 'info';
    const eventType = action === 'BLOCK' ? 'firewall_block' : 'firewall_allow';

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'ufw',
      category: 'network',
      severity,
      eventType,
      sourceIp: srcIp,
      destinationPort: dstPort,
      userName: null,
      processName: null,
      rawLog: entry.line,
      metadata: { action, sourcePort, dst },
    };
  }

  private static normalizeDocker(entry: RawLogEntry): NormalizedEvent | null {
    const parts = entry.line.split(' ');
    if (parts.length < 4) return null;

    const [, type, action, name] = parts;

    if (action?.startsWith('exec_') || action?.startsWith('exec ')) return null;

    const severity = action === 'die' || action === 'kill' ? 'medium' : 'info';

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'docker',
      category: 'container',
      severity,
      eventType: `docker_${action}`,
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: name || null,
      rawLog: entry.line,
      metadata: { containerAction: action, containerType: type },
    };
  }

  private static normalizeFim(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    const modifiedMatch = line.match(/^FILE_MODIFIED\s+path=(\S+)\s+old_sha256=(\S+)\s+new_sha256=(\S+)/);
    if (modifiedMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'fim',
        category: 'integrity',
        severity: 'high',
        eventType: 'file_modified',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { filePath: modifiedMatch[1], oldSha256: modifiedMatch[2], newSha256: modifiedMatch[3] },
      };
    }

    const createdMatch = line.match(/^FILE_CREATED\s+path=(\S+)\s+sha256=(\S+)/);
    if (createdMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'fim',
        category: 'integrity',
        severity: 'medium',
        eventType: 'file_created',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { filePath: createdMatch[1], sha256: createdMatch[2] },
      };
    }

    const deletedMatch = line.match(/^FILE_DELETED\s+path=(\S+)/);
    if (deletedMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'fim',
        category: 'integrity',
        severity: 'high',
        eventType: 'file_deleted',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { filePath: deletedMatch[1] },
      };
    }

    const permsMatch = line.match(/^FILE_PERMISSIONS_CHANGED\s+path=(\S+)\s+old_permissions=(\S+)\s+new_permissions=(\S+)/);
    if (permsMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'fim',
        category: 'integrity',
        severity: 'high',
        eventType: 'file_permissions_changed',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { filePath: permsMatch[1], oldPermissions: permsMatch[2], newPermissions: permsMatch[3] },
      };
    }

    const ownerMatch = line.match(/^FILE_OWNER_CHANGED\s+path=(\S+)\s+old_owner=(\S+)\s+new_owner=(\S+)/);
    if (ownerMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'fim',
        category: 'integrity',
        severity: 'high',
        eventType: 'file_modified',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { filePath: ownerMatch[1], oldOwner: ownerMatch[2], newOwner: ownerMatch[3] },
      };
    }

    return null;
  }

  private static normalizeSudo(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    // Match journalctl format: 2024-01-15T10:30:45+0000 server sudo[1234]: user : TTY=... ; USER=... ; COMMAND=...
    // Match auth.log format: Jan 15 10:30:45 server sudo:  user : TTY=... ; USER=... ; COMMAND=...
    const sudoMatch = line.match(/sudo[[\d:\]]*\s*:?\s*(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/);
    if (sudoMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'sudo',
        category: 'authentication',
        severity: 'medium',
        eventType: 'sudo_command',
        sourceIp: null,
        destinationPort: null,
        userName: sudoMatch[1],
        processName: 'sudo',
        rawLog: line,
        metadata: {
          tty: sudoMatch[2],
          pwd: sudoMatch[3],
          targetUser: sudoMatch[4],
          command: sudoMatch[5].trim(),
        },
      };
    }

    // sudo: user NOT in sudoers / is not allowed to run sudo
    const notAllowedMatch = line.match(/sudo[[\d:\]]*\s*:?\s*(\S+)\s*:.*(?:NOT in sudoers|not allowed to run sudo|not allowed to execute)/i);
    if (notAllowedMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'sudo',
        category: 'authentication',
        severity: 'high',
        eventType: 'sudo_not_allowed',
        sourceIp: null,
        destinationPort: null,
        userName: notAllowedMatch[1],
        processName: 'sudo',
        rawLog: line,
        metadata: {},
      };
    }

    // sudo authentication failure (wrong password)
    const authFailMatch = line.match(/sudo[[\d:\]]*.*(?:authentication failure|3 incorrect password)/i);
    if (authFailMatch) {
      const userMatch = line.match(/user=(\S+)/);
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'sudo',
        category: 'authentication',
        severity: 'medium',
        eventType: 'sudo_auth_failure',
        sourceIp: null,
        destinationPort: null,
        userName: userMatch ? userMatch[1] : null,
        processName: 'sudo',
        rawLog: line,
        metadata: {},
      };
    }

    return null;
  }

  private static normalizeCron(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    const addedMatch = line.match(/^CRON_ADDED\s+user=(\S+)\s+schedule="([^"]+)"\s+command="([^"]+)"/);
    if (addedMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'cron',
        category: 'persistence',
        severity: 'medium',
        eventType: 'cron_added',
        sourceIp: null,
        destinationPort: null,
        userName: addedMatch[1],
        processName: 'cron',
        rawLog: line,
        metadata: { schedule: addedMatch[2], command: addedMatch[3] },
      };
    }

    const removedMatch = line.match(/^CRON_REMOVED\s+user=(\S+)\s+schedule="([^"]+)"\s+command="([^"]+)"/);
    if (removedMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'cron',
        category: 'persistence',
        severity: 'low',
        eventType: 'cron_removed',
        sourceIp: null,
        destinationPort: null,
        userName: removedMatch[1],
        processName: 'cron',
        rawLog: line,
        metadata: { schedule: removedMatch[2], command: removedMatch[3] },
      };
    }

    return null;
  }

  private static normalizeDns(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    // Match: systemd-resolved[123]: query[A] domain from IP
    // Match: dnsmasq[456]: query[AAAA] domain from IP
    const dnsMatch = line.match(/(?:systemd-resolved|dnsmasq)\[\d+\]:\s*query\[(\w+)\]\s+(\S+)\s+from\s+([\d.]+)/);
    if (dnsMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'dns',
        category: 'network',
        severity: 'info',
        eventType: 'dns_query',
        sourceIp: dnsMatch[3],
        destinationPort: 53,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { queryType: dnsMatch[1], domain: dnsMatch[2], clientIp: dnsMatch[3] },
      };
    }

    return null;
  }

  private static normalizeSshKeys(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    const addedMatch = line.match(/^SSH_KEY_ADDED\s+user=(\S+)\s+type=(\S+)\s+fingerprint=(\S+)\s+comment="([^"]*)"/);
    if (addedMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'ssh-keys',
        category: 'credential',
        severity: 'high',
        eventType: 'ssh_key_added',
        sourceIp: null,
        destinationPort: null,
        userName: addedMatch[1],
        processName: null,
        rawLog: line,
        metadata: { keyType: addedMatch[2], fingerprint: addedMatch[3], comment: addedMatch[4] },
      };
    }

    const removedMatch = line.match(/^SSH_KEY_REMOVED\s+user=(\S+)\s+type=(\S+)\s+fingerprint=(\S+)\s+comment="([^"]*)"/);
    if (removedMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'ssh-keys',
        category: 'credential',
        severity: 'medium',
        eventType: 'ssh_key_removed',
        sourceIp: null,
        destinationPort: null,
        userName: removedMatch[1],
        processName: null,
        rawLog: line,
        metadata: { keyType: removedMatch[2], fingerprint: removedMatch[3], comment: removedMatch[4] },
      };
    }

    return null;
  }

  private static normalizeSyslog(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    if (/Out of memory: Killed process/i.test(line)) {
      const processMatch = line.match(/Killed process \d+ \(([^)]+)\)/);
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'syslog',
        category: 'system',
        severity: 'high',
        eventType: 'syslog_oom_kill',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: processMatch?.[1] ?? null,
        rawLog: line,
        metadata: { process: processMatch?.[1] },
      };
    }

    if (/segfault|core dumped|fatal error/i.test(line)) {
      const procMatch = line.match(/(\S+)\[\d+\]/) || line.match(/:\s+(\S+)\s/);
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'syslog',
        category: 'system',
        severity: 'high',
        eventType: 'syslog_service_crash',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: procMatch?.[1] ?? null,
        rawLog: line,
        metadata: {},
      };
    }

    if (/Hardware Error|I\/O error|EXT4-fs error|BTRFS error|XFS.*error|mce:/i.test(line)) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'syslog',
        category: 'system',
        severity: 'critical',
        eventType: 'syslog_hardware_error',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: {},
      };
    }

    return null;
  }

  private static normalizeProxy(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    const ipMatch = line.match(/([\d.]+)\s+-\s+-/) || line.match(/"ClientAddr":"([\d.]+)/) || line.match(/SRC=([\d.]+)/);
    const statusMatch = line.match(/" (\d{3}) /) || line.match(/"OriginStatus":(\d{3})/) || line.match(/"status":(\d+)/);
    const pathMatch = line.match(/"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s"]+)/) || line.match(/"RequestPath":"([^"]+)"/);

    const sourceIp = ipMatch?.[1] ?? null;
    const status = statusMatch ? parseInt(statusMatch[1]) : 0;
    const path = pathMatch?.[1] ?? '';

    const TRAVERSAL_PATTERNS = /\.\.[\/\\]|%2e%2e|%252e|\/etc\/passwd|\/proc\/self/i;
    const SCANNER_PATHS = /\/\.env|\/wp-login|\/wp-admin|\/phpMyAdmin|\/\.git\/|\/actuator|\/api\/swagger|\/solr\/|\/manager\/html|\/cgi-bin/i;

    if (TRAVERSAL_PATTERNS.test(path)) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'proxy',
        category: 'network',
        severity: 'high',
        eventType: 'proxy_path_traversal',
        sourceIp,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { path, status },
      };
    }

    if (SCANNER_PATHS.test(path)) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'proxy',
        category: 'network',
        severity: 'medium',
        eventType: 'proxy_scanner_detected',
        sourceIp,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { path, status },
      };
    }

    if (status >= 500) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'proxy',
        category: 'network',
        severity: 'medium',
        eventType: 'proxy_error_spike',
        sourceIp,
        destinationPort: null,
        userName: null,
        processName: null,
        rawLog: line,
        metadata: { path, status },
      };
    }

    return null;
  }

  private static normalizePackage(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    // dpkg.log: 2024-01-15 10:30:45 install package:amd64 1.2.3
    const dpkgMatch = line.match(/\d{4}-\d{2}-\d{2}\s+[\d:]+\s+(install|remove|upgrade)\s+(\S+)\s+(\S+)/);
    if (!dpkgMatch) return null;

    const action = dpkgMatch[1];
    const packageName = dpkgMatch[2].split(':')[0];
    const version = dpkgMatch[3];

    const SUSPICIOUS_PACKAGES = /nmap|masscan|hydra|john|hashcat|metasploit|aircrack|sqlmap|nikto|gobuster|wpscan|mimikatz|responder|impacket/i;
    const isSuspicious = SUSPICIOUS_PACKAGES.test(packageName);

    const eventType = isSuspicious ? 'package_suspicious' :
      action === 'install' ? 'package_installed' :
      action === 'remove' ? 'package_removed' : 'package_installed';

    const severity = isSuspicious ? 'high' : action === 'remove' ? 'low' : 'info';

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'package',
      category: 'system',
      severity,
      eventType,
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: packageName,
      rawLog: line,
      metadata: { action, package: packageName, version },
    };
  }

  private static normalizeSystemd(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    // UNIT_FAILED prefix from our custom systemctl --failed output
    const failedMatch = line.match(/^UNIT_FAILED\s+(\S+)/);
    if (failedMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'systemd',
        category: 'system',
        severity: 'medium',
        eventType: 'systemd_unit_failed',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: failedMatch[1],
        rawLog: line,
        metadata: { unit: failedMatch[1] },
      };
    }

    // Journalctl restart/failed patterns
    const unitMatch = line.match(/(\S+\.service).*(?:Failed|failed|entered failed state)/i);
    if (unitMatch) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'systemd',
        category: 'system',
        severity: 'medium',
        eventType: 'systemd_unit_failed',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: unitMatch[1],
        rawLog: line,
        metadata: { unit: unitMatch[1] },
      };
    }

    const restartMatch = line.match(/Started\s+(.+)\./i) || line.match(/(\S+\.service).*start/i);
    if (restartMatch && /restart|Restarting/i.test(line)) {
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'systemd',
        category: 'system',
        severity: 'low',
        eventType: 'systemd_unit_restarted',
        sourceIp: null,
        destinationPort: null,
        userName: null,
        processName: restartMatch[1],
        rawLog: line,
        metadata: { unit: restartMatch[1] },
      };
    }

    return null;
  }

  private static normalizeAudit(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;

    if (/ADD_USER|DEL_USER|USER_CHAUTHTOK|useradd|userdel|usermod|passwd/i.test(line)) {
      const userMatch = line.match(/acct="?(\w+)"?/) || line.match(/user=(\w+)/);
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'audit',
        category: 'authentication',
        severity: 'high',
        eventType: 'audit_user_change',
        sourceIp: null,
        destinationPort: null,
        userName: userMatch?.[1] ?? null,
        processName: null,
        rawLog: line,
        metadata: {},
      };
    }

    if (/USER_AUTH.*res=failed|ANOM_LOGIN_FAILURES|authentication failure/i.test(line)) {
      const userMatch = line.match(/acct="?(\w+)"?/) || line.match(/user=(\w+)/);
      const ipMatch = line.match(/addr=([\d.]+)/) || line.match(/src=([\d.]+)/i);
      return {
        serverId: entry.serverId,
        timestamp: entry.timestamp,
        source: 'audit',
        category: 'authentication',
        severity: 'medium',
        eventType: 'audit_auth_failure',
        sourceIp: ipMatch?.[1] ?? null,
        destinationPort: null,
        userName: userMatch?.[1] ?? null,
        processName: null,
        rawLog: line,
        metadata: {},
      };
    }

    return null;
  }

  // ─── Container Runtime Sources ──────────────────────────────────────────────

  private static normalizeContainerProcess(entry: RawLogEntry): NormalizedEvent | null {
    // Format: containerName|pid user %cpu %mem command args
    const [containerName, rest] = entry.line.split('|', 2);
    if (!containerName || !rest) return null;

    const parts = rest.trim().split(/\s+/);
    const [, , cpu, , command, ...argParts] = parts;
    const fullCommand = `${command ?? ''} ${argParts.join(' ')}`.trim();

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'container_process',
      category: 'container',
      severity: 'info',
      eventType: 'container_process_list',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: containerName,
      rawLog: entry.line,
      metadata: { containerName, command: fullCommand, cpu: parseFloat(cpu ?? '0') },
    };
  }

  private static normalizeContainerNetwork(entry: RawLogEntry): NormalizedEvent | null {
    // Format: containerName|ESTAB 0 0 local:port remote:port users:((...))
    const [containerName, rest] = entry.line.split('|', 2);
    if (!containerName || !rest) return null;

    const parts = rest.trim().split(/\s+/);
    const remoteAddr = parts[4] || '';
    const remoteParts = remoteAddr.split(':');
    const remotePort = parseInt(remoteParts.pop() ?? '0');
    const remoteIp = remoteParts.join(':');

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'container_network',
      category: 'container',
      severity: 'info',
      eventType: 'container_connection',
      sourceIp: remoteIp || null,
      destinationPort: remotePort || null,
      userName: null,
      processName: containerName,
      rawLog: entry.line,
      metadata: { containerName, remoteIp, remotePort },
    };
  }

  private static normalizeContainerFilesystem(entry: RawLogEntry): NormalizedEvent | null {
    // Format: containerName|A /tmp/xmrig  or  C /usr/bin/node
    const [containerName, rest] = entry.line.split('|', 2);
    if (!containerName || !rest) return null;

    const changeType = rest.trim().charAt(0);
    const filePath = rest.trim().slice(2).trim();

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'container_filesystem',
      category: 'container',
      severity: changeType === 'A' ? 'low' : 'info',
      eventType: changeType === 'A' ? 'container_file_added' : 'container_file_changed',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: containerName,
      rawLog: entry.line,
      metadata: { containerName, filePath, changeType },
    };
  }

  private static normalizeContainerConfig(entry: RawLogEntry): NormalizedEvent | null {
    // Format: name|IMAGE=img|RO=false|SECOPT=...|CAPDROP=...|MEM=0|CPU=0
    const parts = entry.line.split('|');
    if (parts.length < 3) return null;

    const containerName = parts[0].trim();
    const fields: Record<string, string> = {};
    for (const part of parts.slice(1)) {
      const [key, val] = part.split('=', 2);
      if (key && val !== undefined) fields[key] = val;
    }

    const readOnly = fields['RO'] === 'true';
    const hasCapDrop = (fields['CAPDROP'] ?? '').length > 2;
    const noNewPrivs = (fields['SECOPT'] ?? '').includes('no-new-privileges');
    const isInsecure = !readOnly && !hasCapDrop;

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'container_config',
      category: 'container',
      severity: isInsecure ? 'medium' : 'info',
      eventType: isInsecure ? 'container_insecure_config' : 'container_config_ok',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: containerName,
      rawLog: entry.line,
      metadata: { containerName, image: fields['IMAGE'], readOnly, noNewPrivs, hasCapDrop },
    };
  }

  private static normalizeContainerImageCve(entry: RawLogEntry): NormalizedEvent | null {
    // Format: imageName|CVE-ID|severity|cvss|pkgName|version|fixedVersion|title
    const parts = entry.line.split('|');
    if (parts.length < 7) return null;

    const [imageName, cveId, _severity, cvss, pkgName, installedVersion, fixedVersion, ...titleParts] = parts;
    const cvssScore = parseFloat(cvss ?? '0');

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'container_image_cve',
      category: 'vulnerability',
      severity: cvssScore >= 9.0 ? 'critical' : 'high',
      eventType: cvssScore >= 9.0 ? 'container_critical_cve' : 'container_high_cve',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: imageName ?? null,
      rawLog: entry.line,
      metadata: { imageName, cveId, cvss: cvssScore, pkgName, installedVersion, fixedVersion, title: titleParts.join('|') },
    };
  }

  private static normalizeLoginHistory(entry: RawLogEntry): NormalizedEvent | null {
    const user = entry.line.trim().split(/\s+/)[0];
    if (!user || user === 'reboot' || user === 'shutdown' || user === 'wtmp' || user === 'btmp') return null;

    const fromIpMatch = entry.line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    const stillLoggedIn = entry.line.includes('still logged in');
    const duration = entry.line.match(/\((\d+[+:]?\d*:\d{2})\)/)?.[1] ?? null;

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'login_history',
      category: 'authentication',
      severity: 'info',
      eventType: stillLoggedIn ? 'interactive_session_active' : 'interactive_session_history',
      sourceIp: fromIpMatch ? fromIpMatch[1] : null,
      destinationPort: null,
      userName: user,
      processName: null,
      rawLog: entry.line,
      metadata: { duration, stillLoggedIn },
    };
  }

  private static normalizeLoginFailed(entry: RawLogEntry): NormalizedEvent | null {
    const user = entry.line.trim().split(/\s+/)[0];
    if (!user || user.startsWith('-') || user === 'btmp') return null;

    const fromIpMatch = entry.line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'login_failed',
      category: 'authentication',
      severity: 'medium',
      eventType: 'interactive_login_failed',
      sourceIp: fromIpMatch ? fromIpMatch[1] : null,
      destinationPort: null,
      userName: user,
      processName: null,
      rawLog: entry.line,
      metadata: {},
    };
  }

  private static normalizeWho(entry: RawLogEntry): NormalizedEvent | null {
    const parts = entry.line.trim().split(/\s+/);
    if (parts.length < 2) return null;
    const user = parts[0];
    if (!user) return null;

    const fromIpMatch = entry.line.match(/\(([^)]+)\)/);
    const fromIp = fromIpMatch?.[1]?.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
      ? fromIpMatch[1]
      : null;

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'who',
      category: 'authentication',
      severity: 'info',
      eventType: 'interactive_session_active',
      sourceIp: fromIp,
      destinationPort: null,
      userName: user,
      processName: null,
      rawLog: entry.line,
      metadata: { tty: parts[1] ?? null },
    };
  }

  private static readonly OOM_PATTERN = /oom.kill|out of memory|oom_kill_process/i;
  private static readonly KERNEL_PANIC_PATTERN = /kernel panic|BUG:|general protection fault|unable to handle kernel/i;
  private static readonly HW_ERROR_PATTERN = /hardware error|mce.*bank|cpu.*uncorrectable|disk error/i;

  private static normalizeKernel(entry: RawLogEntry): NormalizedEvent | null {
    const line = entry.line;
    let eventType = 'kernel_error';
    let severity: NormalizedEvent['severity'] = 'medium';

    if (this.OOM_PATTERN.test(line)) {
      eventType = 'oom_kill';
      severity = 'high';
    } else if (this.KERNEL_PANIC_PATTERN.test(line)) {
      eventType = 'kernel_panic';
      severity = 'critical';
    } else if (this.HW_ERROR_PATTERN.test(line)) {
      eventType = 'hardware_error';
      severity = 'critical';
    }

    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'kernel',
      category: 'system',
      severity,
      eventType,
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: null,
      rawLog: entry.line,
      metadata: {},
    };
  }

  private static normalizeJournalError(entry: RawLogEntry): NormalizedEvent | null {
    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'journal_error',
      category: 'system',
      severity: 'medium',
      eventType: 'journal_error',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: null,
      rawLog: entry.line,
      metadata: {},
    };
  }

  private static normalizeSystemdFailed(entry: RawLogEntry): NormalizedEvent | null {
    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'systemd_failed',
      category: 'system',
      severity: 'high',
      eventType: 'service_failed',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: entry.line,
      rawLog: entry.line,
      metadata: { unit: entry.line },
    };
  }

  // nginx: 1.2.3.4 - user [15/Jan/2024:10:30:45 +0000] "GET /path HTTP/1.1" 404 1234
  private static normalizeNginxAccess(entry: RawLogEntry): NormalizedEvent | null {
    const match = entry.line.match(/^([\d.]+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+HTTP\/[\d.]+"\s+(\d+)/);
    if (!match) return null;

    const statusCode = parseInt(match[6]);
    if (statusCode < 400) return null; // only surface errors and above

    const severity: NormalizedEvent['severity'] = statusCode >= 500 ? 'high' : 'medium';
    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'nginx_access',
      category: 'web',
      severity,
      eventType: statusCode >= 500 ? 'web_server_error' : 'web_client_error',
      sourceIp: match[1],
      destinationPort: 80,
      userName: match[2] !== '-' ? match[2] : null,
      processName: 'nginx',
      rawLog: entry.line,
      metadata: { method: match[4], path: match[5], statusCode },
    };
  }

  private static normalizeNginxError(entry: RawLogEntry): NormalizedEvent | null {
    if (!entry.line.trim()) return null;
    const isCrit = /\[crit\]|\[alert\]|\[emerg\]/i.test(entry.line);
    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'nginx_error',
      category: 'web',
      severity: isCrit ? 'critical' : 'medium',
      eventType: 'web_server_error',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: 'nginx',
      rawLog: entry.line,
      metadata: {},
    };
  }

  private static normalizeAppError(entry: RawLogEntry): NormalizedEvent | null {
    if (!entry.line.trim()) return null;
    const isError = /error|fatal|critical|panic/i.test(entry.line);
    if (!isError) return null;
    const appName = entry.source.replace('_log', '').replace('_error', '');
    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: entry.source,
      category: 'application',
      severity: /fatal|critical|panic/i.test(entry.line) ? 'high' : 'medium',
      eventType: 'app_error',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: appName,
      rawLog: entry.line,
      metadata: { app: appName },
    };
  }

  private static normalizeDiskCritical(entry: RawLogEntry): NormalizedEvent | null {
    const usedMatch = entry.line.match(/used=(\d+)%/);
    const mountMatch = entry.line.match(/mount=(\S+)/);
    const usedPercent = usedMatch ? parseInt(usedMatch[1]) : 0;
    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'disk_critical',
      category: 'system',
      severity: usedPercent >= 95 ? 'critical' : 'high',
      eventType: 'disk_space_critical',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: null,
      rawLog: entry.line,
      metadata: { mountpoint: mountMatch ? mountMatch[1] : null, usedPercent },
    };
  }

  private static normalizeReboot(entry: RawLogEntry): NormalizedEvent | null {
    const uptimeMatch = entry.line.match(/uptime=(\d+)s/);
    return {
      serverId: entry.serverId,
      timestamp: entry.timestamp,
      source: 'reboot',
      category: 'system',
      severity: 'medium',
      eventType: 'system_reboot',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: null,
      rawLog: entry.line,
      metadata: { uptimeSeconds: uptimeMatch ? parseInt(uptimeMatch[1]) : null },
    };
  }
}
