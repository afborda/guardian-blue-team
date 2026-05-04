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
];

const UFW_PATTERN = /\[UFW (\w+)\].*SRC=([\da-fA-F.:]+)\s.*DPT=(\d+)/;

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
      metadata: { action },
    };
  }

  private static normalizeDocker(entry: RawLogEntry): NormalizedEvent | null {
    const parts = entry.line.split(' ');
    if (parts.length < 4) return null;

    const [, type, action, name] = parts;

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
    const sudoMatch = line.match(/sudo[\[:\d\]]*\s*:?\s*(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/);
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
}
