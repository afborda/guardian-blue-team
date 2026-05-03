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
}
