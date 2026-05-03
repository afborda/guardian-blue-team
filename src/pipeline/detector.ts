import type { NormalizedEvent } from './normalizer.js';
import { logger } from '../utils/logger.js';

export interface DetectionRule {
  name: string;
  description: string;
  condition: (events: NormalizedEvent[], current: NormalizedEvent) => boolean;
  severity: NormalizedEvent['severity'];
  eventType: string;
}

// IPs that are expected to login — add your admin IPs here
const TRUSTED_IPS = new Set([
  '203.0.113.10',   // Home IP
  '203.0.113.11',    // synthfin-direct
  '203.0.113.12',     // ovh-automabothub (old IP)
  '203.0.113.13',      // ovh-automabothub
  '203.0.113.14',     // ovh-spark
  '203.0.113.15',    // GCP Cloud Shell / deploy
]);

function isTrustedIp(ip: string): boolean {
  if (TRUSTED_IPS.has(ip)) return true;
  if (ip.startsWith('172.') || ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  return false;
}

const TRUSTED_FINGERPRINTS = new Set([
  'SHA256:REDACTED_FINGERPRINT_1',
  'SHA256:REDACTED_FINGERPRINT_2',
  'SHA256:REDACTED_FINGERPRINT_3',
]);

function isTrustedFingerprint(event: NormalizedEvent): boolean {
  const fp = event.metadata?.fingerprint as string | undefined;
  if (!fp) return false;
  const hashPart = fp.includes(' ') ? fp.split(' ')[1] : fp;
  return TRUSTED_FINGERPRINTS.has(hashPart);
}

export function addTrustedIp(ip: string): void {
  TRUSTED_IPS.add(ip);
}

export function addTrustedFingerprint(fingerprint: string): void {
  TRUSTED_FINGERPRINTS.add(fingerprint);
}

const KNOWN_USERS = new Set(['ubuntu', 'root', 'deploy']);

const DETECTION_RULES: DetectionRule[] = [
  {
    name: 'crypto_mining',
    description: 'Detects cryptocurrency mining processes',
    condition: (_events, current) => {
      const patterns = /xmrig|minerd|cpuminer|cryptonight|kdevtmpfsi|kinsing/i;
      return current.source === 'process' && patterns.test(current.rawLog);
    },
    severity: 'critical',
    eventType: 'crypto_mining',
  },
  {
    name: 'ssh_brute_force_burst',
    description: 'Detects SSH brute force burst (>20 failures from same IP in buffer)',
    condition: (events, current) => {
      if (current.eventType !== 'ssh_failed_password' && current.eventType !== 'ssh_invalid_user') return false;
      if (!current.sourceIp) return false;

      const count = events.filter(e =>
        e.sourceIp === current.sourceIp &&
        (e.eventType === 'ssh_failed_password' || e.eventType === 'ssh_invalid_user')
      ).length;

      return count >= 20;
    },
    severity: 'high',
    eventType: 'ssh_brute_force',
  },
  {
    name: 'suspicious_binary',
    description: 'Detects execution from /tmp, /dev/shm, or hidden paths',
    condition: (_events, current) => {
      if (current.source !== 'process') return false;
      return /\/tmp\/|\/dev\/shm\/|\/\.[^/]+\//.test(current.rawLog);
    },
    severity: 'high',
    eventType: 'suspicious_binary',
  },
  {
    name: 'lateral_movement',
    description: 'Detects SSH login from internal/unusual source after brute force',
    condition: (events, current) => {
      if (current.eventType !== 'ssh_login_success') return false;
      if (!current.sourceIp) return false;

      const hadFailures = events.some(e =>
        e.sourceIp === current.sourceIp &&
        (e.eventType === 'ssh_failed_password' || e.eventType === 'ssh_invalid_user')
      );

      return hadFailures;
    },
    severity: 'critical',
    eventType: 'lateral_movement',
  },
  {
    name: 'container_escape_attempt',
    description: 'Detects container dying repeatedly or privileged exec',
    condition: (events, current) => {
      if (current.source !== 'docker') return false;
      if (current.rawLog.includes('ANOMALY')) return true;
      if (current.eventType !== 'docker_die') return false;

      const containerName = current.metadata?.containerName;
      if (!containerName) return false;

      const recentDies = events.filter(e =>
        e.source === 'docker' &&
        e.eventType === 'docker_die' &&
        e.metadata?.containerName === containerName &&
        e.timestamp.getTime() > Date.now() - 10 * 60 * 1000
      ).length;

      return recentDies >= 5;
    },
    severity: 'high',
    eventType: 'container_anomaly',
  },
  {
    name: 'high_connection_flood',
    description: 'Detects abnormally high connections from single IP',
    condition: (_events, current) => {
      return current.source === 'network' && current.rawLog.includes('HIGH_CONN_COUNT');
    },
    severity: 'medium',
    eventType: 'connection_flood',
  },
  {
    name: 'unauthorized_login',
    description: 'SSH login from IP not in trusted list and fingerprint not trusted',
    condition: (_events, current) => {
      if (current.eventType !== 'ssh_login_success') return false;
      if (!current.sourceIp) return false;
      if (isTrustedIp(current.sourceIp)) return false;
      if (isTrustedFingerprint(current)) return false;
      return true;
    },
    severity: 'high',
    eventType: 'unauthorized_login',
  },
  {
    name: 'password_login',
    description: 'SSH login using password instead of key',
    condition: (_events, current) => {
      if (current.eventType !== 'ssh_login_success') return false;
      return /password/.test(current.rawLog) && !/publickey/.test(current.rawLog);
    },
    severity: 'high',
    eventType: 'password_login',
  },
  {
    name: 'unusual_hour_login',
    description: 'SSH login between 00:00 and 06:00 BRT from non-trusted IP',
    condition: (_events, current) => {
      if (current.eventType !== 'ssh_login_success') return false;
      if (!current.sourceIp || isTrustedIp(current.sourceIp)) return false;
      if (current.userName && KNOWN_USERS.has(current.userName)) return false;
      const brt = new Date(current.timestamp.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
      const hour = brt.getHours();
      return hour >= 0 && hour < 6;
    },
    severity: 'medium',
    eventType: 'unusual_hour_login',
  },
];

export class EventDetector {
  private static eventBuffer: NormalizedEvent[] = [];
  private static readonly MAX_BUFFER = 2000;

  static detect(events: NormalizedEvent[]): NormalizedEvent[] {
    this.eventBuffer.push(...events);
    if (this.eventBuffer.length > this.MAX_BUFFER) {
      this.eventBuffer = this.eventBuffer.slice(-this.MAX_BUFFER);
    }

    const detectedEvents: NormalizedEvent[] = [];

    for (const event of events) {
      for (const rule of DETECTION_RULES) {
        if (rule.condition(this.eventBuffer, event)) {
          const detected: NormalizedEvent = {
            ...event,
            severity: rule.severity,
            eventType: rule.eventType,
            metadata: {
              ...event.metadata,
              detectionRule: rule.name,
              originalEventType: event.eventType,
            },
          };
          detectedEvents.push(detected);
          logger.info({ rule: rule.name, ip: event.sourceIp, server: event.serverId }, 'Detection rule triggered');
          break;
        }
      }
    }

    return detectedEvents;
  }

  static getRules(): Array<{ name: string; description: string }> {
    return DETECTION_RULES.map(r => ({ name: r.name, description: r.description }));
  }

  static clearBuffer(): void {
    this.eventBuffer = [];
  }
}
