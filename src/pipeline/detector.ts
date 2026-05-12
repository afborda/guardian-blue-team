import type { NormalizedEvent } from './normalizer.js';
import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';

export interface DetectionRule {
  name: string;
  description: string;
  condition: (events: NormalizedEvent[], current: NormalizedEvent) => boolean;
  severity: NormalizedEvent['severity'];
  eventType: string;
}

// IPs that are expected to login — add your admin IPs here
const TRUSTED_IPS = new Set(CONSTANTS.trustedIps);

function isTrustedIp(ip: string): boolean {
  if (TRUSTED_IPS.has(ip)) return true;
  if (ip.startsWith('172.') || ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  return false;
}

const TRUSTED_FINGERPRINTS = new Set(CONSTANTS.trustedFingerprints);

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
      return current.source === 'process' && CONSTANTS.cryptoMiningPatterns.test(current.rawLog);
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

      return count >= CONSTANTS.detection.bruteForceThreshold;
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
    name: 'syn_flood_detected',
    description: 'SYN flood detected (>50 half-open connections from single IP)',
    condition: (_events: NormalizedEvent[], current: NormalizedEvent) => {
      return current.source === 'network' && current.rawLog.includes('SYN_FLOOD');
    },
    severity: 'critical' as const,
    eventType: 'syn_flood',
  },
  {
    name: 'bandwidth_spike',
    description: 'Bandwidth spike detected via anomaly detection',
    condition: (_events: NormalizedEvent[], current: NormalizedEvent) => {
      return current.source === 'network' && current.rawLog.includes('BANDWIDTH_SPIKE');
    },
    severity: 'high' as const,
    eventType: 'bandwidth_spike',
  },
  {
    name: 'connection_rate_spike',
    description: 'Connection rate spike (>100 new connections/sec)',
    condition: (_events: NormalizedEvent[], current: NormalizedEvent) => {
      return current.source === 'network' && current.rawLog.includes('CONN_RATE_SPIKE');
    },
    severity: 'high' as const,
    eventType: 'connection_rate_spike',
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
      return hour >= CONSTANTS.detection.unusualHourStart && hour < CONSTANTS.detection.unusualHourEnd;
    },
    severity: 'medium',
    eventType: 'unusual_hour_login',
  },
  {
    name: 'critical_file_modified',
    description: 'Critical system file was modified',
    condition: (_events, current) => {
      if (current.eventType !== 'file_modified' && current.eventType !== 'file_permissions_changed') return false;
      const path = current.metadata?.filePath as string;
      if (!path) return false;
      return CONSTANTS.fim.criticalPaths.some(p => path.includes(p));
    },
    severity: 'critical',
    eventType: 'critical_file_tampering',
  },
  {
    name: 'sudo_suspicious_command',
    description: 'Suspicious command executed via sudo',
    condition: (_events, current) => {
      if (current.eventType !== 'sudo_command') return false;
      const cmd = (current.metadata?.command as string) || current.rawLog;
      return CONSTANTS.sudo.suspiciousCommands.test(cmd);
    },
    severity: 'high',
    eventType: 'sudo_suspicious',
  },
  {
    name: 'suspicious_cron_added',
    description: 'Cron job with suspicious command was added',
    condition: (_events, current) => {
      if (current.eventType !== 'cron_added') return false;
      const cmd = (current.metadata?.command as string) || current.rawLog;
      return CONSTANTS.cron.suspiciousPatterns.test(cmd);
    },
    severity: 'high',
    eventType: 'cron_persistence',
  },
  {
    name: 'unauthorized_ssh_key',
    description: 'New SSH key added to authorized_keys',
    condition: (_events, current) => {
      return current.eventType === 'ssh_key_added';
    },
    severity: 'high',
    eventType: 'unauthorized_ssh_key',
  },
  {
    name: 'dns_dga_detected',
    description: 'Domain with high entropy detected (possible DGA)',
    condition: (_events, current) => {
      if (current.eventType !== 'dns_query') return false;
      const domain = current.metadata?.domain as string;
      if (!domain || domain.length < CONSTANTS.dns.minDgaLength) return false;
      const len = domain.length;
      const freq = new Map<string, number>();
      for (const ch of domain) freq.set(ch, (freq.get(ch) || 0) + 1);
      let entropy = 0;
      for (const count of freq.values()) { const p = count / len; entropy -= p * Math.log2(p); }
      return entropy > CONSTANTS.dns.entropyThreshold;
    },
    severity: 'high',
    eventType: 'dns_dga',
  },
  {
    name: 'dns_suspicious_tld',
    description: 'DNS query to suspicious TLD',
    condition: (_events, current) => {
      if (current.eventType !== 'dns_query') return false;
      const domain = current.metadata?.domain as string;
      if (!domain) return false;
      return CONSTANTS.dns.suspiciousTlds.some(tld => domain.endsWith(tld));
    },
    severity: 'medium',
    eventType: 'dns_suspicious_tld',
  },
  {
    name: 'proxy_path_traversal',
    description: 'Path traversal attempt detected in proxy logs',
    condition: (_events, current) => {
      return current.eventType === 'proxy_path_traversal';
    },
    severity: 'high',
    eventType: 'proxy_path_traversal',
  },
  {
    name: 'proxy_scanner_burst',
    description: '10+ scanner requests from same IP in buffer',
    condition: (events, current) => {
      if (current.eventType !== 'proxy_scanner_detected') return false;
      if (!current.sourceIp) return false;

      const count = events.filter(e =>
        e.sourceIp === current.sourceIp &&
        e.eventType === 'proxy_scanner_detected'
      ).length;

      return count >= 10;
    },
    severity: 'medium',
    eventType: 'proxy_scanner_burst',
  },
  {
    name: 'systemd_restart_loop',
    description: 'Same systemd unit restarted 3+ times in buffer',
    condition: (events, current) => {
      if (current.eventType !== 'systemd_unit_failed' && current.source !== 'systemd') return false;
      const unit = (current.metadata?.unit as string) || current.processName;
      if (!unit) return false;

      const count = events.filter(e =>
        e.source === 'systemd' &&
        ((e.metadata?.unit as string) === unit || e.processName === unit) &&
        (e.rawLog.toLowerCase().includes('restart') || e.rawLog.toLowerCase().includes('failed') || e.eventType === 'systemd_unit_failed')
      ).length;

      return count >= 3;
    },
    severity: 'high',
    eventType: 'systemd_restart_loop',
  },
  {
    name: 'package_suspicious_install',
    description: 'Known offensive/attack tool package installed',
    condition: (_events, current) => {
      return current.eventType === 'package_suspicious';
    },
    severity: 'high',
    eventType: 'package_suspicious',
  },
  {
    name: 'oom_kill_repeated',
    description: '2+ OOM kills in event buffer',
    condition: (events, current) => {
      if (current.eventType !== 'syslog_oom_kill') return false;

      const count = events.filter(e => e.eventType === 'syslog_oom_kill').length;
      return count >= 2;
    },
    severity: 'high',
    eventType: 'syslog_oom_repeated',
  },
  // ─── Container Runtime Security Rules ──────────────────────────────────────
  {
    name: 'container_crypto_process',
    description: 'Detects cryptocurrency mining process INSIDE a container',
    condition: (_events, current) => {
      return current.source === 'container_process' && CONSTANTS.cryptoMiningPatterns.test(current.rawLog);
    },
    severity: 'critical',
    eventType: 'container_crypto_process',
  },
  {
    name: 'container_suspicious_exec',
    description: 'Detects process execution from /tmp or /dev/shm inside container',
    condition: (_events, current) => {
      if (current.source !== 'container_process') return false;
      return /\/tmp\/|\/dev\/shm\/|\/var\/tmp\//.test(current.rawLog);
    },
    severity: 'high',
    eventType: 'container_suspicious_exec',
  },
  {
    name: 'container_mining_network',
    description: 'Detects container connection to known mining pool ports',
    condition: (_events, current) => {
      if (current.source !== 'container_network') return false;
      const remotePort = current.destinationPort ?? (current.metadata?.remotePort as number);
      if (!remotePort) return false;
      return (CONSTANTS.container.miningPorts as readonly number[]).includes(remotePort);
    },
    severity: 'critical',
    eventType: 'container_mining_network',
  },
  {
    name: 'container_fs_tampering',
    description: 'Detects new files written to suspicious paths inside container',
    condition: (_events, current) => {
      if (current.source !== 'container_filesystem') return false;
      if (current.eventType !== 'container_file_added') return false;
      const filePath = current.metadata?.filePath as string;
      if (!filePath) return false;
      return CONSTANTS.container.suspiciousContainerPaths.some(p => filePath.includes(p));
    },
    severity: 'high',
    eventType: 'container_fs_tampering',
  },
  {
    name: 'container_critical_cve',
    description: 'Critical CVE (CVSS >= 9.0) found in running container image',
    condition: (_events, current) => {
      if (current.source !== 'container_image_cve') return false;
      const cvss = current.metadata?.cvss as number;
      return cvss >= CONSTANTS.container.minCvssForAutoUpdate;
    },
    severity: 'critical',
    eventType: 'container_critical_cve',
  },
];

export class EventDetector {
  private static eventBuffer: NormalizedEvent[] = [];
  private static readonly MAX_BUFFER = CONSTANTS.detection.eventBufferSize;

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
