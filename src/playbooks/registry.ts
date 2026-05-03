import { PlaybookEngine, type PlaybookDefinition } from './engine.js';
import { blockIP, unblockIP } from './actions/block-ip.js';
import { notify } from './actions/notify.js';
import { enrichIP } from './actions/enrich-ip.js';
import { checkRepeatOffender } from './actions/check-repeat.js';
import { killProcess } from './actions/kill-process.js';
import { pauseContainer, disconnectContainer } from './actions/container-actions.js';

const PLAYBOOKS: PlaybookDefinition[] = [
  {
    name: 'ssh-brute-force',
    description: 'Responds to SSH brute force attacks — enriches IP, blocks if malicious or repeat, notifies',
    trigger: { eventType: 'ssh_brute_force', threshold: 10, window: '5m' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'check-repeat' },
      { action: 'block-ip', params: { duration: '24h' }, condition: 'score > 50 OR repeatCount > 1' },
      { action: 'notify', params: { severity: 'high' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'port-scan-response',
    description: 'Responds to port scans — enriches IP, checks repeat offenses, blocks if risky or persistent',
    trigger: { eventType: 'port_scan', threshold: 5, window: '10m' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'check-repeat' },
      { action: 'block-ip', params: { duration: '12h' }, condition: 'score > 50 OR repeatCount > 2' },
      { action: 'notify', params: { severity: 'medium' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'crypto-mining-response',
    description: 'Responds to crypto mining — kills miner process, blocks source IP, critical alert',
    trigger: { eventType: 'crypto_mining' },
    steps: [
      { action: 'kill-process' },
      { action: 'enrich-ip' },
      { action: 'block-ip', params: { duration: '7d' } },
      { action: 'notify', params: { severity: 'critical', message: '🚨 CRYPTO MINER DETECTED AND KILLED' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'container-escape-response',
    description: 'Responds to container escape attempts — pauses container, isolates network, awaits approval',
    trigger: { eventType: 'container_escape_attempt' },
    steps: [
      { action: 'pause-container' },
      { action: 'disconnect-container' },
      { action: 'notify', params: { severity: 'critical', message: '🚨 CONTAINER ESCAPE ATTEMPT — container paused and isolated' } },
    ],
    requiresApproval: true,
  },
  {
    name: 'lateral-movement-response',
    description: 'Responds to lateral movement — blocks source IP immediately, critical alert',
    trigger: { eventType: 'lateral_movement' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'block-ip', params: { duration: '7d' } },
      { action: 'notify', params: { severity: 'critical', message: '🚨 LATERAL MOVEMENT DETECTED — IP blocked' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'connection-flood-response',
    description: 'Responds to high connection floods — enriches IP, blocks if suspicious',
    trigger: { eventType: 'high_connection_flood' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'check-repeat' },
      { action: 'block-ip', params: { duration: '6h' }, condition: 'score > 30 OR repeatCount > 1' },
      { action: 'notify', params: { severity: 'high' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'suspicious-process',
    description: 'Responds to suspicious processes — notifies and waits for manual action',
    trigger: { eventType: 'suspicious_process' },
    steps: [
      { action: 'notify', params: { severity: 'high' } },
    ],
    requiresApproval: true,
  },
  {
    name: 'password-login-alert',
    description: 'Alerts when password-based SSH login is detected (should use key auth)',
    trigger: { eventType: 'password_login' },
    steps: [
      { action: 'notify', params: { severity: 'high', message: '⚠️ Password-based SSH login detected — consider disabling PasswordAuthentication in sshd_config' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'unusual-hour-alert',
    description: 'Alerts on SSH logins during unusual hours (00:00-06:00 BRT)',
    trigger: { eventType: 'unusual_hour_login' },
    steps: [
      { action: 'notify', params: { severity: 'medium' } },
    ],
    requiresApproval: false,
  },
];

export class PlaybookRegistry {
  private static initialized = false;

  static init(): void {
    if (this.initialized) return;

    PlaybookEngine.registerAction('enrich-ip', enrichIP);
    PlaybookEngine.registerAction('check-repeat', checkRepeatOffender);
    PlaybookEngine.registerAction('block-ip', blockIP);
    PlaybookEngine.registerAction('unblock-ip', unblockIP);
    PlaybookEngine.registerAction('kill-process', killProcess);
    PlaybookEngine.registerAction('pause-container', pauseContainer);
    PlaybookEngine.registerAction('disconnect-container', disconnectContainer);
    PlaybookEngine.registerAction('notify', notify);

    this.initialized = true;
  }

  static getAll(): PlaybookDefinition[] {
    return PLAYBOOKS;
  }

  static getByName(name: string): PlaybookDefinition | undefined {
    return PLAYBOOKS.find(p => p.name === name);
  }

  static getByTrigger(eventType: string): PlaybookDefinition[] {
    return PLAYBOOKS.filter(p => p.trigger.eventType === eventType);
  }

  static listNames(): string[] {
    return PLAYBOOKS.map(p => p.name);
  }
}
