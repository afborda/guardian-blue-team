import { PlaybookEngine, type PlaybookDefinition } from './engine.js';
import { blockIP, unblockIP } from './actions/block-ip.js';
import { notify } from './actions/notify.js';
import { enrichIP } from './actions/enrich-ip.js';

const PLAYBOOKS: PlaybookDefinition[] = [
  {
    name: 'ssh-brute-force',
    description: 'Responds to SSH brute force attacks — enriches IP, blocks if malicious, notifies',
    trigger: { eventType: 'ssh_brute_force', threshold: 10, window: '5m' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'block-ip', params: { duration: '24h' }, condition: 'score > 50' },
      { action: 'notify', params: { severity: 'high' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'port-scan-response',
    description: 'Responds to port scans — enriches IP, blocks high-risk scanners, notifies',
    trigger: { eventType: 'port_scan', threshold: 5, window: '10m' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'block-ip', params: { duration: '12h' }, condition: 'score > 70' },
      { action: 'notify', params: { severity: 'medium' } },
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
];

export class PlaybookRegistry {
  private static initialized = false;

  static init(): void {
    if (this.initialized) return;

    PlaybookEngine.registerAction('enrich-ip', enrichIP);
    PlaybookEngine.registerAction('block-ip', blockIP);
    PlaybookEngine.registerAction('unblock-ip', unblockIP);
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
