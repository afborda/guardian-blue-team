import { PlaybookEngine, type PlaybookDefinition } from './engine.js';
import { blockIP, unblockIP } from './actions/block-ip.js';
import { notify } from './actions/notify.js';
import { enrichIP } from './actions/enrich-ip.js';
import { checkRepeatOffender } from './actions/check-repeat.js';
import { killProcess } from './actions/kill-process.js';
import { pauseContainer, disconnectContainer, killContainerProcess, restartContainer, pullContainerImage, recreateContainer } from './actions/container-actions.js';
import { rateLimit, removeRateLimit } from './actions/rate-limit.js';

const PLAYBOOKS: PlaybookDefinition[] = [
  {
    name: 'ssh-brute-force',
    description: 'Responds to SSH brute force attacks — enriches IP, blocks permanently, notifies',
    trigger: { eventType: 'ssh_brute_force', threshold: 10, window: '5m' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'block-ip', params: { duration: 'permanent' } },
      { action: 'notify', params: { severity: 'high' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'port-scan-response',
    description: 'Responds to port scans — enriches IP, blocks permanently, notifies',
    trigger: { eventType: 'port_scan', threshold: 5, window: '10m' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'block-ip', params: { duration: 'permanent' } },
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
      { action: 'block-ip', params: { duration: 'permanent' } },
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
      { action: 'block-ip', params: { duration: 'permanent' } },
      { action: 'notify', params: { severity: 'critical', message: '🚨 LATERAL MOVEMENT DETECTED — IP blocked' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'connection-flood-response',
    description: 'Responds to high connection floods — enriches IP, blocks permanently',
    trigger: { eventType: 'connection_flood' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'block-ip', params: { duration: 'permanent' } },
      { action: 'notify', params: { severity: 'high' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'ddos-syn-flood-response',
    description: 'SYN flood graduated response: rate-limit, then escalate to permanent block',
    trigger: { eventType: 'syn_flood' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'rate-limit', params: { limitPerSec: 10, burst: 20 } },
      { action: 'notify', params: { severity: 'critical', message: 'SYN flood detected — rate limiting applied' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'connection-rate-response',
    description: 'Connection rate spike response',
    trigger: { eventType: 'connection_rate_spike' },
    steps: [
      { action: 'enrich-ip' },
      { action: 'rate-limit', params: { limitPerSec: 10, burst: 20 } },
      { action: 'notify', params: { severity: 'high' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'bandwidth-spike-response',
    description: 'Bandwidth spike response — notify and investigate',
    trigger: { eventType: 'bandwidth_spike' },
    steps: [
      { action: 'notify', params: { severity: 'high', message: 'Bandwidth spike detected — possible DDoS' } },
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
  {
    name: 'file-integrity-response',
    description: 'Responds to file integrity changes — notifies, requires approval if critical system file',
    trigger: { eventType: 'critical_file_tampering' },
    steps: [
      { action: 'notify', params: { severity: 'critical', message: '🚨 CRITICAL FILE MODIFIED — investigate immediately' } },
    ],
    requiresApproval: true,
  },
  {
    name: 'sudo-suspicious-response',
    description: 'Responds to suspicious sudo commands — enriches context, notifies',
    trigger: { eventType: 'sudo_suspicious' },
    steps: [
      { action: 'notify', params: { severity: 'high', message: '⚠️ Suspicious sudo command detected' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'cron-persistence-response',
    description: 'Responds to suspicious cron job additions — notifies, requires approval to investigate',
    trigger: { eventType: 'cron_persistence' },
    steps: [
      { action: 'notify', params: { severity: 'high', message: '⚠️ Suspicious cron job added — possible persistence mechanism' } },
    ],
    requiresApproval: true,
  },
  {
    name: 'ssh-key-response',
    description: 'Responds to unauthorized SSH key additions — notifies, requires approval',
    trigger: { eventType: 'unauthorized_ssh_key' },
    steps: [
      { action: 'notify', params: { severity: 'high', message: '⚠️ New SSH key added to authorized_keys' } },
    ],
    requiresApproval: true,
  },
  {
    name: 'dns-c2-response',
    description: 'Responds to DNS-based C2 indicators (DGA domains, suspicious TLDs)',
    trigger: { eventType: 'dns_dga' },
    steps: [
      { action: 'notify', params: { severity: 'high', message: '⚠️ Possible C2 communication — DGA domain detected' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'dns-suspicious-tld-response',
    description: 'Alerts on DNS queries to suspicious TLDs',
    trigger: { eventType: 'dns_suspicious_tld' },
    steps: [
      { action: 'notify', params: { severity: 'medium' } },
    ],
    requiresApproval: false,
  },
  // ─── Container Runtime Security Playbooks ──────────────────────────────────
  {
    name: 'container-crypto-response',
    description: 'Responds to crypto mining inside container — kills process, isolates, restarts',
    trigger: { eventType: 'container_crypto_process' },
    steps: [
      { action: 'kill-container-process' },
      { action: 'disconnect-container' },
      { action: 'restart-container' },
      { action: 'notify', params: { severity: 'critical', message: '&#9888;&#65039; MINERADOR DE CRIPTO DETECTADO E ELIMINADO\n\nGuardian detectou um processo de mineracao rodando dentro de um container, matou o processo, isolou a rede e reiniciou o container automaticamente.' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'container-mining-network-response',
    description: 'Responds to mining pool connection from container — isolates and restarts',
    trigger: { eventType: 'container_mining_network' },
    steps: [
      { action: 'disconnect-container' },
      { action: 'restart-container' },
      { action: 'notify', params: { severity: 'critical', message: '&#128279; CONEXAO COM POOL DE MINERACAO DETECTADA\n\nContainer tentou se conectar a uma porta conhecida de pool de mineracao. Guardian cortou a rede e reiniciou o container.' } },
    ],
    requiresApproval: false,
  },
  {
    name: 'container-fs-tampering-response',
    description: 'Alerts on suspicious filesystem changes inside container',
    trigger: { eventType: 'container_fs_tampering' },
    steps: [
      { action: 'notify', params: { severity: 'high', message: '&#128193; ARQUIVO SUSPEITO CRIADO EM CONTAINER\n\nBinario ou arquivo novo detectado em /tmp, /dev/shm ou /usr/bin dentro de um container. Pode indicar exploit em andamento. Investigue antes de tomar acao.' } },
    ],
    requiresApproval: true,
  },
  {
    name: 'container-auto-update',
    description: 'Responds to critical CVE in container image — pulls latest and recreates',
    trigger: { eventType: 'container_critical_cve' },
    steps: [
      { action: 'pull-container-image' },
      { action: 'recreate-container' },
      { action: 'notify', params: { severity: 'high', message: '&#128736; CONTAINER ATUALIZADO POR CVE CRITICA\n\nVulnerabilidade critica (CVSS >= 9.0) encontrada na imagem do container. Guardian puxou a versao corrigida e recriou o container.' } },
    ],
    requiresApproval: true,
  },
  {
    name: 'container-suspicious-exec-response',
    description: 'Alerts on execution from /tmp or /dev/shm inside container',
    trigger: { eventType: 'container_suspicious_exec' },
    steps: [
      { action: 'kill-container-process' },
      { action: 'notify', params: { severity: 'high', message: '&#128065; EXECUCAO SUSPEITA EM CONTAINER\n\nProcesso iniciado de /tmp ou /dev/shm — tipico de exploit que baixa e executa payload. Guardian matou o processo automaticamente.' } },
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
    PlaybookEngine.registerAction('kill-container-process', killContainerProcess);
    PlaybookEngine.registerAction('restart-container', restartContainer);
    PlaybookEngine.registerAction('pull-container-image', pullContainerImage);
    PlaybookEngine.registerAction('recreate-container', recreateContainer);
    PlaybookEngine.registerAction('rate-limit', rateLimit);
    PlaybookEngine.registerAction('remove-rate-limit', removeRateLimit);
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
