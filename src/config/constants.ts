// ─── Guardian Blue Team — Tunable Constants ─────────────────────────────────
// All hardcoded values that an operator might want to adjust.
// Modify these to change Guardian's behavior without touching logic code.

export const CONSTANTS = {

  // ─── Detection ──────────────────────────────────────────────────────────────
  detection: {
    // Minimum failed SSH attempts from same IP to trigger brute force alert
    bruteForceThreshold: 20,
    // Max events kept in detector memory buffer
    eventBufferSize: 2000,
    // Hours considered "unusual" for login (0-6 = midnight to 6am)
    unusualHourStart: 0,
    unusualHourEnd: 6,
  },

  // ─── Correlation ────────────────────────────────────────────────────────────
  correlation: {
    // General correlation window (how far back to look for related events)
    windowMs: 10 * 60 * 1000, // 10 minutes
    // Extended window for port scan deduplication
    portScanWindowMs: 30 * 60 * 1000, // 30 minutes
    // Min events to consider a brute force incident
    bruteForceThreshold: 10,
    // Min events to consider a port scan incident
    portScanThreshold: 10,
  },

  // ─── IP Blocking ───────────────────────────────────────────────────────────
  blocking: {
    // How often the cleanup worker checks for expired blocks
    cleanupIntervalMs: 5 * 60 * 1000, // 5 minutes
    // Default block duration (-1 = permanent)
    defaultDurationHours: -1,
    // SSH command timeout for block/unblock operations
    sshTimeoutMs: 10_000,
  },

  // ─── DDoS Detection & Mitigation ─────────────────────────────────────────
  ddos: {
    // SYN_RECV count from single IP to trigger SYN flood alert
    synFloodThreshold: 50,
    // New connections/sec from single IP to trigger rate spike alert
    connectionRateThreshold: 100,
    // Standard deviations above baseline to trigger bandwidth spike
    bandwidthSigmaThreshold: 3,
    // iptables rate-limit parameters (graduated response before full block)
    rateLimitPerSec: 10,
    rateLimitBurst: 20,
    // If rate-limited IP triggers again within this window, escalate to full block
    escalationWindowMs: 10 * 60 * 1000, // 10 minutes
    // How often the escalation worker checks rate-limited IPs
    escalationCheckIntervalMs: 2 * 60 * 1000, // 2 minutes
  },

  // ─── Event Collection ──────────────────────────────────────────────────────
  collection: {
    // How often to collect logs from servers
    intervalMs: 2 * 60 * 1000, // 2 minutes
    // How far back to look for new logs on each collection
    lookbackMinutes: 5,
    // SSH command timeout for log collection
    sshTimeoutMs: 20_000,
  },

  // ─── Inventory & CVE ───────────────────────────────────────────────────────
  inventory: {
    // How long to cache server package lists
    cacheTtlMs: 24 * 60 * 60 * 1000, // 24 hours
    // Max packages to collect per server (prevents memory issues)
    maxPackages: 2000,
    // SSH timeout for package listing
    sshTimeoutMs: 30_000,
    // OSV API batch size (max 1000 per request)
    osvBatchSize: 1000,
  },

  // ─── Telegram ──────────────────────────────────────────────────────────────
  telegram: {
    // Max commands per window before rate limiting kicks in
    rateLimitMax: 10,
    // Rate limit window duration
    rateLimitWindowMs: 60_000, // 1 minute
    // How long playbook approval requests stay valid
    approvalExpiryMs: 30 * 60 * 1000, // 30 minutes
    // Max time a playbook can run before being killed
    playbookTimeoutMs: 60_000, // 1 minute
  },

  // ─── Workers ───────────────────────────────────────────────────────────────
  workers: {
    // Vulnerability scanner: runs weekly on Saturday at this hour (BRT)
    vulnScanDay: 6, // Saturday
    vulnScanHour: 9, // 09:00
    // Daily report: sends at this hour (BRT)
    dailyReportHour: 8, // 08:00
  },

  // ─── Threat Intelligence ───────────────────────────────────────────────────
  threatIntel: {
    // AbuseIPDB cache TTL
    cacheTtlMs: 24 * 60 * 60 * 1000, // 24 hours
    // Max age for AbuseIPDB lookups
    maxAgeDays: 90,
  },

  // ─── Trusted IPs ──────────────────────────────────────────────────────────
  // IPs that should NEVER trigger unauthorized_login alerts.
  // Set via TRUSTED_IPS env var (comma-separated). Add your admin/deploy IPs.
  trustedIps: (process.env.TRUSTED_IPS || '').split(',').map(s => s.trim()).filter(Boolean) as string[],

  // ─── Trusted SSH Fingerprints ─────────────────────────────────────────────
  // SSH key fingerprints that should NEVER trigger unauthorized_login alerts.
  // Set via TRUSTED_FINGERPRINTS env var (comma-separated SHA256:xxx values).
  trustedFingerprints: (process.env.TRUSTED_FINGERPRINTS || '').split(',').map(s => s.trim()).filter(Boolean) as string[],

  // ─── File Integrity Monitoring (FIM) ──────────────────────────────────────
  fim: {
    intervalMs: 4 * 60 * 60 * 1000, // 4 hours
    monitoredPaths: [
      '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
      '/etc/ssh/sshd_config', '/etc/crontab', '/etc/hosts',
      '/etc/resolv.conf', '/etc/ld.so.preload',
      '/root/.ssh/authorized_keys', '/root/.bashrc',
    ],
    criticalPaths: ['/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/ssh/sshd_config'],
  },

  // ─── Sudo Auditing ────────────────────────────────────────────────────────
  sudo: {
    suspiciousCommands: /curl|wget|nc |ncat|dd |chmod\s+[67]77|bash\s+-[ic]|python[23]?\s+-c|perl\s+-e|base64\s+-d|mkfifo|socat/i,
  },

  // ─── Cron Monitoring ──────────────────────────────────────────────────────
  cron: {
    suspiciousPatterns: /curl|wget|nc |bash\s+-[ic]|python|perl|base64|\/tmp\/|\/dev\/shm\/|socat|mkfifo/i,
  },

  // ─── DNS Monitoring (C2 Detection) ────────────────────────────────────────
  dns: {
    entropyThreshold: 3.5,
    beaconThreshold: 5,
    beaconWindowMs: 10 * 60 * 1000, // 10 minutes
    suspiciousTlds: ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.pw', '.cc', '.buzz', '.surf'],
    minDgaLength: 20,
  },

  // ─── Crypto Mining Detection ───────────────────────────────────────────────
  // Patterns that indicate crypto mining processes
  cryptoMiningPatterns: /xmrig|minerd|cpuminer|cryptonight|kdevtmpfsi|kinsing|ccminer|t-rex|phoenixminer|nbminer|gminer/i,

  // ─── Suspicious Binary Paths ───────────────────────────────────────────────
  // Execution from these paths triggers suspicious_binary alert
  suspiciousPaths: ['/tmp/', '/dev/shm/', '/var/tmp/.', '/run/user/'],

  // ─── Container Runtime Security ────────────────────────────────────────────
  container: {
    processIntervalMs: 2 * 60 * 1000,       // 2 min — lightweight, critical detection
    networkIntervalMs: 5 * 60 * 1000,       // 5 min — moderate I/O
    filesystemIntervalMs: 30 * 60 * 1000,   // 30 min — heavy, cached
    configAuditIntervalMs: 60 * 60 * 1000,  // 1h — very light
    imageScanIntervalMs: 6 * 60 * 60 * 1000, // 6h — heavy, separate worker
    miningPorts: [3333, 4444, 5555, 8888, 14433, 14444, 45700, 9999],
    suspiciousContainerPaths: ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/'],
    minCvssForAutoUpdate: 9.0,
    minCvssForAlert: 7.0,
  },

} as const;
