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
    // Default block duration if playbook doesn't specify
    defaultDurationHours: 24,
    // SSH command timeout for block/unblock operations
    sshTimeoutMs: 10_000,
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

  // ─── Crypto Mining Detection ───────────────────────────────────────────────
  // Patterns that indicate crypto mining processes
  cryptoMiningPatterns: /xmrig|minerd|cpuminer|cryptonight|kdevtmpfsi|kinsing/i,

  // ─── Suspicious Binary Paths ───────────────────────────────────────────────
  // Execution from these paths triggers suspicious_binary alert
  suspiciousPaths: ['/tmp/', '/dev/shm/', '/var/tmp/.', '/run/user/'],

} as const;
