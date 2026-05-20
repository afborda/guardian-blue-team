import { z } from 'zod';

const envSchema = z.object({
  PORT: z.string().transform(Number).default('3334'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  DATABASE_URL: z.string().optional(),

  // Dashboard
  DASHBOARD_TOKEN: z.string().optional(),
  DASHBOARD_USERS: z.string().optional(),

  // Notifications
  NOTIFIERS: z.string().default('telegram'),

  // Docker
  DOCKER_HOST: z.string().optional(),

  // Telegram
  TELEGRAM_BOT_TOKEN: z.string().min(1, 'TELEGRAM_BOT_TOKEN is required'),
  TELEGRAM_CHAT_ID: z.string().min(1, 'TELEGRAM_CHAT_ID is required'),
  TELEGRAM_WEBHOOK_SECRET: z.string().optional(),

  // Base URL for webhook registration
  GUARDIAN_BASE_URL: z.string().optional(),

  // AI — Gemini
  GEMINI_API_KEY: z.string().optional(),
  GEMINI_MODEL: z.string().default('gemini-2.5-flash'),

  // AI — OpenAI
  OPENAI_API_KEY: z.string().optional(),
  OPENAI_MODEL: z.string().default('gpt-4o-mini'),

  // AI — Claude
  ANTHROPIC_API_KEY: z.string().optional(),
  ANTHROPIC_MODEL: z.string().default('claude-sonnet-4-6-20250514'),

  // AI — Ollama
  OLLAMA_URL: z.string().default('http://localhost:11434'),
  OLLAMA_MODEL: z.string().default('qwen3:4b'),
  OLLAMA_CHAT_MODEL: z.string().default('qwen3:0.6b'),
  OLLAMA_EMBED_MODEL: z.string().default('bge-m3'),

  // AI — Provider preference
  AI_PROVIDER: z.enum(['gemini', 'openai', 'claude', 'ollama', 'auto']).default('auto'),
  // AI — Strategy (local-only: only Ollama | api-only: only cloud | auto: Ollama first, cloud fallback)
  AI_STRATEGY: z.enum(['local-only', 'api-only', 'auto']).default('auto'),

  // Email
  RESEND_API_KEY: z.string().optional(),

  // Abuse detection
  ABUSE_CONFIDENCE_THRESHOLD: z.string().transform(Number).default('70'),

  // Health
  UPTIME_KUMA_PUSH_URL: z.string().optional(),

  // Host Security SSH (legacy, used as default when no servers registered)
  HOST_SSH_HOST: z.string().default('127.0.0.1'),
  HOST_SSH_PORT: z.string().transform(Number).default('22'),
  HOST_SSH_USER: z.string().default('ubuntu'),
  HOST_SSH_KEY_PATH: z.string().optional(),

  // Security — Trusted entities
  TRUSTED_IPS: z.string().default(''),
  TRUSTED_FINGERPRINTS: z.string().default(''),

  // Threat Intelligence
  ABUSEIPDB_API_KEY: z.string().optional(),
  VIRUSTOTAL_API_KEY: z.string().optional(),

  // CVE Monitor
  CVE_MONITOR_ENABLED: z.string().transform(v => v !== 'false').default('true'),
  CVE_MONITOR_MIN_CVSS: z.string().transform(Number).default('7.0'),
  CVE_MONITOR_INTERVAL_HOURS: z.string().transform(Number).default('6'),
  CVE_INTEL_FEEDS_ENABLED: z.string().transform(v => v !== 'false').default('true'),
  CVE_EPSS_HISTORY_DAYS: z.string().transform(Number).default('30'),

  // Trivy — image vulnerability scanner. Optional: when unset, docker-audit
  // falls back to its cheap :latest/age heuristics only.
  TRIVY_SERVER_URL: z.string().optional(),
  TRIVY_TOKEN: z.string().optional(),

  // Falco — runtime syscall visibility. Token is shared by all Falco agents
  // and validated on POST /webhook/falco. Unset = endpoint returns 503.
  FALCO_WEBHOOK_TOKEN: z.string().optional(),
});

export interface DashboardUser {
  username: string;
  token: string;
  role: 'admin' | 'operator' | 'viewer';
}

function parseDashboardUsers(raw?: string): DashboardUser[] {
  if (!raw) return [];
  return raw.split(';').map(entry => {
    const [username, token, role] = entry.split(':');
    if (!username || !token) return null;
    const validRole = ['admin', 'operator', 'viewer'].includes(role) ? role as DashboardUser['role'] : 'viewer';
    return { username: username.trim(), token: token.trim(), role: validRole };
  }).filter((u): u is DashboardUser => u !== null);
}

const env = envSchema.parse(process.env);

// Falco token is shell-interpolated into the deploy command. Single quotes are
// the only safe quoting char that works on every POSIX shell — but they break
// if the token itself contains '. base64 tokens (openssl rand -base64 32) never
// do; reject anything else at startup with a clear error.
if (env.FALCO_WEBHOOK_TOKEN && env.FALCO_WEBHOOK_TOKEN.includes("'")) {
  throw new Error("FALCO_WEBHOOK_TOKEN must not contain single quotes. Generate with: openssl rand -base64 32");
}

export const config = {
  server: {
    port: env.PORT,
    nodeEnv: env.NODE_ENV,
  },

  dashboard: {
    token: env.DASHBOARD_TOKEN || null,
    users: parseDashboardUsers(env.DASHBOARD_USERS),
  },

  database: {
    url: env.DATABASE_URL || null,
    isSqlite: !env.DATABASE_URL || env.DATABASE_URL.startsWith('sqlite:'),
  },

  notifiers: env.NOTIFIERS.split(',').map(s => s.trim()).filter(Boolean),

  telegram: {
    botToken: env.TELEGRAM_BOT_TOKEN,
    chatId: env.TELEGRAM_CHAT_ID,
    webhookSecret: env.TELEGRAM_WEBHOOK_SECRET,
    baseUrl: env.GUARDIAN_BASE_URL || null,
  },

  ai: {
    provider: env.AI_PROVIDER,
    strategy: env.AI_STRATEGY,
    geminiApiKey: env.GEMINI_API_KEY || null,
    geminiModel: env.GEMINI_MODEL,
    openaiApiKey: env.OPENAI_API_KEY || null,
    openaiModel: env.OPENAI_MODEL,
    anthropicApiKey: env.ANTHROPIC_API_KEY || null,
    anthropicModel: env.ANTHROPIC_MODEL,
    ollamaUrl: env.OLLAMA_URL,
    ollamaModel: env.OLLAMA_MODEL,
    ollamaChatModel: env.OLLAMA_CHAT_MODEL,
    ollamaEmbedModel: env.OLLAMA_EMBED_MODEL,
  },

  resend: {
    apiKey: env.RESEND_API_KEY || null,
    fromEmail: 'Guardian <noreply@guardian.local>',
  },

  abuse: {
    confidenceThreshold: env.ABUSE_CONFIDENCE_THRESHOLD,
  },

  health: {
    uptimeKumaPushUrl: env.UPTIME_KUMA_PUSH_URL || null,
  },

  hostSecurity: {
    sshHost: env.HOST_SSH_HOST,
    sshPort: env.HOST_SSH_PORT,
    sshUser: env.HOST_SSH_USER,
    sshKeyPath: env.HOST_SSH_KEY_PATH || null,
  },

  security: {
    trustedIps: env.TRUSTED_IPS.split(',').map(s => s.trim()).filter(Boolean),
    trustedFingerprints: env.TRUSTED_FINGERPRINTS.split(',').map(s => s.trim()).filter(Boolean),
  },

  threatIntel: {
    abuseIpDbKey: env.ABUSEIPDB_API_KEY || null,
    virusTotalKey: env.VIRUSTOTAL_API_KEY || null,
  },

  cveMonitor: {
    enabled: env.CVE_MONITOR_ENABLED,
    minCvss: env.CVE_MONITOR_MIN_CVSS,
    checkIntervalHours: env.CVE_MONITOR_INTERVAL_HOURS,
  },

  cveIntelFeeds: {
    enabled: env.CVE_INTEL_FEEDS_ENABLED,
    epssHistoryDays: env.CVE_EPSS_HISTORY_DAYS,
  },

  trivy: {
    serverUrl: env.TRIVY_SERVER_URL || null,
    token: env.TRIVY_TOKEN || null,
  },

  falco: {
    webhookToken: env.FALCO_WEBHOOK_TOKEN || null,
  },
} as const;

export type Config = typeof config;
