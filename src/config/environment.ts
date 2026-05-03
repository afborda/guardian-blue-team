import { z } from 'zod';

const envSchema = z.object({
  PORT: z.string().transform(Number).default('3334'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  // Database
  DATABASE_URL: z.string().optional(),

  // Notifications
  NOTIFIERS: z.string().default('telegram'),

  // Docker
  DOCKER_HOST: z.string().optional(),

  // Telegram
  TELEGRAM_BOT_TOKEN: z.string().min(1, 'TELEGRAM_BOT_TOKEN is required'),
  TELEGRAM_CHAT_ID: z.string().min(1, 'TELEGRAM_CHAT_ID is required'),
  TELEGRAM_WEBHOOK_SECRET: z.string().optional(),

  // AI — Gemini
  GEMINI_API_KEY: z.string().optional(),
  GEMINI_MODEL: z.string().default('gemini-2.0-flash-001'),

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

  // AI — Provider preference
  AI_PROVIDER: z.enum(['gemini', 'openai', 'claude', 'ollama', 'auto']).default('auto'),

  // Email
  RESEND_API_KEY: z.string().optional(),

  // Abuse detection
  ABUSE_CONFIDENCE_THRESHOLD: z.string().transform(Number).default('70'),

  // Health
  UPTIME_KUMA_PUSH_URL: z.string().optional(),

  // Host Security SSH (legacy, used as default when no servers registered)
  HOST_SSH_HOST: z.string().default('127.0.0.1'),
  HOST_SSH_PORT: z.string().transform(Number).default('49222'),
  HOST_SSH_USER: z.string().default('ubuntu'),
  HOST_SSH_KEY_PATH: z.string().optional(),

  // Threat Intelligence
  ABUSEIPDB_API_KEY: z.string().optional(),
  VIRUSTOTAL_API_KEY: z.string().optional(),

  // CVE Monitor
  CVE_MONITOR_ENABLED: z.string().transform(v => v !== 'false').default('true'),
  CVE_MONITOR_MIN_CVSS: z.string().transform(Number).default('7.0'),
  CVE_MONITOR_INTERVAL_HOURS: z.string().transform(Number).default('6'),
});

const env = envSchema.parse(process.env);

export const config = {
  server: {
    port: env.PORT,
    nodeEnv: env.NODE_ENV,
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
  },

  ai: {
    provider: env.AI_PROVIDER,
    geminiApiKey: env.GEMINI_API_KEY || null,
    geminiModel: env.GEMINI_MODEL,
    openaiApiKey: env.OPENAI_API_KEY || null,
    openaiModel: env.OPENAI_MODEL,
    anthropicApiKey: env.ANTHROPIC_API_KEY || null,
    anthropicModel: env.ANTHROPIC_MODEL,
    ollamaUrl: env.OLLAMA_URL,
    ollamaModel: env.OLLAMA_MODEL,
    ollamaChatModel: env.OLLAMA_CHAT_MODEL,
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

  threatIntel: {
    abuseIpDbKey: env.ABUSEIPDB_API_KEY || null,
    virusTotalKey: env.VIRUSTOTAL_API_KEY || null,
  },

  cveMonitor: {
    enabled: env.CVE_MONITOR_ENABLED,
    minCvss: env.CVE_MONITOR_MIN_CVSS,
    checkIntervalHours: env.CVE_MONITOR_INTERVAL_HOURS,
  },
} as const;

export type Config = typeof config;
