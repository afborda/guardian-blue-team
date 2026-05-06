export interface EnvConfig {
  telegramBotToken: string;
  telegramChatId: string;
  aiProvider: string;
  aiApiKey: string;
  aiModel: string;
  domain: string;
  dashboardToken: string;
  dbPassword: string;
  sshPort: number;
  sshUser: string;
  sshKeyPath: string;
  traefikNetwork: string | null;
  abuseIpDbKey?: string;
  virusTotalKey?: string;
}

export function generateEnvFile(cfg: EnvConfig): string {
  const lines = [
    '# ─── Guardian Blue Team — Auto-Generated ─────────────────────────────────',
    `PORT=3334`,
    `NODE_ENV=production`,
    '',
    `# Database`,
    `DATABASE_URL=postgres://guardian:${cfg.dbPassword}@guardian-db:5432/guardian`,
    '',
    `# Dashboard`,
    `DASHBOARD_TOKEN=${cfg.dashboardToken}`,
    '',
    `# Telegram`,
    `TELEGRAM_BOT_TOKEN=${cfg.telegramBotToken}`,
    `TELEGRAM_CHAT_ID=${cfg.telegramChatId}`,
    '',
    `# AI Provider`,
    `AI_PROVIDER=${cfg.aiProvider}`,
  ];

  if (cfg.aiProvider === 'gemini') {
    lines.push(`GEMINI_API_KEY=${cfg.aiApiKey}`, `GEMINI_MODEL=${cfg.aiModel}`);
  } else if (cfg.aiProvider === 'openai') {
    lines.push(`OPENAI_API_KEY=${cfg.aiApiKey}`, `OPENAI_MODEL=${cfg.aiModel}`);
  } else if (cfg.aiProvider === 'claude') {
    lines.push(`ANTHROPIC_API_KEY=${cfg.aiApiKey}`, `ANTHROPIC_MODEL=${cfg.aiModel}`);
  } else if (cfg.aiProvider === 'ollama') {
    lines.push(`OLLAMA_URL=http://ollama:11434`, `OLLAMA_MODEL=${cfg.aiModel}`);
  }

  lines.push(
    '',
    `# SSH`,
    `HOST_SSH_HOST=127.0.0.1`,
    `HOST_SSH_PORT=${cfg.sshPort}`,
    `HOST_SSH_USER=${cfg.sshUser}`,
    `HOST_SSH_KEY_PATH=${cfg.sshKeyPath}`,
    '',
    `# Threat Intel`,
  );

  if (cfg.abuseIpDbKey) lines.push(`ABUSEIPDB_API_KEY=${cfg.abuseIpDbKey}`);
  if (cfg.virusTotalKey) lines.push(`VIRUSTOTAL_API_KEY=${cfg.virusTotalKey}`);

  lines.push(
    '',
    `# CVE Monitor`,
    `CVE_MONITOR_ENABLED=true`,
    '',
    `# Docker Compose vars`,
    `GUARDIAN_DOMAIN=${cfg.domain}`,
    `GUARDIAN_DB_PASSWORD=${cfg.dbPassword}`,
    `SSH_KEY_DIR=./data/ssh`,
    '',
  );

  return lines.join('\n');
}
