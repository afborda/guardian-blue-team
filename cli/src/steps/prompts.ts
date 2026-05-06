import * as p from '@clack/prompts';
import type { SystemInfo } from '../utils/system.js';

export interface UserConfig {
  telegramBotToken: string;
  telegramChatId: string;
  aiProvider: string;
  aiApiKey: string;
  aiModel: string;
  domain: string;
  abuseIpDbKey: string;
  virusTotalKey: string;
}

export async function collectConfig(info: SystemInfo): Promise<UserConfig> {
  const group = await p.group(
    {
      telegramBotToken: () =>
        p.text({
          message: 'Telegram Bot Token',
          placeholder: '8300199343:AAFi...',
          validate: (v) => {
            if (!v || v.length < 20) return 'Token inválido. Crie um bot via @BotFather.';
          },
        }),
      telegramChatId: () =>
        p.text({
          message: 'Telegram Chat ID',
          placeholder: '136236067',
          validate: (v) => {
            if (!v || !/^-?\d+$/.test(v)) return 'Chat ID deve ser numérico.';
          },
        }),
      aiProvider: () =>
        p.select({
          message: 'AI Provider',
          options: [
            { value: 'gemini', label: 'Gemini (free tier — recommended)', hint: 'gemini-2.5-flash' },
            { value: 'openai', label: 'OpenAI', hint: 'gpt-4o-mini' },
            { value: 'claude', label: 'Claude/Anthropic', hint: 'claude-sonnet-4-6' },
            { value: 'ollama', label: 'Ollama (local)', hint: 'qwen3:4b' },
          ],
        }),
      aiApiKey: ({ results }) => {
        if (results.aiProvider === 'ollama') {
          return p.text({ message: 'Ollama URL', initialValue: 'http://localhost:11434' });
        }
        const labels: Record<string, string> = { gemini: 'Gemini', openai: 'OpenAI', claude: 'Anthropic' };
        return p.text({
          message: `${labels[results.aiProvider as string] ?? 'AI'} API Key`,
          validate: (v) => {
            if (!v || v.length < 10) return 'API key inválida.';
          },
        });
      },
      domain: () =>
        p.text({
          message: 'Domain for dashboard (or IP:port)',
          placeholder: info.traefikNetwork ? 'guardian.example.com' : 'localhost:3334',
          initialValue: info.traefikNetwork ? '' : 'localhost:3334',
        }),
      abuseIpDbKey: () =>
        p.text({
          message: 'AbuseIPDB API Key (optional, Enter to skip)',
          placeholder: 'Free: https://abuseipdb.com',
          defaultValue: '',
        }),
      virusTotalKey: () =>
        p.text({
          message: 'VirusTotal API Key (optional, Enter to skip)',
          placeholder: 'Free: https://virustotal.com',
          defaultValue: '',
        }),
    },
    { onCancel: () => { p.cancel('Installation cancelled.'); process.exit(0); } }
  );

  const aiModels: Record<string, string> = {
    gemini: 'gemini-2.5-flash',
    openai: 'gpt-4o-mini',
    claude: 'claude-sonnet-4-6-20250514',
    ollama: 'qwen3:4b',
  };

  return {
    telegramBotToken: group.telegramBotToken as string,
    telegramChatId: group.telegramChatId as string,
    aiProvider: group.aiProvider as string,
    aiApiKey: group.aiApiKey as string,
    aiModel: aiModels[group.aiProvider as string] ?? 'gemini-2.5-flash',
    domain: (group.domain as string) || 'localhost:3334',
    abuseIpDbKey: (group.abuseIpDbKey as string) || '',
    virusTotalKey: (group.virusTotalKey as string) || '',
  };
}
