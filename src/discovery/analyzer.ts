import { AIProvider } from '../services/ai-provider.js';
import { logger } from '../utils/logger.js';
import { discoveryResultSchema, type DiscoveryResult, type ServerSnapshot } from './types.js';
import { generateFallbackConfig } from './templates.js';

const SYSTEM_PROMPT = `You are an expert DevOps engineer specializing in server security infrastructure.
Analyze the server snapshot and generate the optimal configuration for Guardian Blue Team SIEM.

Rules:
1. If Traefik detected → configure Guardian as service in same Docker network with Traefik labels
2. If Nginx detected → Guardian listens on 127.0.0.1:3334, generate upstream block
3. If SSH on non-standard port → set HOST_SSH_PORT accordingly
4. If fail2ban active → include its jails in monitoring profile
5. If Docker present → mount /var/run/docker.sock read-only
6. Adapt to available tools (Alpine uses wget, Ubuntu/Debian has curl)
7. Generate .env with all detected values filled (never include secrets/passwords)
8. Generate docker-compose.yml adapted to the found architecture
9. If no Docker on server → generate systemd unit file instead of docker-compose
10. Set monitoringProfile with detected services, log paths, and critical ports

IMPORTANT: Respond with valid JSON only. No markdown, no code fences, no explanation outside JSON.
Match this exact schema:
{
  "summary": "string describing server",
  "architecture": "traefik-docker" | "nginx-standalone" | "nginx-docker" | "caddy" | "haproxy" | "bare-metal" | "unknown",
  "confidence": 0-100,
  "env": { "KEY": "value", ... },
  "dockerCompose": "yaml string or omit",
  "systemdUnit": "unit file string or omit",
  "proxyConfig": "nginx/caddy block or omit",
  "warnings": ["string", ...],
  "recommendations": ["string", ...],
  "monitoringProfile": {
    "services": ["name", ...],
    "logPaths": ["/var/log/...", ...],
    "criticalPorts": [443, ...],
    "customChecks": ["command", ...]
  }
}`;

export async function analyzeSnapshot(snapshot: ServerSnapshot): Promise<DiscoveryResult> {
  const sanitized = sanitizeForAI(snapshot);
  const prompt = `Analyze this server snapshot and generate Guardian SIEM configuration:\n\n${JSON.stringify(sanitized, null, 2)}`;

  const response = await AIProvider.chat(prompt, SYSTEM_PROMPT);

  if (response?.text) {
    try {
      const cleaned = response.text.replace(/```json?\n?/g, '').replace(/```/g, '').trim();
      const parsed = JSON.parse(cleaned);
      const validated = discoveryResultSchema.parse(parsed);
      logger.info({ provider: response.provider, confidence: validated.confidence }, 'Discovery AI analysis complete');
      return validated;
    } catch (err) {
      logger.warn({ err }, 'Discovery AI response failed validation, using fallback');
    }
  }

  logger.info('Discovery using heuristic fallback');
  return generateFallbackConfig(snapshot);
}

function sanitizeForAI(snapshot: ServerSnapshot): object {
  const safe = JSON.parse(JSON.stringify(snapshot));
  if (safe.probes?.system?.data?.recentAuthLogs) {
    safe.probes.system.data.recentAuthLogs = safe.probes.system.data.recentAuthLogs
      .map((l: string) => l.replace(/key fingerprint is \S+/g, 'key fingerprint is [REDACTED]'));
  }
  if (safe.probes?.security?.data?.firewall?.rules) {
    safe.probes.security.data.firewall.rules = safe.probes.security.data.firewall.rules.slice(0, 800);
  }
  return safe;
}
