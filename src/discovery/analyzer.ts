import { AIProvider } from '../services/ai-provider.js';
import { logger } from '../utils/logger.js';
import { discoveryResultSchema, type DiscoveryResult, type ServerSnapshot } from './types.js';
import { generateFallbackConfig } from './templates.js';

const SYSTEM_PROMPT = `You configure Guardian SIEM. Respond ONLY with compact JSON, no markdown.
Schema: {"summary":"<1 sentence>","architecture":"traefik-docker"|"nginx-standalone"|"nginx-docker"|"caddy"|"haproxy"|"bare-metal"|"unknown","confidence":0-100,"env":{"HOST_SSH_PORT":"N","HOST_SSH_USER":"x","AI_PROVIDER":"auto","DATABASE_URL":"postgres://guardian:pwd@guardian-db:5432/guardian"},"warnings":["short warning"],"recommendations":["short rec"],"monitoringProfile":{"services":["name"],"logPaths":["/path"],"criticalPorts":[N],"customChecks":[]}}
Rules: Traefik+Docker→traefik-docker. Nginx+Docker→nginx-docker. Nginx alone→nginx-standalone. No proxy+Docker→bare-metal with docker. No proxy+no docker→bare-metal. Only include env keys that differ from defaults. Keep warnings/recommendations under 3 items each.`;

export async function analyzeSnapshot(snapshot: ServerSnapshot): Promise<DiscoveryResult> {
  const compact = buildCompactInput(snapshot);
  const prompt = `Server scan:\n${compact}\n\nGenerate Guardian config JSON.`;

  const response = await AIProvider.chat(prompt, SYSTEM_PROMPT);

  if (response?.text) {
    try {
      const parsed = parseAIResponse(response.text);
      if (parsed) {
        const validated = discoveryResultSchema.parse(fillDefaults(parsed));
        logger.info({ provider: response.provider, confidence: validated.confidence }, 'Discovery AI analysis complete');
        return validated;
      }
    } catch (err) {
      logger.warn({ err }, 'Discovery AI response failed validation, using fallback');
    }
  }

  logger.info('Discovery using heuristic fallback');
  return generateFallbackConfig(snapshot);
}

function buildCompactInput(snapshot: ServerSnapshot): string {
  const { network, proxy, docker, security, system } = snapshot.probes;
  const lines: string[] = [];

  // OS (1 line)
  if (system.success) {
    lines.push(`OS: ${system.data.os.name || system.data.os.id} ${system.data.os.version} | Kernel: ${system.data.kernel} | CPU: ${system.data.cpu.cores}c | RAM: ${system.data.memoryMb.total}MB`);
  }

  // Network — only ports < 10000 (1-2 lines)
  if (network.success) {
    const importantPorts = network.data.listeningPorts
      .filter(p => p.port < 10000)
      .map(p => `${p.port}/${p.process}`)
      .slice(0, 15);
    lines.push(`Ports: ${importantPorts.join(', ') || 'none detected'}`);
    if (network.data.sshPort) lines.push(`SSH: port ${network.data.sshPort}`);
  }

  // Proxy (1 line)
  if (proxy.success) {
    if (proxy.data.detected !== 'none') {
      lines.push(`Proxy: ${proxy.data.detected} v${proxy.data.version || '?'} | Domains: ${proxy.data.domains.slice(0, 5).join(', ') || 'none'}`);
    } else {
      lines.push('Proxy: none');
    }
  }

  // Docker (1-2 lines)
  if (docker.success) {
    if (docker.data.installed) {
      const containers = docker.data.containers.map(c => c.name).slice(0, 10).join(', ');
      lines.push(`Docker: ${docker.data.runtime} v${docker.data.version} | Containers: ${containers || 'none running'}`);
      if (docker.data.networks.length > 0) {
        lines.push(`Networks: ${docker.data.networks.filter(n => !['bridge', 'host', 'none'].includes(n)).slice(0, 5).join(', ')}`);
      }
    } else {
      lines.push('Docker: not installed');
    }
  }

  // Security (2-3 lines)
  if (security.success) {
    const s = security.data;
    lines.push(`SSH config: Port=${s.sshConfig.port} PermitRoot=${s.sshConfig.permitRoot} PwdAuth=${s.sshConfig.passwordAuth}`);
    lines.push(`Firewall: ${s.firewall.tool} | fail2ban: ${s.fail2ban.active ? 'active (' + s.fail2ban.jails.join(',') + ')' : 'inactive'} | MAC: ${s.mac.type}`);
  }

  // Services (1 line — only interesting ones)
  if (system.success && system.data.services.length > 0) {
    const interesting = system.data.services
      .map(s => s.name)
      .filter(n => !['getty', 'systemd-', 'dbus', 'cron', 'rsyslog', 'snapd', 'unattended'].some(skip => n.includes(skip)))
      .slice(0, 12);
    if (interesting.length > 0) lines.push(`Services: ${interesting.join(', ')}`);
  }

  return lines.join('\n');
}

function parseAIResponse(text: string): Record<string, unknown> | null {
  let cleaned = text.replace(/```json?\n?/g, '').replace(/```/g, '').trim();

  // Try direct parse
  try { return JSON.parse(cleaned); } catch {}

  // Try to repair truncated JSON by closing open structures
  let repaired = cleaned;
  if (!repaired.endsWith('}')) {
    // Find last complete value and close
    const lastComplete = repaired.lastIndexOf('",');
    if (lastComplete > 0) {
      repaired = repaired.slice(0, lastComplete + 1);
    }
    // Close open arrays and objects
    const opens = (repaired.match(/[\[{]/g) || []).length;
    const closes = (repaired.match(/[\]}]/g) || []).length;
    for (let i = 0; i < opens - closes; i++) {
      const lastOpen = Math.max(repaired.lastIndexOf('['), repaired.lastIndexOf('{'));
      if (lastOpen >= 0) {
        repaired += repaired[lastOpen] === '[' ? ']' : '}';
      }
    }
  }
  try { return JSON.parse(repaired); } catch {}

  return null;
}

function fillDefaults(parsed: Record<string, unknown>): Record<string, unknown> {
  return {
    summary: parsed.summary || '',
    architecture: parsed.architecture || 'unknown',
    confidence: parsed.confidence ?? 70,
    env: parsed.env || {},
    dockerCompose: parsed.dockerCompose,
    systemdUnit: parsed.systemdUnit,
    proxyConfig: parsed.proxyConfig,
    warnings: Array.isArray(parsed.warnings) ? parsed.warnings : [],
    recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
    monitoringProfile: {
      services: (parsed.monitoringProfile as any)?.services || [],
      logPaths: (parsed.monitoringProfile as any)?.logPaths || ['/var/log/auth.log', '/var/log/syslog'],
      criticalPorts: (parsed.monitoringProfile as any)?.criticalPorts || [],
      customChecks: (parsed.monitoringProfile as any)?.customChecks || [],
    },
  };
}
