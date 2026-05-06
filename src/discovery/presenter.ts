import type { DiscoveryResult, ServerSnapshot } from './types.js';
import type { GeneratedConfig } from './config-generator.js';

export function formatTerminalPresentation(
  snapshot: ServerSnapshot,
  result: DiscoveryResult,
  config: GeneratedConfig,
): string {
  const os = snapshot.probes.system.data.os.name || 'Unknown OS';
  const containers = snapshot.probes.docker.data.containers.length;
  const sshPort = snapshot.probes.security.data.sshConfig.port || snapshot.probes.network.data.sshPort || 22;
  const proxy = snapshot.probes.proxy.data.detected;
  const proxyVersion = snapshot.probes.proxy.data.version;
  const envVars = Object.keys(result.env).length;

  const lines: string[] = [
    '',
    '╔══════════════════════════════════════════════════════════════════╗',
    '║  Guardian Auto-Discovery Complete                               ║',
    '╠══════════════════════════════════════════════════════════════════╣',
    '║                                                                  ║',
    `║  Server: ${pad(os, 52)}║`,
    `║  Architecture: ${pad(result.architecture, 46)}║`,
    `║  SSH Port: ${pad(String(sshPort), 50)}║`,
    `║  Reverse Proxy: ${pad(proxy !== 'none' ? `${proxy}${proxyVersion ? ` v${proxyVersion}` : ''}` : 'none detected', 44)}║`,
    `║  Containers: ${pad(String(containers) + ' running', 48)}║`,
    `║  Confidence: ${pad(result.confidence + '%', 48)}║`,
    '║                                                                  ║',
  ];

  if (result.warnings.length > 0) {
    lines.push('║  Warnings:                                                       ║');
    for (const w of result.warnings.slice(0, 4)) {
      lines.push(`║  - ${pad(w.slice(0, 56), 58)}║`);
    }
    lines.push('║                                                                  ║');
  }

  if (result.recommendations.length > 0) {
    lines.push('║  Recommendations:                                                ║');
    for (const r of result.recommendations.slice(0, 3)) {
      lines.push(`║  - ${pad(r.slice(0, 56), 58)}║`);
    }
    lines.push('║                                                                  ║');
  }

  lines.push(`║  Generated: .env (${envVars} vars) + ${pad(config.composeContent ? 'docker-compose.yml' : 'systemd unit', 26)}║`);
  lines.push('║                                                                  ║');
  lines.push('╚══════════════════════════════════════════════════════════════════╝');
  lines.push('');
  lines.push('[V] View full config    [A] Apply    [E] Edit .env    [Q] Quit');
  lines.push('');

  return lines.join('\n');
}

export function formatTelegramMessage(
  snapshot: ServerSnapshot,
  result: DiscoveryResult,
): string {
  const os = snapshot.probes.system.data.os.name || 'Unknown';
  const sshPort = snapshot.probes.security.data.sshConfig.port || 22;
  const containers = snapshot.probes.docker.data.containers.length;

  const lines: string[] = [
    `<b>Discovery completo</b> — ${snapshot.target.host}`,
    '',
    `<b>Resumo:</b>`,
    `• ${os} — ${result.architecture}`,
    `• SSH porta ${sshPort}`,
    `• ${containers} containers rodando`,
    `• Confiança: ${result.confidence}%`,
  ];

  if (result.warnings.length > 0) {
    lines.push('', '<b>Avisos:</b>');
    for (const w of result.warnings.slice(0, 4)) {
      lines.push(`• ${w}`);
    }
  }

  if (result.monitoringProfile.services.length > 0) {
    lines.push('', '<b>Monitoring Profile:</b>');
    lines.push(`• Serviços: ${result.monitoringProfile.services.slice(0, 5).join(', ')}`);
    lines.push(`• Logs: ${result.monitoringProfile.logPaths.slice(0, 3).join(', ')}`);
    lines.push(`• Portas: ${result.monitoringProfile.criticalPorts.slice(0, 6).join(', ')}`);
  }

  if (result.recommendations.length > 0) {
    lines.push('', '<b>Recomendações:</b>');
    for (const r of result.recommendations.slice(0, 3)) {
      lines.push(`• ${r}`);
    }
  }

  return lines.join('\n');
}

function pad(text: string, width: number): string {
  return text + ' '.repeat(Math.max(0, width - text.length));
}
