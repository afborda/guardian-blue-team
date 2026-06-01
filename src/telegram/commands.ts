import { logger } from '../utils/logger.js';
import { DailyReportWorker } from '../workers/daily-report.worker.js';
import { ServerService } from '../services/server.service.js';
import { SSHCollector } from '../collectors/ssh-collector.js';
import { CronCollector } from '../collectors/cron-collector.js';
import { SSHKeysCollector } from '../collectors/ssh-keys-collector.js';
import { db, dbTrue } from '../database/connection.js';
import { securityEvents, socIncidents, socServers, serverScores, serverMetrics, blockedIps, threatHuntFindings, rateLimitedIps, playbookExecutions } from '../database/schema.js';
import { desc, eq, ne, count, and, gte, inArray } from 'drizzle-orm';
import { ThreatIntelManager } from '../threat-intel/manager.js';
import { PlaybookRegistry } from '../playbooks/registry.js';
import { PlaybookEngine, type PlaybookContext } from '../playbooks/engine.js';
import { VulnScanner } from '../vuln-scanner/scanner.js';
import { RuntimeVersionScanner } from '../vuln-scanner/runtime-versions.js';
import { SOCAnalystService } from '../services/soc-analyst.service.js';
import { AIProvider } from '../services/ai-provider.js';
import { IncidentMemoryService } from '../services/incident-memory.service.js';
import { blockIP, unblockIP, verifyBlock, syncBlocksToServer, type BlockMethod } from '../playbooks/actions/block-ip.js';
import { isValidHostname, isValidIp, isValidSshUser, isValidKeyPath, isValidServerName } from '../utils/sanitize.js';
import { discoverRemoteServer, formatDiscoveryApprovalKeyboard } from '../discovery/remote.js';
import { ServerReadinessService } from '../services/server-readiness.service.js';
import { rotateToken } from '../dashboard/auth.js';
import { config } from '../config/environment.js';
import { LegacyMigrationWorker } from '../workers/legacy-migration.worker.js';

const pendingDiscoveries = new Map<number, { analysis: import('../discovery/types.js').DiscoveryResult; serverName: string }>();
const pendingReadiness = new Map<number, { target: ReturnType<typeof ServerService.toSSHTarget>; missing: import('../services/server-readiness.service.js').ReadinessCheck[]; serverName: string }>();

export { pendingDiscoveries, pendingReadiness };

export async function handleTelegramCommand(text: string): Promise<string> {
  const parts = text.split(/\s+/);
  const command = parts[0].toLowerCase().replace(/@\w+$/, '').replace(/_/g, '-');

  switch (command) {
    case '/status':
      return await getMultiServerStatus();
    case '/servers':
      return await listServers();
    case '/events':
      return await getRecentEvents(parts[1]);
    case '/incidents':
      return await getOpenIncidents(true);
    case '/threat':
      return await threatLookup(parts[1]);
    case '/hunt':
      return await huntIOC(parts[1]);
    case '/playbook':
      return await handlePlaybook(parts.slice(1));
    case '/vulns':
      return await getVulnSummary();
    case '/ask':
      return await askSOCAnalyst(parts.slice(1).join(' '));
    case '/containers':
      return await getContainers(parts[1]);
    case '/health':
      return await getFleetHealth();
    case '/scores':
      return await getServerScores(parts[1]);
    case '/scan':
      return '🔍 Use /vulns para verificar vulnerabilidades ou aguarde o CVE Monitor automático.';
    case '/files':
      return await getFileChanges(parts[1]);
    case '/sudo':
      return await getSudoActivity(parts[1]);
    case '/crons':
      return await getCronJobs(parts[1]);
    case '/keys':
      return await getSSHKeys(parts[1]);
    case '/dns':
      return await getDNSActivity(parts[1], parts[2]);
    case '/report':
      if (parts[1] === 'full') return await getFullReport();
      DailyReportWorker.sendReport().catch(err =>
        logger.error({ err }, 'Manual report trigger failed')
      );
      return '📊 Relatório sendo gerado...';
    case '/add-server':
      return await addServer(parts.slice(1));
    case '/upgrade-server':
      return await upgradeServer(parts[1]);
    case '/rm-server':
      return await removeServer(parts[1]);
    case '/apis':
      return getApiStatus();
    case '/block':
      return await blockIPCommand(parts.slice(1));
    case '/unblock':
      return await unblockIPCommand(parts.slice(1));
    case '/firewall':
      return await getFirewallStatus(parts[1]);
    case '/verify-blocks':
      return await verifyBlocksCommand();
    case '/services':
      return await getServices(parts[1]);
    case '/ai':
      return getAIStatus();
    case '/learn':
      return await learnFromIncident(parts.slice(1));
    case '/memory':
      return await getMemoryStats();
    case '/dashboard':
      return getDashboardUrl();
    case '/hunts':
      return await getThreatHuntResults();
    case '/rate-limits':
      return await getRateLimits();
    case '/playbook-log':
      return await getPlaybookLog();
    case '/versions':
      return await getRuntimeVersions(parts[1]);
    case '/help':
      return formatHelp();
    default:
      return `Comando desconhecido: ${command}\nUse /help`;
  }
}

// ─── /status ────────────────────────────────────────────────────────────────

async function getMultiServerStatus(): Promise<string> {
  const servers = await ServerService.getEnabled();
  if (servers.length === 0) return '⚠️ Nenhum servidor. Use /add-server';

  const results = await Promise.all(
    servers.map(async server => {
      const target = ServerService.toSSHTarget(server);
      const reachable = await SSHCollector.isReachable(target);

      if (!reachable) return `🔴 <b>${server.name}</b> — offline`;

      const infoResult = await SSHCollector.run(target,
        "echo \"$(nproc):$(uptime -p):$(cat /proc/loadavg | cut -d' ' -f1):" +
        "$(free -m | awk '/^Mem:/{printf \"%d/%d\", $3, $2}'):" +
        "$(df -h / | awk 'NR==2{printf \"%s/%s (%s)\", $3, $2, $5}')\"",
        8_000
      );

      await ServerService.updateLastSeen(server.id);

      if (!infoResult.success) {
        return `🟡 <b>${server.name}</b> — parcial`;
      }

      const [cores, uptime, load1, mem, disk] = infoResult.stdout.trim().split(':');
      const loadNum = parseFloat(load1 || '0');
      const coreCount = parseInt(cores || '1');
      const loadRatio = loadNum / coreCount;
      const loadIcon = loadRatio < 0.7 ? '✅' : loadRatio < 1.5 ? '🟡' : '⚠️';

      return [
        `🟢 <b>${server.name}</b>`,
        `   ⏱ ${(uptime || 'unknown').replace('up ', '')} | 📊 Load: ${load1} ${loadIcon} (${cores} cores)`,
        `   💾 ${mem || '?'} MB | 💿 ${disk || '?'}`,
      ].join('\n');
    })
  );

  return `🖥️ <b>Status — ${servers.length} servidores</b>\n\n${results.join('\n\n')}`;
}

// ─── /servers ───────────────────────────────────────────────────────────────

async function listServers(): Promise<string> {
  const servers = await ServerService.getAll();
  if (servers.length === 0) return '📋 Nenhum servidor.\nUse /add-server nome host [porta] [user] [key_path]';

  const healthResults = await ServerService.checkHealth();

  const lines = healthResults.map(({ server, reachable }) => {
    const icon = reachable ? '🟢' : '🔴';
    const tags = server.tags.length > 0 ? ` [${server.tags.join(', ')}]` : '';
    const enabled = server.enabled ? '' : ' (disabled)';
    const lastSeen = server.lastSeenAt ? ` — ${timeAgo(server.lastSeenAt)}` : '';
    return `${icon} <b>${server.name}</b>${tags}${enabled}\n   ${server.sshUser}@${server.host}:${server.sshPort}${lastSeen}`;
  });

  return `📋 <b>Servidores (${servers.length})</b>\n\n${lines.join('\n\n')}`;
}

// ─── /containers ────────────────────────────────────────────────────────────

async function getContainers(serverName?: string): Promise<string> {
  if (serverName) {
    const server = await ServerService.getByName(serverName);
    if (!server) return `❌ Servidor "${serverName}" não encontrado.`;
    const target = ServerService.toSSHTarget(server);
    return await formatContainers(target);
  }

  const servers = await ServerService.getEnabled();
  if (servers.length === 0) return '⚠️ Nenhum servidor registrado.';

  const sections: string[] = [];
  for (const server of servers) {
    const target = ServerService.toSSHTarget(server);
    const result = await SSHCollector.run(target, "docker ps --format '{{.Names}}\t{{.Status}}'", 10_000);

    if (!result.success) {
      sections.push(`━━ <b>${server.name}</b> — ❌ erro`);
      continue;
    }

    const lines = result.stdout.trim().split('\n').filter(Boolean);
    const formatted = lines.slice(0, 15).map(line => {
      const [name, status] = line.split('\t');
      const icon = status?.includes('Up') ? '🟢' : '🔴';
      return `${icon} <code>${name}</code>`;
    });

    const more = lines.length > 15 ? `\n   ... +${lines.length - 15} mais` : '';
    sections.push(`━━ <b>${server.name}</b> (${lines.length}) ━━\n${formatted.join('\n')}${more}`);
  }

  return `🐳 <b>Containers — ${servers.length} servidores</b>\n\n${sections.join('\n\n')}`;
}

async function formatContainers(target: { name: string; host: string; sshPort: number; sshUser: string; sshKeyPath: string | null; id: number }): Promise<string> {
  const result = await SSHCollector.run(target, "docker ps --format '{{.Names}}\t{{.Status}}'", 10_000);
  if (!result.success) return `❌ Falha ao listar containers em ${target.name}`;

  const lines = result.stdout.trim().split('\n').filter(Boolean);
  if (lines.length === 0) return `🐳 Nenhum container rodando em ${target.name}.`;

  const formatted = lines.slice(0, 30).map(line => {
    const [name, status] = line.split('\t');
    const icon = status?.includes('Up') ? '🟢' : '🔴';
    return `${icon} <code>${name}</code>`;
  });

  return `🐳 <b>${target.name} (${lines.length})</b>\n\n${formatted.join('\n')}`;
}

// ─── /events ────────────────────────────────────────────────────────────────

async function getRecentEvents(filterArg?: string): Promise<string> {
  const minSeverity = filterArg || 'low';
  const severityLevels: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const minLevel = severityLevels[minSeverity] ?? 1;

  const events = await db.select({
    id: securityEvents.id,
    serverId: securityEvents.serverId,
    timestamp: securityEvents.timestamp,
    severity: securityEvents.severity,
    eventType: securityEvents.eventType,
    sourceIp: securityEvents.sourceIp,
    userName: securityEvents.userName,
    source: securityEvents.source,
  })
    .from(securityEvents)
    .where(ne(securityEvents.severity, 'info'))
    .orderBy(desc(securityEvents.timestamp))
    .limit(30);

  const filtered = events.filter(e => (severityLevels[e.severity] ?? 0) >= minLevel);
  if (filtered.length === 0) return `📋 Nenhum evento com severidade &gt;= ${minSeverity}.`;

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };

  const lines = filtered.slice(0, 20).map(e => {
    const icon = severityIcon[e.severity] ?? '⚪';
    const time = e.timestamp.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
    const who = e.sourceIp ? ` ${e.sourceIp}` : e.userName ? ` ${e.userName}` : '';
    const server = serverNames.get(e.serverId!) ?? '?';
    return `${icon} ${time} <b>${e.eventType}</b>${who} [${server}]`;
  });

  return `📊 <b>Eventos (${minSeverity}+)</b>\n\n${lines.join('\n')}`;
}

// ─── /incidents ─────────────────────────────────────────────────────────────

async function getOpenIncidents(withButtons = false): Promise<string> {
  const incidents = await db.select()
    .from(socIncidents)
    .where(eq(socIncidents.status, 'open'))
    .orderBy(desc(socIncidents.lastSeenAt))
    .limit(10);

  if (incidents.length === 0) return '✅ Nenhum incidente aberto.';

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };

  if (withButtons) {
    for (const i of incidents) {
      const icon = severityIcon[i.severity] ?? '⚪';
      const ago = timeAgo(i.lastSeenAt);
      const affectedIds = (i.affectedServers ?? []) as number[];
      const serverName = affectedIds.length > 0 ? serverNames.get(affectedIds[0]) ?? '?' : '?';
      const ips = (i.sourceIps ?? []) as string[];
      const mainIp = ips[0];

      const text = `${icon} <b>#${i.id} ${i.title}</b>\n📍 ${serverName} | ${i.eventCount} eventos | ${ago}`;

      const buttons: { text: string; callback_data: string }[][] = [[
        { text: '✅ Resolver', callback_data: `incident_confirm_${i.id}` },
        { text: '🚫 Falso Positivo', callback_data: `incident_fp_${i.id}` },
      ]];

      if (mainIp && /^[\d.]+$/.test(mainIp)) {
        buttons.push([
          { text: `🔒 Bloquear ${mainIp}`, callback_data: `incident_block_${i.id}_${mainIp}` },
          { text: `🔍 Threat Intel`, callback_data: `incident_threat_${i.id}_${mainIp}` },
        ]);
      }

      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text,
          parse_mode: 'HTML',
          reply_markup: { inline_keyboard: buttons },
        }),
      }).catch(() => {});
    }

    return `🚨 <b>Incidentes Abertos: ${incidents.length}</b>`;
  }

  const lines = incidents.map(i => {
    const icon = severityIcon[i.severity] ?? '⚪';
    const ago = timeAgo(i.lastSeenAt);
    const affectedIds = (i.affectedServers ?? []) as number[];
    const serverName = affectedIds.length > 0 ? serverNames.get(affectedIds[0]) ?? '?' : '?';

    const ips = (i.sourceIps ?? []) as string[];
    const mainIp = ips[0];
    let suggestion = '';
    if (mainIp && /^[\d.]+$/.test(mainIp)) {
      suggestion = `\n   💡 /threat ${mainIp}`;
    }

    return `${icon} <b>#${i.id} ${i.title}</b>\n   📍 ${serverName} | ${i.eventCount} eventos | ${ago}${suggestion}`;
  });

  return `🚨 <b>Incidentes Abertos (${incidents.length})</b>\n\n${lines.join('\n\n')}`;
}

// ─── /threat ────────────────────────────────────────────────────────────────

const EVENT_TYPE_PT: Record<string, string> = {
  ssh_failed_password: 'senha errada (SSH)',
  ssh_invalid_user: 'usuário inexistente (SSH)',
  ssh_login: 'login SSH',
  unauthorized_login: 'login não autorizado',
  port_scan: 'port scan',
  brute_force: 'força bruta',
  ssh_brute_force: 'força bruta SSH',
  crypto_mining: 'mineração de cripto',
  container_escape: 'escape de container',
  dns_dga: 'DNS suspeito (C2)',
  fim_change: 'alteração de arquivo',
  sudo_abuse: 'abuso de sudo',
  reverse_shell: 'reverse shell',
};

async function threatLookup(ip: string | undefined): Promise<string> {
  if (!ip) return '❌ Uso: /threat &lt;ip&gt;\nEx: /threat 8.8.8.8';
  if (!/^[\d.:a-fA-F]+$/.test(ip)) return '❌ IP inválido.';

  const lines: string[] = [`🔍 <b>Threat: ${ip}</b>`, ''];

  const report = await ThreatIntelManager.lookupIP(ip);
  if (report) {
    const scoreBar = report.score >= 80 ? '🔴' : report.score >= 50 ? '🟠' : report.score >= 25 ? '🟡' : '🟢';
    lines.push(
      `${scoreBar} Reputação: <b>${report.score}/100</b> (quanto maior, pior)`,
      `📊 Denúncias: ${report.totalReports} | 🌍 País: ${report.country} | 🏢 Provedor: ${report.isp}`,
      ''
    );
  } else {
    lines.push('⚠️ AbuseIPDB: não disponível (sem API key)', '');
  }

  const serverNames = await getServerNameMap();
  const eventsByServer = await db.select({
    serverId: securityEvents.serverId,
    eventType: securityEvents.eventType,
    cnt: count(),
  })
    .from(securityEvents)
    .where(eq(securityEvents.sourceIp, ip))
    .groupBy(securityEvents.serverId, securityEvents.eventType);

  if (eventsByServer.length > 0) {
    lines.push('📋 <b>Atividade nos nossos servidores:</b>');
    for (const row of eventsByServer) {
      const name = serverNames.get(row.serverId!) ?? '?';
      const typeLabel = EVENT_TYPE_PT[row.eventType!] ?? row.eventType;
      lines.push(`   • ${row.cnt}× ${typeLabel} em ${name}`);
    }

    const [firstEvent] = await db.select({ ts: securityEvents.timestamp })
      .from(securityEvents).where(eq(securityEvents.sourceIp, ip))
      .orderBy(securityEvents.timestamp).limit(1);
    const [lastEvent] = await db.select({ ts: securityEvents.timestamp })
      .from(securityEvents).where(eq(securityEvents.sourceIp, ip))
      .orderBy(desc(securityEvents.timestamp)).limit(1);

    if (firstEvent && lastEvent) {
      const fmt = (d: Date) => d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
      lines.push(`   ⏱ Primeiro: ${fmt(firstEvent.ts)} | Último: ${fmt(lastEvent.ts)}`);
    }
  } else {
    lines.push('📋 Nenhuma atividade deste IP nos nossos servidores.');
  }

  lines.push('');

  // Recomendação em português baseada no score e eventos
  if (report) {
    const eventCount = eventsByServer.reduce((sum, r) => sum + Number(r.cnt), 0);
    if (report.score >= 80) {
      lines.push(
        '⚠️ <b>RECOMENDAÇÃO: BLOQUEAR</b>',
        `Este IP é altamente malicioso (score ${report.score}/100).`,
        `Reportado ${report.totalReports} vezes. Risco real de ataque.`,
        `→ /block ${ip}`,
      );
    } else if (report.score >= 50) {
      lines.push(
        '🟠 <b>RECOMENDAÇÃO: PROVÁVEL AMEAÇA</b>',
        `Score moderado (${report.score}/100) com ${report.totalReports} reports.`,
        eventCount > 5
          ? 'Múltiplas tentativas nos nossos logs. Recomendo bloquear.'
          : 'Poucos eventos locais. Monitorar, bloquear se persistir.',
        `→ /block ${ip}`,
      );
    } else if (report.score >= 25) {
      lines.push(
        '🟡 <b>RECOMENDAÇÃO: SUSPEITO</b>',
        `Score baixo-médio (${report.score}/100). Pode ser scanner automatizado.`,
        eventCount > 10
          ? 'Muita atividade local — considere bloquear.'
          : 'Monitorar por agora. Não é urgente.',
      );
    } else {
      lines.push(
        '🟢 <b>RECOMENDAÇÃO: SEGURO</b>',
        `IP com boa reputação (score ${report.score}/100).`,
        'Provavelmente legítimo. Não precisa bloquear.',
      );
    }
  } else {
    const eventCount = eventsByServer.reduce((sum, r) => sum + Number(r.cnt), 0);
    if (eventCount > 20) {
      lines.push('🟠 <b>RECOMENDAÇÃO: BLOQUEAR</b>', 'Muita atividade suspeita nos logs, mesmo sem dados do AbuseIPDB.');
    } else {
      lines.push('⚪ <b>SEM DADOS SUFICIENTES</b>', 'Sem AbuseIPDB e pouca atividade. Monitorar.');
    }
  }

  return lines.join('\n');
}

// ─── /hunt ──────────────────────────────────────────────────────────────────

async function huntIOC(ioc: string | undefined): Promise<string> {
  if (!ioc) return '❌ Uso: /hunt &lt;ip|username&gt;\nEx: /hunt 8.8.8.8';

  const isIP = /^[\d.:a-fA-F]+$/.test(ioc);

  const events = await db.select()
    .from(securityEvents)
    .where(isIP
      ? eq(securityEvents.sourceIp, ioc)
      : eq(securityEvents.userName, ioc)
    )
    .orderBy(desc(securityEvents.timestamp))
    .limit(20);

  if (events.length === 0) return `🔍 Nenhum evento para "${ioc}"`;

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

  const lines = events.map(e => {
    const icon = severityIcon[e.severity] ?? '⚪';
    const time = e.timestamp.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    const server = serverNames.get(e.serverId!) ?? '?';
    return `${icon} ${time} ${e.eventType} [${server}]`;
  });

  const header = isIP ? `🔍 <b>Hunt: ${ioc}</b>` : `🔍 <b>Hunt user: ${ioc}</b>`;
  return `${header}\n${events.length} evento(s)\n\n${lines.join('\n')}`;
}

// ─── /report full ───────────────────────────────────────────────────────────

async function getFullReport(): Promise<string> {
  const [totalEventsResult] = await db.select({ cnt: count() }).from(securityEvents);
  const [totalIncidentsResult] = await db.select({ cnt: count() }).from(socIncidents);
  const [openIncidents] = await db.select({ cnt: count() }).from(socIncidents).where(eq(socIncidents.status, 'open'));

  const topAttackers = await db.select({
    ip: securityEvents.sourceIp,
    cnt: count(),
  })
    .from(securityEvents)
    .where(ne(securityEvents.severity, 'info'))
    .groupBy(securityEvents.sourceIp)
    .orderBy(desc(count()))
    .limit(10);

  const [firstEvent] = await db.select({ ts: securityEvents.timestamp })
    .from(securityEvents).orderBy(securityEvents.timestamp).limit(1);

  const since = firstEvent
    ? firstEvent.ts.toLocaleDateString('pt-BR')
    : 'N/A';

  const lines = [
    `📊 <b>RELATÓRIO COMPLETO</b>`,
    `📅 Desde: ${since}`,
    ``,
    `📈 <b>Totais:</b>`,
    `   • ${totalEventsResult.cnt} eventos coletados`,
    `   • ${totalIncidentsResult.cnt} incidentes (${openIncidents.cnt} abertos)`,
    ``,
    `🎯 <b>Top 10 Atacantes:</b>`,
  ];

  topAttackers.forEach((a, i) => {
    if (a.ip) lines.push(`   ${i + 1}. <code>${a.ip}</code> — ${a.cnt} eventos`);
  });

  const eventsByType = await db.select({
    type: securityEvents.eventType,
    cnt: count(),
  })
    .from(securityEvents)
    .where(ne(securityEvents.severity, 'info'))
    .groupBy(securityEvents.eventType)
    .orderBy(desc(count()))
    .limit(5);

  if (eventsByType.length > 0) {
    lines.push('', '📋 <b>Top Tipos de Evento:</b>');
    eventsByType.forEach(e => lines.push(`   • ${e.type}: ${e.cnt}`));
  }

  return lines.join('\n');
}

// ─── /playbook ──────────────────────────────────────────────────────────────

async function handlePlaybook(args: string[]): Promise<string> {
  const subcommand = args[0];

  if (!subcommand || subcommand === 'list') {
    const playbooks = PlaybookRegistry.getAll();
    const lines = playbooks.map(p => {
      const approval = p.requiresApproval ? '🔒' : '⚡';
      return `${approval} <b>${p.name}</b>\n   ${p.description}`;
    });
    return `📋 <b>Playbooks (${playbooks.length})</b>\n\n${lines.join('\n\n')}\n\n⚡ = auto | 🔒 = requer aprovação`;
  }

  if (subcommand === 'run') {
    const [, playbookName, serverName, ip] = args;
    if (!playbookName || !serverName) {
      return '❌ Uso: /playbook run &lt;name&gt; &lt;server&gt; [ip]\nEx: /playbook run ssh-brute-force ovh-main 1.2.3.4';
    }

    const playbook = PlaybookRegistry.getByName(playbookName);
    if (!playbook) return `❌ Playbook "${playbookName}" não encontrado.\nUse /playbook list`;

    const server = await ServerService.getByName(serverName);
    if (!server) return `❌ Servidor "${serverName}" não encontrado.`;

    const ctx: PlaybookContext = {
      serverId: server.id,
      serverName: server.name,
      sourceIp: ip,
      triggeredBy: 'manual',
      variables: {},
    };

    PlaybookEngine.execute(playbook, ctx).catch(err =>
      logger.error({ err, playbook: playbookName }, 'Playbook execution failed')
    );

    return `⚡ Playbook "${playbookName}" iniciado em ${serverName}${ip ? ` (IP: ${ip})` : ''}`;
  }

  return '❌ Uso: /playbook list | /playbook run &lt;name&gt; &lt;server&gt; [ip]';
}

// ─── /vulns ─────────────────────────────────────────────────────────────────

async function getVulnSummary(): Promise<string> {
  const summary = await VulnScanner.getSummary();
  if (summary.length === 0) return '📋 Nenhum servidor registrado.';

  const totalVulns = summary.reduce((t, s) => t + s.open, 0);
  if (totalVulns === 0) return '✅ Nenhuma vulnerabilidade aberta.';

  const lines = summary
    .filter(s => s.open > 0)
    .map(s => {
      const sevParts = Object.entries(s.bySeverity)
        .sort((a, b) => severityOrder(a[0]) - severityOrder(b[0]))
        .map(([sev, cnt]) => `${cnt} ${sev}`);
      return `🖥️ <b>${s.serverName}</b>: ${s.open} vuln(s)\n   ${sevParts.join(' | ')}`;
    });

  return `🔍 <b>Vulnerabilidades (${totalVulns})</b>\n\n${lines.join('\n\n')}`;
}

// ─── /ask ───────────────────────────────────────────────────────────────────

async function askSOCAnalyst(question: string): Promise<string> {
  if (!question.trim()) return '❌ Uso: /ask &lt;pergunta&gt;\nEx: /ask quantos ataques SSH essa semana?';
  if (!SOCAnalystService.isAvailable()) return '⚠️ AI não configurada (nenhum provider disponível: Ollama, Gemini, OpenAI ou Claude).';

  const answer = await SOCAnalystService.naturalLanguageQuery(question);
  if (!answer) return '⚠️ Não foi possível obter resposta da AI.';
  return `🤖 <b>SOC Analyst</b>\n\n${answer}`;
}

// ─── /add-server & /rm-server ───────────────────────────────────────────────

async function addServer(args: string[]): Promise<string> {
  if (args.length < 2) {
    return '❌ Uso: /add-server nome host [porta] [user] [key_path]\nEx: /add-server ovh-main 1.2.3.4 22 ubuntu /root/.ssh/id_ed25519';
  }

  const [name, host, portStr, user, keyPath] = args;
  const sshPort = portStr ? parseInt(portStr) : 22;

  if (!isValidServerName(name)) return '❌ Nome inválido (use a-z, 0-9, -, _, . — max 64 chars).';
  if (!isValidHostname(host) && !isValidIp(host)) return '❌ Hostname/IP inválido.';
  if (isNaN(sshPort) || sshPort < 1 || sshPort > 65535) return '❌ Porta SSH inválida.';
  if (user && !isValidSshUser(user)) return '❌ Usuário SSH inválido (a-z, 0-9, _, - — max 32 chars).';
  if (keyPath && !isValidKeyPath(keyPath)) return '❌ Caminho de chave SSH inválido (path absoluto, sem ..).';

  const existing = await ServerService.getByName(name);
  if (existing) return `❌ Servidor "${name}" já existe.`;

  const server = await ServerService.add({ name, host, sshPort, sshUser: user || 'ubuntu', sshKeyPath: keyPath });
  const target = ServerService.toSSHTarget(server);
  const reachable = await SSHCollector.isReachable(target);

  if (!reachable) {
    await ServerService.remove(name);
    return `❌ Não foi possível conectar a ${host}:${sshPort}. Servidor não adicionado.`;
  }

  // Readiness check in background
  ServerReadinessService.check(target).then(async (readiness) => {
    if (readiness.missing.length === 0) {
      // All tools present — sync blocks and start discovery
      const synced = await syncBlocksToServer(server.id);
      const syncMsg = synced > 0 ? `\n🔒 ${synced} IPs bloqueados sincronizados.` : '';

      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text: `✅ <b>${name}</b> — todas ferramentas OK!\n\n🛠️ Instalados: ${readiness.installed.join(', ')}${syncMsg}`,
          parse_mode: 'HTML',
        }),
      }).catch(() => {});
    } else {
      // Missing tools — ask user
      pendingReadiness.set(server.id, { target, missing: readiness.missing, serverName: name });
      setTimeout(() => pendingReadiness.delete(server.id), 30 * 60_000);

      const lines = [`⚠️ <b>${name}</b> — ferramentas faltando:\n`];
      for (const m of readiness.missing) {
        const icon = m.required ? '🔴' : '🟡';
        lines.push(`${icon} <b>${m.tool}</b> — ${m.description}`);
      }
      if (readiness.installed.length > 0) {
        lines.push(`\n✅ Já instalados: ${readiness.installed.join(', ')}`);
      }
      lines.push(`\nDeseja instalar e configurar automaticamente?`);

      const keyboard = {
        inline_keyboard: [[
          { text: '✅ Instalar e configurar', callback_data: `readiness_install_${server.id}` },
          { text: '⏭️ Pular', callback_data: `readiness_skip_${server.id}` },
        ]],
      };

      await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text: lines.join('\n'),
          parse_mode: 'HTML',
          reply_markup: keyboard,
        }),
      }).catch(err => logger.warn({ err }, 'Failed to send readiness message'));
    }
  }).catch(err => logger.warn({ err }, 'Readiness check failed'));

  // Discovery in background (parallel to readiness)
  discoverRemoteServer(target).then(async discoveryResult => {
    if (!discoveryResult) return;

    pendingDiscoveries.set(server.id, { analysis: discoveryResult.analysis, serverName: name });

    const keyboard = formatDiscoveryApprovalKeyboard(server.id);
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text: discoveryResult.telegramMessage,
        parse_mode: 'HTML',
        reply_markup: keyboard,
      }),
    }).catch(err => logger.warn({ err }, 'Failed to send discovery message'));

    setTimeout(() => pendingDiscoveries.delete(server.id), 30 * 60_000);
  }).catch(err => logger.warn({ err }, 'Background discovery failed'));

  return `✅ <b>${name}</b> adicionado (${user || 'ubuntu'}@${host}:${sshPort}) 🟢\n\n🔍 Verificando ferramentas e auto-discovery...`;
}

async function removeServer(name: string | undefined): Promise<string> {
  if (!name) return '❌ Uso: /rm-server nome';
  const removed = await ServerService.remove(name);
  if (!removed) return `❌ Servidor "${name}" não encontrado.`;
  return `✅ Servidor "${name}" removido.`;
}

// ─── /upgrade-server ────────────────────────────────────────────────────────

async function upgradeServer(idStr: string | undefined): Promise<string> {
  if (!idStr) return '❌ Uso: /upgrade-server &lt;id&gt;\nEx: /upgrade-server 5';
  const id = parseInt(idStr);
  if (isNaN(id) || id < 1) return '❌ ID inválido.';

  const servers = await ServerService.getEnabled();
  const server = servers.find(s => s.id === id);
  if (!server) return `❌ Servidor id=${id} não encontrado ou desabilitado.`;

  if (server.installMode === 'guardian') {
    return `ℹ️ <b>${server.name}</b> já está em modo Tier 0 (guardian).`;
  }

  LegacyMigrationWorker.upgradeOne(server).catch(err =>
    logger.error({ err, server: server.name }, '/upgrade-server background upgrade error'),
  );

  return (
    `🔄 Upgrade Tier 0 iniciado para <b>${server.name}</b> (${server.host})\n` +
    `Você receberá notificação ao final.\n` +
    `<i>Para acompanhar: /status</i>`
  );
}



async function blockIPCommand(args: string[]): Promise<string> {
  if (args.length < 1) {
    return '❌ Uso: /block &lt;ip&gt; [server] [duration]\nEx: /block 1.2.3.4 hetzner-prod 7d\nDurações: 1h, 24h, 7d, 30d, permanent (padrão: permanent)';
  }

  const [ip, serverName, duration] = args;
  if (!isValidIp(ip)) return '❌ IP inválido.';

  const servers = serverName
    ? [await ServerService.getByName(serverName)].filter(Boolean)
    : await ServerService.getEnabled();

  if (servers.length === 0) return serverName ? `❌ Servidor "${serverName}" não encontrado.` : '⚠️ Nenhum servidor registrado.';

  const results: string[] = [];
  for (const server of servers) {
    if (!server) continue;
    const result = await blockIP(
      { serverId: server.id, serverName: server.name, sourceIp: ip, triggeredBy: 'telegram', variables: {} },
      { duration: duration || 'permanent' }
    );
    const icon = result.success ? '✅' : '❌';
    results.push(`${icon} ${server.name}: ${result.message}`);
  }

  return `🚫 <b>Block ${ip}</b>\n\n${results.join('\n')}`;
}

// ─── /unblock ──────────────────────────────────────────────────────────────

async function unblockIPCommand(args: string[]): Promise<string> {
  if (args.length < 1) {
    return '❌ Uso: /unblock &lt;ip&gt; [server]\nEx: /unblock 1.2.3.4 hetzner-prod';
  }

  const [ip, serverName] = args;
  if (!isValidIp(ip)) return '❌ IP inválido.';

  const servers = serverName
    ? [await ServerService.getByName(serverName)].filter(Boolean)
    : await ServerService.getEnabled();

  if (servers.length === 0) return serverName ? `❌ Servidor "${serverName}" não encontrado.` : '⚠️ Nenhum servidor registrado.';

  const results: string[] = [];
  for (const server of servers) {
    if (!server) continue;
    const result = await unblockIP(
      { serverId: server.id, serverName: server.name, sourceIp: ip, triggeredBy: 'telegram', variables: {} },
      { ip }
    );
    const icon = result.success ? '✅' : '❌';
    results.push(`${icon} ${server.name}: ${result.message}`);
  }

  return `🔓 <b>Unblock ${ip}</b>\n\n${results.join('\n')}`;
}

// ─── /firewall ─────────────────────────────────────────────────────────────

async function getFirewallStatus(serverName?: string): Promise<string> {
  const servers = serverName
    ? [await ServerService.getByName(serverName)].filter(Boolean)
    : await ServerService.getEnabled();

  if (servers.length === 0) return serverName ? `❌ Servidor "${serverName}" não encontrado.` : '⚠️ Nenhum servidor registrado.';

  const sections: string[] = [];
  for (const server of servers) {
    if (!server) continue;
    const target = ServerService.toSSHTarget(server);

    const ufwResult = await SSHCollector.run(target, 'sudo ufw status numbered 2>/dev/null | head -30', 10_000);
    if (!ufwResult.success) {
      sections.push(`━━ <b>${server.name}</b> — ❌ erro ou UFW não disponível`);
      continue;
    }

    const lines = ufwResult.stdout.trim().split('\n');
    const statusLine = lines[0] || '';
    const isActive = statusLine.toLowerCase().includes('active');
    const icon = isActive ? '🟢' : '🔴';
    const rules = lines.slice(3).filter(l => l.trim()).slice(0, 15);

    const formatted = rules.length > 0
      ? rules.map(r => `   ${r.trim()}`).join('\n')
      : '   (sem regras)';

    sections.push(`${icon} <b>${server.name}</b> — ${statusLine}\n${formatted}`);
  }

  return `🧱 <b>Firewall Status</b>\n\n${sections.join('\n\n')}`;
}

// ─── /verify-blocks ───────────────────────────────────────────────────────

async function verifyBlocksCommand(): Promise<string> {
  const activeBlocks = await db.select().from(blockedIps)
    .where(eq(blockedIps.active, dbTrue));

  if (activeBlocks.length === 0) return '✅ Nenhum IP bloqueado no momento.';

  const servers = await ServerService.getEnabled();
  let verified = 0;
  let missing = 0;
  const missingList: string[] = [];

  for (const block of activeBlocks) {
    const server = servers.find(s => s.id === block.serverId);
    if (!server) continue;

    const target = ServerService.toSSHTarget(server);
    const isBlocked = await verifyBlock(target, block.ip, (block.method as BlockMethod) || 'ufw');

    if (isBlocked) {
      verified++;
      if (!block.verified) {
        await db.update(blockedIps).set({ verified: true }).where(eq(blockedIps.id, block.id));
      }
    } else {
      missing++;
      missingList.push(`${block.ip} (${server.name})`);
    }
  }

  let response = `🔍 <b>Verificação de Blocks</b>\n\n✅ Verificados: ${verified}\n❌ Ausentes no firewall: ${missing}`;
  if (missingList.length > 0) {
    response += `\n\n⚠️ Blocks ausentes:\n${missingList.slice(0, 10).map(ip => `  • ${ip}`).join('\n')}`;
  }
  return response;
}

// ─── /services ─────────────────────────────────────────────────────────────

async function getServices(serverName?: string): Promise<string> {
  const servers = serverName
    ? [await ServerService.getByName(serverName)].filter(Boolean)
    : await ServerService.getEnabled();

  if (servers.length === 0) return serverName ? `❌ Servidor "${serverName}" não encontrado.` : '⚠️ Nenhum servidor registrado.';

  const sections: string[] = [];
  for (const server of servers) {
    if (!server) continue;
    const target = ServerService.toSSHTarget(server);

    const result = await SSHCollector.run(target,
      "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -25",
      10_000
    );

    if (!result.success) {
      sections.push(`━━ <b>${server.name}</b> — ❌ erro`);
      continue;
    }

    const services = result.stdout.trim().split('\n').filter(Boolean);
    const failedResult = await SSHCollector.run(target,
      'systemctl --failed --no-pager --no-legend 2>/dev/null | head -10',
      8_000
    );

    const failedLines = failedResult.success ? failedResult.stdout.trim().split('\n').filter(Boolean) : [];
    const failedCount = failedLines.length;

    const serviceList = services.slice(0, 20).map(s => `   🟢 ${s.replace('.service', '')}`).join('\n');
    const failedSection = failedCount > 0
      ? `\n   ⚠️ <b>${failedCount} failed:</b>\n` + failedLines.slice(0, 5).map(l => `   🔴 ${l.split(/\s+/)[0]?.replace('.service', '')}`).join('\n')
      : '';

    const more = services.length > 20 ? `\n   ... +${services.length - 20} mais` : '';
    sections.push(`━━ <b>${server.name}</b> (${services.length} running) ━━\n${serviceList}${more}${failedSection}`);
  }

  return `⚙️ <b>Services</b>\n\n${sections.join('\n\n')}`;
}

// ─── /ai ───────────────────────────────────────────────────────────────────

function getAIStatus(): string {
  const providers = AIProvider.getStatus();
  const lines = providers.map(p => {
    const icon = p.available ? '🟢' : '⚫';
    return `${icon} #${p.priority} <b>${p.name}</b> — ${p.model}${p.available ? '' : ' (não configurado)'}`;
  });

  const activeProvider = providers.find(p => p.available);
  const strategy = config.ai.provider === 'auto' ? 'Local-first (Ollama → Cloud)' : `Fixed: ${config.ai.provider}`;

  return [
    '🤖 <b>AI Providers</b>',
    '',
    `Estratégia: ${strategy}`,
    `Provider ativo: ${activeProvider?.name ?? 'nenhum'}`,
    '',
    ...lines,
    '',
    '<i>Ollama é sempre tentado primeiro. Se falhar ou timeout, usa cloud como fallback.</i>',
  ].join('\n');
}

// ─── /learn ────────────────────────────────────────────────────────────────

async function learnFromIncident(args: string[]): Promise<string> {
  if (args.length < 2) {
    return '❌ Uso: /learn &lt;incident_id&gt; &lt;resolved|false_positive|mitigated&gt; [resolução]\nEx: /learn 42 resolved "Bloqueei subnet inteira via /block"';
  }

  const [idStr, outcome, ...resolutionParts] = args;
  const incidentId = parseInt(idStr);
  if (isNaN(incidentId)) return '❌ ID do incidente inválido.';

  const validOutcomes = ['resolved', 'false_positive', 'mitigated'];
  if (!validOutcomes.includes(outcome)) {
    return `❌ Outcome inválido. Use: ${validOutcomes.join(', ')}`;
  }

  const resolution = resolutionParts.join(' ') || `Marcado como ${outcome} via Telegram`;

  await IncidentMemoryService.store(incidentId, resolution, outcome as 'resolved' | 'false_positive' | 'mitigated');
  return `🧠 Incidente #${incidentId} salvo na memória (${outcome}).\nA AI usará este caso como referência para incidentes similares.`;
}

// ─── /memory ───────────────────────────────────────────────────────────────

async function getMemoryStats(): Promise<string> {
  const stats = await IncidentMemoryService.getStats();

  if (stats.total === 0) return '🧠 Memória vazia. Use /learn para ensinar o Guardian sobre incidentes resolvidos.';

  const categories = Object.entries(stats.byCategory)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([cat, cnt]) => `   • ${cat}: ${cnt}`)
    .join('\n');

  return [
    '🧠 <b>Memória do Guardian (RAG)</b>',
    '',
    `📊 Total de casos: <b>${stats.total}</b>`,
    `⚠️ Taxa de falso positivo: ${stats.falsePositiveRate}%`,
    '',
    '📂 <b>Categorias:</b>',
    categories,
    '',
    '<i>A AI usa estes casos para dar recomendações baseadas em histórico.</i>',
    '💡 /learn &lt;id&gt; resolved|false_positive|mitigated [descrição]',
  ].join('\n');
}

// ─── /dashboard ────────────────────────────────────────────────────────────

function getDashboardUrl(): string {
  const token = rotateToken();
  const baseUrl = config.telegram.baseUrl;
  if (!baseUrl) return '❌ GUARDIAN_BASE_URL não configurado.';

  return [
    '🖥️ <b>Dashboard Guardian</b>',
    '',
    `<code>${baseUrl}/dashboard?token=${token}</code>`,
    '',
    '⏱ Token válido por <b>5 minutos</b>.',
    'Solicite novamente com /dashboard para gerar um novo.',
  ].join('\n');
}

// ─── /help ──────────────────────────────────────────────────────────────────

function formatHelp(): string {
  return [
    '🛡️ <b>Guardian Blue Team</b>',
    '',
    '📊 <b>Visão Geral:</b>',
    '  /status — Resumo de todos os servidores',
    '  /health — CPU, RAM, disco de cada servidor',
    '  /scores — Pontuação de segurança (6 dimensões)',
    '  /servers — Lista de servidores monitorados',
    '  /events — Últimos eventos de segurança',
    '',
    '🚨 <b>Incidentes e Ameaças:</b>',
    '  /incidents — Incidentes abertos (com ações)',
    '  /threat <code>1.2.3.4</code> — Investigar IP (reputação + recomendação)',
    '  /hunt <code>1.2.3.4</code> — Buscar IP ou usuário nos logs',
    '  /block <code>1.2.3.4</code> — Bloquear IP no firewall',
    '  /unblock <code>1.2.3.4</code> — Desbloquear IP',
    '',
    '🔍 <b>Investigação:</b>',
    '  /files — Arquivos modificados (FIM)',
    '  /sudo — Atividade sudo nas últimas 24h',
    '  /crons — Cron jobs (mudanças detectadas)',
    '  /keys — SSH keys (novas/removidas)',
    '  /dns — Consultas DNS suspeitas',
    '  /containers — Containers Docker',
    '  /vulns — Vulnerabilidades (CVE)',
    '',
    '🤖 <b>Inteligência:</b>',
    '  /ask <code>pergunta</code> — Pergunte qualquer coisa à AI',
    '  /report — Relatório diário de segurança',
    '  /learn <code>42 resolved "bloqueei"</code> — Ensinar o Guardian',
    '  /memory — Status da memória RAG',
    '',
    '⚙️ <b>Gestão:</b>',
    '  /add-server <code>nome host porta user</code>',
    '  /rm-server <code>nome</code>',
    '  /upgrade-server <code>id</code> — Migrar servidor para Tier 0 (guardian-shell)',
    '  /firewall — Status UFW',
    '  /ai — Status dos providers AI',
    '  /apis — Status das APIs externas',
  ].join('\n');
}

// ─── /apis ────────────────────────────────────────────────────────────────

function getApiStatus(): string {
  const status = ThreatIntelManager.getCircuitStatus();
  const icon = (s: string) => s === 'closed' ? '🟢' : s === 'open' ? '🔴' : '🟡';
  const label = (s: string) => s === 'closed' ? 'OK' : s === 'open' ? 'OPEN (bloqueado)' : 'half-open (testando)';

  return [
    '🔌 <b>Status das APIs Externas</b>',
    '',
    `${icon(status.abuseipdb)} AbuseIPDB: ${label(status.abuseipdb)}`,
    `${icon(status.virustotal)} VirusTotal: ${label(status.virustotal)}`,
    '',
    '<i>Circuit breaker abre após 3 falhas consecutivas. Recupera automaticamente em 5min.</i>',
  ].join('\n');
}

async function getFleetHealth(): Promise<string> {
  const servers = await ServerService.getEnabled();
  if (servers.length === 0) return '⚠️ Nenhum servidor. Use /add-server';

  const lines: string[] = [];

  for (const server of servers) {
    const [latestScore] = await db.select().from(serverScores)
      .where(eq(serverScores.serverId, server.id))
      .orderBy(desc(serverScores.periodStart))
      .limit(1);

    const [latestMetric] = await db.select().from(serverMetrics)
      .where(eq(serverMetrics.serverId, server.id))
      .orderBy(desc(serverMetrics.collectedAt))
      .limit(1);

    if (!latestMetric) {
      lines.push(`⚪ <b>${server.name}</b> — sem dados`);
      continue;
    }

    const score = latestScore?.overallScore;
    const icon = score === undefined ? '⚪' : score >= 80 ? '🟢' : score >= 60 ? '🟡' : score >= 40 ? '🟠' : '🔴';
    const scoreText = score !== undefined ? `Score: ${score}/100` : 'Score: pendente';
    const memPct = latestMetric.memTotalBytes ? Math.round(((latestMetric.memUsedBytes ?? 0) / latestMetric.memTotalBytes) * 100) : 0;
    const loadRatio = ((latestMetric.load1 ?? 0) / Math.max(latestMetric.cpuCount ?? 1, 1)).toFixed(1);
    const disks = (latestMetric.disks as any[]) ?? [];
    const maxDisk = Math.max(...disks.map(d => d.usedPercent ?? 0), 0);

    lines.push(
      `${icon} <b>${server.name}</b> — ${scoreText}` +
      `\n   Load: ${loadRatio} | Mem: ${memPct}% | Disk: ${maxDisk}%`
    );
  }

  return `🏥 <b>Fleet Health — ${servers.length} servidores</b>\n\n${lines.join('\n\n')}`;
}

// ─── /scores ──────────────────────────────────────────────────────────────

async function getServerScores(serverName?: string): Promise<string> {
  if (serverName) {
    const server = await ServerService.getByName(serverName);
    if (!server) return `❌ Servidor "${serverName}" não encontrado.`;

    const [score] = await db.select().from(serverScores)
      .where(eq(serverScores.serverId, server.id))
      .orderBy(desc(serverScores.periodStart))
      .limit(1);

    if (!score) return `⚠️ Nenhum score calculado para "${serverName}" ainda.`;

    const icon = (v: number) => v >= 80 ? '🟢' : v >= 60 ? '🟡' : v >= 40 ? '🟠' : '🔴';

    return [
      `📊 <b>Scores — ${server.name}</b>`,
      '',
      `${icon(score.overallScore)} Overall: <b>${score.overallScore}</b>/100`,
      `   🏥 Health: ${score.healthScore}`,
      `   🔒 Security: ${score.securityScore}`,
      `   ⚙️ Quality: ${score.qualityScore}`,
      `   💰 Waste: ${score.wasteScore}`,
      `   🛡️ Vulnerability: ${score.vulnerabilityScore}`,
      `   ⏱ Availability: ${score.availabilityScore}`,
      '',
      `📅 Período: ${new Date(score.periodStart).toLocaleString('pt-BR')}`,
    ].join('\n');
  }

  const servers = await ServerService.getEnabled();
  if (servers.length === 0) return '⚠️ Nenhum servidor. Use /add-server';

  const lines: string[] = [];
  for (const server of servers) {
    const [score] = await db.select().from(serverScores)
      .where(eq(serverScores.serverId, server.id))
      .orderBy(desc(serverScores.periodStart))
      .limit(1);

    if (!score) {
      lines.push(`⚪ ${server.name}: sem dados`);
      continue;
    }

    const icon = score.overallScore >= 80 ? '🟢' : score.overallScore >= 60 ? '🟡' : score.overallScore >= 40 ? '🟠' : '🔴';
    lines.push(`${icon} <b>${server.name}</b>: ${score.overallScore} | H:${score.healthScore} S:${score.securityScore} Q:${score.qualityScore} W:${score.wasteScore} V:${score.vulnerabilityScore} A:${score.availabilityScore}`);
  }

  return `📊 <b>Scores — ${servers.length} servidores</b>\n\n${lines.join('\n')}`;
}

// ─── /files ────────────────────────────────────────────────────────────────

async function getFileChanges(serverName?: string): Promise<string> {
  const whereClause = serverName
    ? and(
        inArray(securityEvents.eventType, ['file_modified', 'file_created', 'file_deleted', 'file_permissions_changed', 'critical_file_tampering']),
        eq(securityEvents.serverId, (await ServerService.getByName(serverName))?.id ?? -1)
      )
    : inArray(securityEvents.eventType, ['file_modified', 'file_created', 'file_deleted', 'file_permissions_changed', 'critical_file_tampering']);

  const events = await db.select()
    .from(securityEvents)
    .where(whereClause)
    .orderBy(desc(securityEvents.timestamp))
    .limit(20);

  if (events.length === 0) return '✅ Nenhuma mudança de arquivo detectada.';

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

  const lines = events.map(e => {
    const icon = severityIcon[e.severity] ?? '⚪';
    const time = e.timestamp.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    const server = serverNames.get(e.serverId!) ?? '?';
    const meta = e.metadata as Record<string, any> | null;
    const path = meta?.filePath ?? '';
    return `${icon} ${time} <b>${e.eventType}</b>\n   📁 ${path} [${server}]`;
  });

  const title = serverName ? `📁 <b>File Changes — ${serverName}</b>` : '📁 <b>File Changes</b>';
  return `${title}\n\n${lines.join('\n\n')}`;
}

// ─── /sudo ─────────────────────────────────────────────────────────────────

async function getSudoActivity(hoursStr?: string): Promise<string> {
  const hours = Math.min(parseInt(hoursStr || '24') || 24, 720);
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  const events = await db.select()
    .from(securityEvents)
    .where(and(
      inArray(securityEvents.eventType, ['sudo_command', 'sudo_failed', 'sudo_suspicious']),
      gte(securityEvents.timestamp, since)
    ))
    .orderBy(desc(securityEvents.timestamp))
    .limit(25);

  if (events.length === 0) return `✅ Nenhuma atividade sudo nas últimas ${hours}h.`;

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

  const lines = events.map(e => {
    const icon = severityIcon[e.severity] ?? '⚪';
    const time = e.timestamp.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    const server = serverNames.get(e.serverId!) ?? '?';
    const meta = e.metadata as Record<string, any> | null;
    const cmd = meta?.command ? ` <code>${(meta.command as string).slice(0, 50)}</code>` : '';
    const user = e.userName ? ` (${e.userName})` : '';
    return `${icon} ${time}${user}${cmd} [${server}]`;
  });

  return `🔐 <b>Sudo — últimas ${hours}h</b> (${events.length})\n\n${lines.join('\n')}`;
}

// ─── /crons ────────────────────────────────────────────────────────────────

async function getCronJobs(serverName?: string): Promise<string> {
  if (serverName) {
    const server = await ServerService.getByName(serverName);
    if (!server) return `❌ Servidor "${serverName}" não encontrado.`;
    const target = ServerService.toSSHTarget(server);
    const crons = await CronCollector.collect(target);
    if (crons.length === 0) return `✅ Nenhum cron encontrado em ${serverName}.`;

    const lines = crons.slice(0, 20).map(c =>
      `👤 ${c.user} | <code>${c.schedule}</code>\n   ${c.command.slice(0, 80)}`
    );
    const more = crons.length > 20 ? `\n... +${crons.length - 20} mais` : '';
    return `⏰ <b>Crons — ${serverName}</b> (${crons.length})\n\n${lines.join('\n\n')}${more}`;
  }

  const recentChanges = await db.select()
    .from(securityEvents)
    .where(inArray(securityEvents.eventType, ['cron_added', 'cron_removed', 'cron_persistence']))
    .orderBy(desc(securityEvents.timestamp))
    .limit(15);

  if (recentChanges.length === 0) return '✅ Nenhuma mudança de cron detectada.\nUse /crons <server> para listar crons atuais.';

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

  const lines = recentChanges.map(e => {
    const icon = severityIcon[e.severity] ?? '⚪';
    const time = e.timestamp.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    const server = serverNames.get(e.serverId!) ?? '?';
    return `${icon} ${time} <b>${e.eventType}</b> [${server}]`;
  });

  return `⏰ <b>Cron Changes</b>\n\n${lines.join('\n')}\n\n💡 /crons <server> para listar crons atuais`;
}

// ─── /keys ─────────────────────────────────────────────────────────────────

async function getSSHKeys(serverName?: string): Promise<string> {
  if (serverName) {
    const server = await ServerService.getByName(serverName);
    if (!server) return `❌ Servidor "${serverName}" não encontrado.`;
    const target = ServerService.toSSHTarget(server);
    const keys = await SSHKeysCollector.collect(target);
    if (keys.length === 0) return `✅ Nenhuma SSH key encontrada em ${serverName}.`;

    const lines = keys.map(k =>
      `👤 ${k.user} | ${k.keyType}\n   🔑 <code>${k.fingerprint.slice(0, 30)}</code> ${k.comment}`
    );
    return `🔑 <b>SSH Keys — ${serverName}</b> (${keys.length})\n\n${lines.join('\n\n')}`;
  }

  const recentChanges = await db.select()
    .from(securityEvents)
    .where(inArray(securityEvents.eventType, ['ssh_key_added', 'ssh_key_removed', 'unauthorized_ssh_key']))
    .orderBy(desc(securityEvents.timestamp))
    .limit(15);

  if (recentChanges.length === 0) return '✅ Nenhuma mudança de SSH key detectada.\nUse /keys <server> para listar keys atuais.';

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

  const lines = recentChanges.map(e => {
    const icon = severityIcon[e.severity] ?? '⚪';
    const time = e.timestamp.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    const server = serverNames.get(e.serverId!) ?? '?';
    const meta = e.metadata as Record<string, any> | null;
    const fp = meta?.fingerprint ? ` <code>${(meta.fingerprint as string).slice(0, 20)}</code>` : '';
    return `${icon} ${time} <b>${e.eventType}</b>${fp} [${server}]`;
  });

  return `🔑 <b>SSH Key Changes</b>\n\n${lines.join('\n')}\n\n💡 /keys <server> para listar keys atuais`;
}

// ─── /dns ──────────────────────────────────────────────────────────────────

async function getDNSActivity(serverName?: string, hoursStr?: string): Promise<string> {
  // If first arg is a number, treat it as hours (not server name)
  const firstArgIsHours = serverName && !isNaN(parseInt(serverName)) && !hoursStr;
  const actualServerName = firstArgIsHours ? undefined : serverName;
  const hours = Math.min(parseInt((firstArgIsHours ? serverName : hoursStr) || '24') || 24, 720);
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  const serverFilter = actualServerName
    ? eq(securityEvents.serverId, (await ServerService.getByName(actualServerName))?.id ?? -1)
    : undefined;

  const whereClause = serverFilter
    ? and(
        inArray(securityEvents.eventType, ['dns_query', 'dns_dga', 'dns_suspicious_tld']),
        gte(securityEvents.timestamp, since),
        serverFilter
      )
    : and(
        inArray(securityEvents.eventType, ['dns_query', 'dns_dga', 'dns_suspicious_tld']),
        gte(securityEvents.timestamp, since)
      );

  const events = await db.select()
    .from(securityEvents)
    .where(whereClause)
    .orderBy(desc(securityEvents.timestamp))
    .limit(25);

  const anomalies = events.filter(e => e.eventType === 'dns_dga' || e.eventType === 'dns_suspicious_tld');

  if (events.length === 0) return `✅ Nenhuma atividade DNS suspeita nas últimas ${hours}h.`;

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

  const lines = anomalies.length > 0
    ? anomalies.slice(0, 20).map(e => {
        const icon = severityIcon[e.severity] ?? '⚪';
        const time = e.timestamp.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
        const server = serverNames.get(e.serverId!) ?? '?';
        const meta = e.metadata as Record<string, any> | null;
        const domain = meta?.domain ? ` <code>${(meta.domain as string).slice(0, 50)}</code>` : '';
        return `${icon} ${time} <b>${e.eventType}</b>${domain} [${server}]`;
      })
    : [`ℹ️ ${events.length} queries DNS — nenhuma anomalia detectada`];

  const title = actualServerName
    ? `🌐 <b>DNS — ${actualServerName} (${hours}h)</b>`
    : `🌐 <b>DNS — últimas ${hours}h</b>`;

  return `${title}\n\n${lines.join('\n')}\n\n📊 ${events.length} queries | ⚠️ ${anomalies.length} anomalias`;
}

// ─── /hunts ─────────────────────────────────────────────────────────────────

async function getThreatHuntResults(): Promise<string> {
  const findings = await db.select()
    .from(threatHuntFindings)
    .orderBy(desc(threatHuntFindings.runAt))
    .limit(20);

  if (findings.length === 0) {
    return '🔍 <b>Threat Hunting</b>\n\nNenhum resultado ainda. O worker executa a cada 4h (primeiro ciclo em 5min após o boot).\n\nQuando houver achados de alta/crítica severidade, você receberá uma notificação automática.';
  }

  const sevIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };

  // Group by run (same minute)
  const runs = new Map<string, typeof findings>();
  for (const f of findings) {
    const key = new Date(f.runAt).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
    if (!runs.has(key)) runs.set(key, []);
    runs.get(key)!.push(f);
  }

  const lines: string[] = [];
  let runIdx = 0;
  for (const [runTime, runFindings] of runs) {
    if (runIdx >= 5) break;
    const eventsCount = runFindings[0].eventsAnalyzed;
    const provider = runFindings[0].aiProvider ?? 'ai';
    lines.push(`\n📅 <b>${runTime}</b> <i>(${eventsCount} eventos, ${provider})</i>`);
    for (const f of runFindings) {
      const icon = sevIcon[f.severity ?? 'medium'] ?? '🔵';
      const text = (f.finding ?? '').split('\n')[0];
      const rec = (f.finding ?? '').split('\n').find((l: string) => l.startsWith('Recommendation:'))?.replace('Recommendation:', '').trim();
      lines.push(`${icon} ${text}`);
      if (rec) lines.push(`   ↳ <i>${rec}</i>`);
    }
    runIdx++;
  }

  const totalRuns = runs.size;
  return `🔍 <b>Threat Hunting — Últimos ${totalRuns} ciclos</b>${lines.join('\n')}`;
}

// ─── /rate-limits ───────────────────────────────────────────────────────────

async function getRateLimits(): Promise<string> {
  const limits = await db.select()
    .from(rateLimitedIps)
    .where(eq(rateLimitedIps.active, true))
    .orderBy(desc(rateLimitedIps.appliedAt))
    .limit(20);

  if (limits.length === 0) {
    return '✅ <b>Rate Limits</b>\n\nNenhum IP em rate-limit ativo no momento.';
  }

  const serverNames = await getServerNameMap();

  const lines = limits.map(r => {
    const server = serverNames.get(r.serverId) ?? `Server #${r.serverId}`;
    const since = timeAgo(r.appliedAt);
    const escalated = r.escalatedAt ? ` ⚠️ escalado ${timeAgo(r.escalatedAt)}` : '';
    return `🟡 <code>${r.ip}</code> [${server}]\n   ${r.limitPerSec}req/s burst ${r.burst} — há ${since}${escalated}\n   ${r.reason ?? ''}`;
  });

  return `🚦 <b>Rate Limits Ativos (${limits.length})</b>\n\n${lines.join('\n\n')}\n\n<i>IPs em rate-limit são verificados a cada 2min — se o ataque continuar, são bloqueados permanentemente.</i>`;
}

// ─── /playbook-log ──────────────────────────────────────────────────────────

async function getPlaybookLog(): Promise<string> {
  const executions = await db.select()
    .from(playbookExecutions)
    .orderBy(desc(playbookExecutions.startedAt))
    .limit(15);

  if (executions.length === 0) {
    return '📋 <b>Playbook Log</b>\n\nNenhuma execução registrada ainda.';
  }

  const statusIcon: Record<string, string> = { completed: '✅', failed: '❌', running: '⚙️', partial: '⚠️' };

  const lines = executions.map(e => {
    const icon = statusIcon[e.status] ?? '⚙️';
    const steps = (e.stepsCompleted as string[] | null) ?? [];
    const failed = (e.stepsFailed as string[] | null) ?? [];
    const duration = e.completedAt
      ? `${Math.round((new Date(e.completedAt).getTime() - new Date(e.startedAt).getTime()) / 1000)}s`
      : 'em andamento';
    const stepsInfo = steps.length > 0 ? ` ${steps.length} passos` : '';
    const failInfo = failed.length > 0 ? ` ❌${failed.length} falhos` : '';
    const time = timeAgo(e.startedAt);
    return `${icon} <b>${e.playbookName}</b> — ${e.status} (${duration})\n   Server #${e.serverId ?? '?'} · ${e.triggerType ?? '?'} · ${time}${stepsInfo}${failInfo}`;
  });

  return `📋 <b>Playbook Log (${executions.length})</b>\n\n${lines.join('\n\n')}`;
}

// ─── /versions ──────────────────────────────────────────────────────────────

async function getRuntimeVersions(serverArg?: string): Promise<string> {
  const servers = await ServerService.getEnabled();
  if (servers.length === 0) return '⚠️ Nenhum servidor configurado.';

  const targets = serverArg
    ? servers.filter(s => s.name.toLowerCase().includes(serverArg.toLowerCase()) || String(s.id) === serverArg)
    : servers;

  if (targets.length === 0) return `⚠️ Servidor "${serverArg}" não encontrado.`;

  const lines: string[] = ['🔧 <b>Runtime Versions</b>\n'];
  let hasIssues = false;

  for (const server of targets) {
    const target = ServerService.toSSHTarget(server);
    const runtimes = await RuntimeVersionScanner.scan(target);

    lines.push(`<b>${server.name}</b>:`);
    if (runtimes.length === 0) {
      lines.push('  Nenhum runtime detectado');
      continue;
    }

    for (const rt of runtimes) {
      const icon = rt.isEol ? '🔴' : rt.isNearEol ? '🟡' : '✅';
      const eolNote = rt.isEol ? ` (EOL ${rt.eolDate})` : rt.isNearEol ? ` (EOL em ${rt.eolDate})` : '';
      lines.push(`  ${icon} ${rt.name} <code>${rt.version}</code>${eolNote}`);
      if (rt.isEol || rt.isNearEol) hasIssues = true;
    }
    lines.push('');
  }

  if (hasIssues) {
    lines.push('⚠️ Use /vulns para ver as vulnerabilidades registradas.');
  }

  return lines.join('\n');
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function severityOrder(s: string): number {
  const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return order[s] ?? 4;
}

function timeAgo(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return 'agora';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}min`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

async function getServerNameMap(): Promise<Map<number, string>> {
  const servers = await db.select({ id: socServers.id, name: socServers.name }).from(socServers);
  return new Map(servers.map(s => [s.id, s.name]));
}
