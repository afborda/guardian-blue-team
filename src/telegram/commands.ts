import { logger } from '../utils/logger.js';
import { DailyReportWorker } from '../workers/daily-report.worker.js';
import { ServerService } from '../services/server.service.js';
import { SSHCollector } from '../collectors/ssh-collector.js';
import { CronCollector } from '../collectors/cron-collector.js';
import { SSHKeysCollector } from '../collectors/ssh-keys-collector.js';
import { db } from '../database/connection.js';
import { securityEvents, socIncidents, socServers, serverScores, serverMetrics } from '../database/schema.js';
import { desc, eq, ne, count, and, gte, inArray } from 'drizzle-orm';
import { ThreatIntelManager } from '../threat-intel/manager.js';
import { PlaybookRegistry } from '../playbooks/registry.js';
import { PlaybookEngine, type PlaybookContext } from '../playbooks/engine.js';
import { VulnScanner } from '../vuln-scanner/scanner.js';
import { SOCAnalystService } from '../services/soc-analyst.service.js';
import { isValidHostname, isValidIp, isValidSshUser, isValidKeyPath, isValidServerName } from '../utils/sanitize.js';

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
      return await getOpenIncidents();
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
    case '/rm-server':
      return await removeServer(parts[1]);
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

async function getOpenIncidents(): Promise<string> {
  const incidents = await db.select()
    .from(socIncidents)
    .where(eq(socIncidents.status, 'open'))
    .orderBy(desc(socIncidents.lastSeenAt))
    .limit(10);

  if (incidents.length === 0) return '✅ Nenhum incidente aberto.';

  const serverNames = await getServerNameMap();
  const severityIcon: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };

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

async function threatLookup(ip: string | undefined): Promise<string> {
  if (!ip) return '❌ Uso: /threat &lt;ip&gt;\nEx: /threat 8.8.8.8';
  if (!/^[\d.:a-fA-F]+$/.test(ip)) return '❌ IP inválido.';

  const lines: string[] = [`🔍 <b>Threat: ${ip}</b>`, ''];

  const report = await ThreatIntelManager.lookupIP(ip);
  if (report) {
    const scoreBar = report.score >= 80 ? '🔴' : report.score >= 50 ? '🟠' : report.score >= 25 ? '🟡' : '🟢';
    lines.push(
      `${scoreBar} AbuseIPDB Score: <b>${report.score}/100</b>`,
      `📊 Reports: ${report.totalReports} | 🌍 ${report.country} | 🏢 ${report.isp}`,
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
    lines.push('📋 <b>Nos nossos logs:</b>');
    for (const row of eventsByServer) {
      const name = serverNames.get(row.serverId!) ?? '?';
      lines.push(`   • ${row.cnt} ${row.eventType} em ${name}`);
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
    lines.push('📋 Nenhum evento encontrado nos nossos logs.');
  }

  lines.push('', `💡 /hunt ${ip} — histórico detalhado`);

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
  if (!SOCAnalystService.isAvailable()) return '⚠️ AI não configurada (GEMINI_API_KEY ausente).';

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
  const status = reachable ? '🟢 conectado' : '🔴 não acessível';

  return `✅ <b>${name}</b> adicionado\n${server.sshUser}@${host}:${sshPort} | ${status}`;
}

async function removeServer(name: string | undefined): Promise<string> {
  if (!name) return '❌ Uso: /rm-server nome';
  const removed = await ServerService.remove(name);
  if (!removed) return `❌ Servidor "${name}" não encontrado.`;
  return `✅ Servidor "${name}" removido.`;
}

// ─── /help ──────────────────────────────────────────────────────────────────

function formatHelp(): string {
  return [
    '🤖 <b>Guardian SOC</b>',
    '',
    '📊 <b>Monitoramento:</b>',
    '  /status — Overview dos servidores',
    '  /health — Métricas de saúde (CPU, RAM, disco)',
    '  /scores — Scores de qualidade (6 dimensões)',
    '  /scores server — Detalhes de um servidor',
    '  /servers — Lista + health check',
    '  /containers — Containers rodando',
    '  /events — Eventos (low+)',
    '  /events high — Filtrar por severidade',
    '',
    '🚨 <b>Incidentes:</b>',
    '  /incidents — Incidentes abertos',
    '  /threat ip — Investigar IP',
    '  /hunt ip|user — Buscar nos logs',
    '',
    '🛡️ <b>Blue Team:</b>',
    '  /files [server] — Mudanças em arquivos',
    '  /sudo [hours] — Atividade sudo (default 24h)',
    '  /crons [server] — Cron jobs / mudanças',
    '  /keys [server] — SSH keys / mudanças',
    '  /dns [server] [hours] — DNS / anomalias',
    '',
    '⚡ <b>Ações:</b>',
    '  /playbook list — Playbooks disponíveis',
    '  /playbook run name server [ip]',
    '  /scan — Forçar análise de abuso',
    '  /report — Relatório do dia',
    '  /report full — Relatório acumulado',
    '',
    '⚙️ <b>Gestão:</b>',
    '  /add-server nome host [porta] [user] [key]',
    '  /rm-server nome',
    '  /vulns — Vulnerabilidades',
    '  /ask pergunta — AI analyst',
  ].join('\n');
}

// ─── /health ───────────────────────────────────────────────────────────────

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
  const hours = parseInt(hoursStr || '24') || 24;
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
    .where(inArray(securityEvents.eventType, ['cron_added', 'cron_removed', 'cron_modified', 'cron_persistence']))
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
  const hours = parseInt(hoursStr || serverName || '24') || 24;
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);

  const serverFilter = serverName && isNaN(parseInt(serverName))
    ? eq(securityEvents.serverId, (await ServerService.getByName(serverName))?.id ?? -1)
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

  const title = serverName && isNaN(parseInt(serverName))
    ? `🌐 <b>DNS — ${serverName} (${hours}h)</b>`
    : `🌐 <b>DNS — últimas ${hours}h</b>`;

  return `${title}\n\n${lines.join('\n')}\n\n📊 ${events.length} queries | ⚠️ ${anomalies.length} anomalias`;
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
