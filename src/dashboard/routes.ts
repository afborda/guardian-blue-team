import { Router } from 'express';
import { db, dbFalse, dbNow } from '../database/connection.js';
import { socServers, securityEvents, socIncidents, blockedIps, cveAlerts, serverMetrics, serverScores, behaviorProfiles, containerSnapshots, threatHuntFindings, rateLimitedIps, playbookExecutions, cveEpss, cveKev, vulnerabilities } from '../database/schema.js';
import { IntelligenceWorker } from '../workers/intelligence.worker.js';
import { ScoreCalculatorWorker } from '../workers/score-calculator.worker.js';
import { CVEMonitorWorker } from '../workers/cve-monitor.worker.js';
import { CVEIntelFeedsWorker } from '../workers/cve-intel-feeds.worker.js';
import { requireRole } from './auth.js';
import { eq, count, desc, and, gte, ne, sql, inArray } from 'drizzle-orm';
import { config } from '../config/environment.js';
import { layout } from './views/layout.js';
import { overviewPage } from './views/overview.js';
import { logger } from '../utils/logger.js';
import { escapeHtml } from '../utils/sanitize.js';
import { ThreatIntelManager } from '../threat-intel/manager.js';
import { PlaybookRegistry } from '../playbooks/registry.js';
import { PlaybookEngine, type PlaybookContext } from '../playbooks/engine.js';
import { IncidentMemoryService } from '../services/incident-memory.service.js';
import { FalsePositiveFilter } from '../intelligence/false-positive-filter.js';
import { CONSTANTS } from '../config/constants.js';
import { ServerService } from '../services/server.service.js';
import { killContainerProcess, restartContainer, disconnectContainer, pullContainerImage, recreateContainer } from '../playbooks/actions/container-actions.js';

const TRUSTED_IPS_SET = new Set(CONSTANTS.trustedIps);

function ipTag(ip: string): string {
  if (TRUSTED_IPS_SET.has(ip) || ip.startsWith('10.') || ip.startsWith('172.') || ip.startsWith('192.168.')) {
    return `<span class="ip-tag-safe">${escapeHtml(ip)}</span>`;
  }
  return `<span class="ip-tag">${escapeHtml(ip)}</span>`;
}

export const dashboardPages = Router();
export const dashboardApi = Router();

// ─── HTML Pages ──────────────────────────────────────────────────────────────

dashboardPages.get('/', async (_req, res) => {
  try {
    const [serversCount] = await db.select({ cnt: count() }).from(socServers);
    const [openCount] = await db.select({ cnt: count() }).from(socIncidents).where(eq(socIncidents.status, 'open'));
    const [blockedCount] = await db.select({ cnt: count() }).from(blockedIps);
    const [cveCount] = await db.select({ cnt: count() }).from(cveAlerts).where(eq(cveAlerts.status, 'pending'));
    const [eventsCount] = await db.select({ cnt: count() }).from(securityEvents)
      .where(and(
        gte(securityEvents.timestamp, new Date(Date.now() - 24 * 60 * 60 * 1000)),
        ne(securityEvents.severity, 'info')
      ));

    const allScores = await db.select({ overall: serverScores.overallScore }).from(serverScores)
      .orderBy(desc(serverScores.periodStart))
      .limit(10);

    const overallScore = allScores.length > 0
      ? Math.round(allScores.reduce((sum, s) => sum + s.overall, 0) / allScores.length)
      : 0;

    const serverList = await db.select({ name: socServers.name, lastSeen: socServers.lastSeenAt, id: socServers.id })
      .from(socServers)
      .where(eq(socServers.enabled, true));

    const content = overviewPage({
      servers: serversCount.cnt,
      openIncidents: openCount.cnt,
      blockedIps: blockedCount.cnt,
      pendingCves: cveCount.cnt,
      eventsToday: eventsCount.cnt,
      overallScore,
      serverList: serverList.map(s => ({ name: s.name, lastSeen: s.lastSeen, id: s.id })),
    });

    res.send(layout('Overview', content));
  } catch (err) {
    logger.error({ err }, 'Dashboard overview error');
    res.status(500).send(layout('Error', '<p class="severity-critical">Failed to load dashboard</p>'));
  }
});

dashboardPages.get('/incidents', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Incidents</h2>
    <div hx-get="/api/dashboard/incidents?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Incidents', content));
});

dashboardPages.get('/servers', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Servers</h2>
    <div hx-get="/api/dashboard/servers?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Servers', content));
});

dashboardPages.get('/cve', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>CVE Alerts</h2>

    <div class="kpi-grid" style="margin-bottom:1.5rem"
         id="cve-kpis"
         hx-get="/api/dashboard/cve-kpis?token=${token}"
         hx-trigger="load"
         hx-swap="innerHTML">
      <p aria-busy="true">Loading…</p>
    </div>

    <div style="display:flex;gap:0.5rem;margin-bottom:1rem;flex-wrap:wrap;">
      <button hx-get="/api/dashboard/cve-alerts?token=${token}&status=pending" hx-target="#cve-list" hx-swap="innerHTML">Pending</button>
      <button hx-get="/api/dashboard/cve-alerts?token=${token}&status=all" hx-target="#cve-list" hx-swap="innerHTML">All</button>
      <button hx-get="/api/dashboard/cve-alerts?token=${token}&category=runtime" hx-target="#cve-list" hx-swap="innerHTML">Runtime EOL</button>
      <button hx-get="/api/dashboard/cve-alerts?token=${token}&kev=1" hx-target="#cve-list" hx-swap="innerHTML" style="border-color:var(--critical);color:var(--critical)">KEV Only</button>
    </div>

    <div id="cve-list" hx-get="/api/dashboard/cve-alerts?token=${token}&status=pending" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('CVE Alerts', content));
});

dashboardPages.get('/blocks', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Active IP Blocks</h2>
    <div id="blocks-list" hx-get="/api/dashboard/blocks?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Blocks', content));
});

dashboardPages.get('/logs', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Security Events</h2>
    <div style="display:flex; gap:0.75rem; flex-wrap:wrap; margin-bottom:1.25rem;">
      <select id="sev-filter" style="background:var(--bg-card);color:var(--text);border:1px solid var(--border);padding:0.4rem 0.75rem;border-radius:var(--radius-sm);font-size:0.8rem;">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <input id="type-filter" type="text" placeholder="Event type..." style="background:var(--bg-card);color:var(--text);border:1px solid var(--border);padding:0.4rem 0.75rem;border-radius:var(--radius-sm);font-size:0.8rem;width:160px;" />
      <input id="ip-filter" type="text" placeholder="Source IP..." style="background:var(--bg-card);color:var(--text);border:1px solid var(--border);padding:0.4rem 0.75rem;border-radius:var(--radius-sm);font-size:0.8rem;width:140px;" />
      <button hx-get="/api/dashboard/events?token=${token}" hx-include="#sev-filter,#type-filter,#ip-filter" hx-target="#events-table" hx-swap="innerHTML" style="font-size:0.8rem;">Filter</button>
    </div>
    <div id="events-table" hx-get="/api/dashboard/events?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Logs', content));
});

dashboardPages.get('/health', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Fleet Health</h2>
    <div hx-get="/api/dashboard/fleet-health?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading fleet status...</p>
    </div>
  `;
  res.send(layout('Fleet Health', content));
});

dashboardPages.get('/health/:id', (req, res) => {
  const token = config.dashboard.token || '';
  const id = req.params.id;
  const content = `
    <h2>Server Detail</h2>
    <div hx-get="/api/dashboard/server/${id}/metrics?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading metrics...</p>
    </div>
    <h3>Score History</h3>
    <div hx-get="/api/dashboard/server/${id}/scores?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading scores...</p>
    </div>
  `;
  res.send(layout('Server Detail', content));
});

dashboardPages.get('/scores', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Server Scores</h2>
    <div hx-get="/api/dashboard/scores?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading scores...</p>
    </div>
  `;
  res.send(layout('Scores', content));
});

dashboardPages.get('/timeline', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Event Timeline</h2>
    <div hx-get="/api/dashboard/timeline?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading timeline...</p>
    </div>
  `;
  res.send(layout('Timeline', content));
});

dashboardPages.get('/map', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Attack Origin Map</h2>
    <p class="text-muted" style="color: var(--text-muted); margin-bottom: 1rem;">
      Geographic distribution of attack sources (last 7 days)
    </p>
    <div hx-get="/api/dashboard/geo-attacks?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading map data...</p>
    </div>
  `;
  res.send(layout('Attack Map', content));
});

dashboardPages.get('/apis', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>API & System Status</h2>
    <div hx-get="/api/dashboard/system-status?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading status...</p>
    </div>
  `;
  res.send(layout('API Status', content));
});

dashboardPages.get('/intelligence', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;">
      <div>
        <h2 style="margin-bottom:0.25rem;">Intelligence & Learning</h2>
        <p style="color:var(--text-muted);font-size:0.82rem;">
          How Guardian learns, when it updates, and what data feeds each system.
        </p>
      </div>
      <button hx-post="/api/dashboard/run-workers?token=${token}" hx-swap="outerHTML" hx-indicator="#run-spinner"
        style="display:inline-flex;align-items:center;gap:0.5rem;">
        <span id="run-spinner" class="htmx-indicator" style="display:none;">&#9881;</span>
        &#9654; Recalcular Agora
      </button>
    </div>
    <div id="intel-content" hx-get="/api/dashboard/intelligence?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading intelligence status...</p>
    </div>
  `;
  res.send(layout('Intelligence', content));
});

dashboardPages.get('/approvals', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <h2>Pending Approvals</h2>
    <p style="color:var(--text-muted);font-size:0.82rem;margin-bottom:1rem;">Playbooks requiring manual approval before execution.</p>
    <div id="approvals-list" hx-get="/api/dashboard/pending-approvals?token=${token}" hx-trigger="load, every 10s" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
    <h2 style="margin-top:2rem;">Recent Incidents (Feedback)</h2>
    <p style="color:var(--text-muted);font-size:0.82rem;margin-bottom:1rem;">Mark incidents as false positives to improve detection accuracy.</p>
    <div id="feedback-list" hx-get="/api/dashboard/incidents-feedback?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
    <h2 style="margin-top:2rem;">Playbook Execution History</h2>
    <p style="color:var(--text-muted);font-size:0.82rem;margin-bottom:1rem;">All playbooks executed (manual and automated), last 50.</p>
    <div hx-get="/api/dashboard/playbook-history?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Approvals', content));
});

dashboardPages.get('/hunting', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;">
      <div>
        <h2 style="margin-bottom:0.25rem;">Threat Hunting</h2>
        <p style="color:var(--text-muted);font-size:0.82rem;">
          Resultados da análise proativa de padrões executada pela IA a cada 4 horas.
        </p>
      </div>
    </div>
    <div hx-get="/api/dashboard/hunting?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading threat hunt results...</p>
    </div>
  `;
  res.send(layout('Threat Hunting', content));
});

dashboardPages.get('/containers', (_req, res) => {
  const token = config.dashboard.token || '';
  const content = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1.5rem;">
      <div>
        <h2 style="margin-bottom:0.25rem;">Container Security</h2>
        <p style="color:var(--text-muted);font-size:0.82rem;">
          Runtime monitoring: processes, network, filesystem, CVEs, and hardening status across all servers.
        </p>
      </div>
    </div>
    <div hx-get="/api/dashboard/containers?token=${token}" hx-trigger="load, every 60s" hx-swap="innerHTML">
      <p aria-busy="true">Loading container security data...</p>
    </div>
  `;
  res.send(layout('Containers', content));
});

// ─── API Routes (HTML fragments for HTMX) ─────────────────────────────────

dashboardApi.get('/stats', async (_req, res) => {
  try {
    const [servers] = await db.select({ cnt: count() }).from(socServers);
    const [incidents] = await db.select({ cnt: count() }).from(socIncidents).where(eq(socIncidents.status, 'open'));
    const [blocks] = await db.select({ cnt: count() }).from(blockedIps);
    const [cves] = await db.select({ cnt: count() }).from(cveAlerts).where(eq(cveAlerts.status, 'pending'));
    const [events] = await db.select({ cnt: count() }).from(securityEvents);

    res.json({ servers: servers.cnt, openIncidents: incidents.cnt, blockedIps: blocks.cnt, pendingCves: cves.cnt, eventsToday: events.cnt });
  } catch (err) {
    logger.error({ err }, 'Dashboard stats API error');
    res.status(500).json({ error: 'internal' });
  }
});

dashboardApi.get('/server-fleet', async (_req, res) => {
  try {
    const servers = await db.select().from(socServers).where(eq(socServers.enabled, true));

    if (servers.length === 0) {
      res.send('<p style="color:var(--text-dim)">No servers configured.</p>');
      return;
    }

    // Latest metrics per server (network I/O + CPU/RAM)
    const latestMetrics = new Map<number, typeof serverMetrics.$inferSelect>();
    for (const srv of servers) {
      const [m] = await db.select().from(serverMetrics)
        .where(eq(serverMetrics.serverId, srv.id))
        .orderBy(desc(serverMetrics.collectedAt))
        .limit(1);
      if (m) latestMetrics.set(srv.id, m);
    }

    // 24h auth events per server: success vs failed
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const authEvents = await db.select({
      serverId: securityEvents.serverId,
      eventType: securityEvents.eventType,
      cnt: count(),
    })
      .from(securityEvents)
      .where(and(
        gte(securityEvents.timestamp, since24h),
        inArray(securityEvents.eventType, ['ssh_login_success', 'ssh_key_login', 'ssh_login_fail', 'ssh_brute_force']),
      ))
      .groupBy(securityEvents.serverId, securityEvents.eventType);

    const authMap = new Map<number, { secure: number; failed: number; brute: number }>();
    for (const row of authEvents) {
      const existing = authMap.get(row.serverId) ?? { secure: 0, failed: 0, brute: 0 };
      if (row.eventType === 'ssh_login_success' || row.eventType === 'ssh_key_login') {
        existing.secure += row.cnt;
      } else if (row.eventType === 'ssh_login_fail') {
        existing.failed += row.cnt;
      } else if (row.eventType === 'ssh_brute_force') {
        existing.brute += row.cnt;
      }
      authMap.set(row.serverId, existing);
    }

    const rows = servers.map(srv => {
      const metrics = latestMetrics.get(srv.id);
      const auth = authMap.get(srv.id) ?? { secure: 0, failed: 0, brute: 0 };
      const isOnline = srv.lastSeenAt && (Date.now() - new Date(srv.lastSeenAt).getTime() < 10 * 60 * 1000);
      const statusDot = isOnline
        ? '<span style="color:var(--success)">&#9679;</span>'
        : '<span style="color:var(--critical)">&#9679;</span>';
      const statusLabel = isOnline ? 'Online' : 'Offline';

      // Network I/O totals from latest metrics
      let rxDisplay = '—';
      let txDisplay = '—';
      if (metrics?.networkIo && Array.isArray(metrics.networkIo)) {
        const totalRx = (metrics.networkIo as Array<{ rxBps: number }>).reduce((s, i) => s + (i.rxBps ?? 0), 0);
        const totalTx = (metrics.networkIo as Array<{ txBps: number }>).reduce((s, i) => s + (i.txBps ?? 0), 0);
        rxDisplay = totalRx > 1_000_000 ? `${(totalRx / 1_000_000).toFixed(1)} MB/s` : `${(totalRx / 1000).toFixed(0)} KB/s`;
        txDisplay = totalTx > 1_000_000 ? `${(totalTx / 1_000_000).toFixed(1)} MB/s` : `${(totalTx / 1000).toFixed(0)} KB/s`;
      }

      const cpu = metrics?.load1 != null ? `${metrics.load1.toFixed(2)}` : '—';
      const ram = metrics?.memTotalBytes && metrics.memUsedBytes
        ? `${((metrics.memUsedBytes / metrics.memTotalBytes) * 100).toFixed(0)}%`
        : '—';

      const secureLabel = auth.secure > 0
        ? `<span style="color:var(--success)">&#128274; ${auth.secure} secure</span>`
        : `<span style="color:var(--text-dim)">—</span>`;
      const failLabel = auth.failed > 0
        ? `<span style="color:var(--warning)">&#128683; ${auth.failed} failed</span>`
        : `<span style="color:var(--text-dim)">0 failed</span>`;
      const bruteLabel = auth.brute > 0
        ? `<span style="color:var(--critical)">&#9888; ${auth.brute} brute</span>`
        : '';

      const lastSeen = srv.lastSeenAt
        ? `${Math.floor((Date.now() - new Date(srv.lastSeenAt).getTime()) / 60000)}m ago`
        : 'never';

      return `<tr>
        <td>${statusDot} <b>${escapeHtml(srv.name)}</b></td>
        <td><span style="color:${isOnline ? 'var(--success)' : 'var(--critical)'}">${statusLabel}</span></td>
        <td style="font-family:var(--font-mono)">${cpu}</td>
        <td style="font-family:var(--font-mono)">${ram}</td>
        <td style="font-family:var(--font-mono)">&#8595; ${rxDisplay}</td>
        <td style="font-family:var(--font-mono)">&#8593; ${txDisplay}</td>
        <td>${secureLabel} ${failLabel} ${bruteLabel}</td>
        <td style="color:var(--text-dim)">${lastSeen}</td>
      </tr>`;
    });

    res.send(`<table>
      <thead><tr>
        <th>Server</th><th>Status</th><th>Load</th><th>RAM</th>
        <th>Network In</th><th>Network Out</th><th>Access (24h)</th><th>Last Seen</th>
      </tr></thead>
      <tbody>${rows.join('')}</tbody>
    </table>`);
  } catch (err) {
    logger.error({ err }, 'Server fleet API error');
    res.status(500).send('<p class="severity-critical">Error loading fleet data</p>');
  }
});

dashboardApi.get('/recent-threats', async (_req, res) => {
  try {
    const routineDockerTypes = [
      'docker_start', 'docker_stop', 'docker_die', 'docker_connect',
      'docker_disconnect', 'docker_mount', 'docker_unmount', 'docker_create',
      'docker_destroy', 'docker_pull', 'docker_attach', 'docker_detach',
      'docker_health_status', 'docker_rename', 'docker_update', 'docker_pause',
      'docker_unpause', 'docker_restart', 'docker_top', 'docker_resize',
    ];

    const events = await db.select({
      event: securityEvents,
      serverName: socServers.name,
    })
      .from(securityEvents)
      .leftJoin(socServers, eq(securityEvents.serverId, socServers.id))
      .where(and(
        ne(securityEvents.severity, 'info'),
        ...routineDockerTypes.map(t => ne(securityEvents.eventType, t))
      ))
      .orderBy(desc(securityEvents.timestamp))
      .limit(5);

    if (events.length === 0) {
      res.send('<div class="action-item"><span>&#9989;</span> Nenhuma ameaça detectada</div>');
      return;
    }

    const threatIcons: Record<string, string> = {
      ssh_brute_force: '&#128128;',
      crypto_mining: '&#9935;',
      unauthorized_login: '&#128274;',
      connection_flood: '&#127754;',
      dns_dga: '&#128225;',
      sudo_suspicious: '&#9888;',
      critical_file_tampering: '&#128196;',
      cron_persistence: '&#128337;',
      container_anomaly: '&#128230;',
      unauthorized_ssh_key: '&#128273;',
    };

    const html = events.map(({ event: e, serverName }) => {
      const icon = threatIcons[e.eventType] || '&#9888;';
      const ipLabel = e.sourceIp ? ` ${ipTag(e.sourceIp)}` : '';
      const name = serverName || `Server #${e.serverId}`;
      return `<div class="threat-item">
        <span class="threat-icon">${icon}</span>
        <div style="flex:1">
          <div style="font-size:0.82rem;"><span class="severity-${e.severity}">${escapeHtml(e.eventType.replace(/_/g, ' '))}</span>${ipLabel}</div>
          <div style="font-size:0.7rem; color:var(--text-dim)">${escapeHtml(name)} &middot; ${new Date(e.timestamp).toLocaleTimeString()}</div>
        </div>
      </div>`;
    }).join('');

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Recent threats API error');
    res.status(500).send('<p class="severity-critical">Error</p>');
  }
});

dashboardApi.get('/recent-actions', async (_req, res) => {
  try {
    const blocks = await db.select()
      .from(blockedIps)
      .orderBy(desc(blockedIps.blockedAt))
      .limit(4);

    if (blocks.length === 0) {
      res.send('<div class="action-item"><span>&#128737;</span> <span style="color: var(--text-dim)">No automated actions yet</span></div>');
      return;
    }

    const html = blocks.map(b => `
      <div class="action-item">
        <span style="font-size:1.1rem;">&#128737;</span>
        <div style="flex:1">
          <div style="font-size:0.82rem;">IP blocked: <code>${escapeHtml(b.ip)}</code></div>
          <div style="font-size:0.7rem; color:var(--text-dim)">${escapeHtml(b.reason)} &middot; Server #${b.serverId}</div>
        </div>
      </div>
    `).join('');

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Recent actions API error');
    res.status(500).send('<p>Error</p>');
  }
});

dashboardApi.get('/incidents', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const status = req.query.status as string || 'open';

    const incidents = await db.select()
      .from(socIncidents)
      .where(eq(socIncidents.status, status))
      .orderBy(desc(socIncidents.lastSeenAt))
      .limit(limit);

    if (incidents.length === 0) {
      res.send('<p style="padding:1rem; color:var(--text-dim)">No incidents found.</p>');
      return;
    }

    const html = `<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Events</th><th>Last Seen</th></tr></thead><tbody>${
      incidents.map(i => `<tr>
        <td><code>#${i.id}</code></td>
        <td>${escapeHtml(i.title)}</td>
        <td><span class="severity-${i.severity}">${i.severity}</span></td>
        <td>${i.eventCount}</td>
        <td style="color:var(--text-dim)">${new Date(i.lastSeenAt).toLocaleString()}</td>
      </tr>`).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard incidents API error');
    res.status(500).send('<p class="severity-critical">Error loading incidents</p>');
  }
});

dashboardApi.get('/servers', async (_req, res) => {
  try {
    const servers = await db.select().from(socServers).orderBy(socServers.name);

    if (servers.length === 0) {
      res.send('<p style="color:var(--text-dim)">No servers registered.</p>');
      return;
    }

    const html = `<table><thead><tr><th>Name</th><th>Host</th><th>Status</th><th>Last Seen</th></tr></thead><tbody>${
      servers.map(s => {
        const statusDot = s.enabled
          ? '<span style="color:var(--success);">&#9679;</span> Active'
          : '<span style="color:var(--critical);">&#9679;</span> Disabled';
        return `<tr>
          <td><strong>${escapeHtml(s.name)}</strong></td>
          <td><code>${escapeHtml(s.host)}:${s.sshPort}</code></td>
          <td>${statusDot}</td>
          <td style="color:var(--text-dim)">${s.lastSeenAt ? new Date(s.lastSeenAt).toLocaleString() : 'never'}</td>
        </tr>`;
      }).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard servers API error');
    res.status(500).send('<p class="severity-critical">Error loading servers</p>');
  }
});

dashboardApi.get('/cve-kpis', async (_req, res) => {
  try {
    const [pending] = await db.select({ cnt: count() }).from(cveAlerts).where(eq(cveAlerts.status, 'pending'));
    const [kevCount] = await db.select({ cnt: count() }).from(cveKev);
    const [epssHigh] = await db.select({ cnt: count() }).from(cveEpss).where(gte(cveEpss.epssScore, 0.5));
    const [runtimeEol] = await db.select({ cnt: count() }).from(vulnerabilities).where(and(eq(vulnerabilities.category, 'runtime'), eq(vulnerabilities.status, 'open')));

    res.send(`
      <div class="kpi kpi-red"><div class="kpi-label">Pending CVEs</div><div class="kpi-value kpi-value-red">${pending.cnt}</div></div>
      <div class="kpi kpi-yellow"><div class="kpi-label">EPSS ≥50%</div><div class="kpi-value kpi-value-yellow">${epssHigh.cnt}</div></div>
      <div class="kpi kpi-red"><div class="kpi-label">KEV (CISA)</div><div class="kpi-value kpi-value-red">${kevCount.cnt}</div></div>
      <div class="kpi kpi-yellow"><div class="kpi-label">Runtime EOL</div><div class="kpi-value kpi-value-yellow">${runtimeEol.cnt}</div></div>
    `);
  } catch (err) {
    logger.error({ err }, 'CVE KPIs error');
    res.status(500).send('');
  }
});

dashboardApi.get('/cve-alerts', async (req, res) => {
  try {
    const token = config.dashboard.token || '';
    const statusFilter = String(req.query.status ?? 'pending');
    const kevOnly = req.query.kev === '1';
    const categoryFilter = req.query.category ? String(req.query.category) : null;

    // Fetch KEV IDs for enrichment (cheap set lookup)
    const kevRows = await db.select({ cveId: cveKev.cveId }).from(cveKev);
    const kevSet = new Set(kevRows.map(r => r.cveId));

    // Fetch EPSS scores map
    const epssRows = await db.select({ cveId: cveEpss.cveId, score: cveEpss.epssScore }).from(cveEpss);
    const epssMap = new Map(epssRows.map(r => [r.cveId, r.score]));

    // Fetch server names
    const serverRows = await db.select({ id: socServers.id, name: socServers.name }).from(socServers);
    const serverMap = new Map(serverRows.map(s => [s.id, s.name]));

    if (kevOnly) {
      // Show KEV table — actively exploited CVEs from CISA
      const kevList = await db.select().from(cveKev).orderBy(desc(cveKev.dateAdded)).limit(50);
      if (kevList.length === 0) {
        res.send('<p style="color:var(--success)">&#9989; No CISA KEV entries loaded. Run CVE Intel Feeds worker to populate.</p>');
        return;
      }
      const html = `<div class="card-header"><span class="dot dot-red"></span>CISA Known Exploited Vulnerabilities (${kevList.length})</div>
      <table><thead><tr><th>CVE</th><th>Product</th><th>Vuln Name</th><th>Date Added</th><th>Ransomware</th></tr></thead><tbody>${
        kevList.map(k => `<tr>
          <td><code>${escapeHtml(k.cveId)}</code></td>
          <td>${escapeHtml(k.vendorProject ?? '')} / ${escapeHtml(k.product ?? '')}</td>
          <td>${escapeHtml(k.vulnerabilityName ?? '')}</td>
          <td>${k.dateAdded ? String(k.dateAdded).slice(0, 10) : '?'}</td>
          <td>${k.ransomwareUse ? '<span class="severity-critical">&#9888; Yes</span>' : '<span style="color:var(--text-dim)">No</span>'}</td>
        </tr>`).join('')
      }</tbody></table>`;
      res.send(html);
      return;
    }

    if (categoryFilter === 'runtime') {
      // Show runtime EOL findings from vulnerabilities table
      const vulns = await db.select().from(vulnerabilities)
        .where(and(eq(vulnerabilities.category, 'runtime'), eq(vulnerabilities.status, 'open')))
        .orderBy(desc(vulnerabilities.detectedAt))
        .limit(50);
      if (vulns.length === 0) {
        res.send('<p style="color:var(--success)">&#9989; No runtime EOL findings. Run a vulnerability scan to detect outdated runtimes.</p>');
        return;
      }
      const html = `<div class="card-header"><span class="dot dot-yellow"></span>Runtime EOL / Near-EOL Findings</div>
      <table><thead><tr><th>Server</th><th>Runtime</th><th>Severity</th><th>Details</th><th>Remediation</th></tr></thead><tbody>${
        vulns.map(v => {
          const sevClass = v.severity === 'critical' ? 'severity-critical' : v.severity === 'high' ? 'severity-high' : 'severity-medium';
          return `<tr>
            <td>${escapeHtml(serverMap.get(v.serverId) ?? String(v.serverId))}</td>
            <td>${escapeHtml(v.title ?? '')}</td>
            <td><span class="${sevClass}">${(v.severity ?? '?').toUpperCase()}</span></td>
            <td>${new Date(v.detectedAt).toLocaleDateString('pt-BR')}</td>
            <td style="max-width:300px;font-size:0.75rem;color:var(--text-muted)">${escapeHtml(v.remediation ?? '—')}</td>
          </tr>`;
        }).join('')
      }</tbody></table>`;
      res.send(html);
      return;
    }

    // Standard CVE alerts from cve_alerts table
    const whereClause = statusFilter === 'all'
      ? undefined
      : eq(cveAlerts.status, 'pending');

    const alerts = whereClause
      ? await db.select().from(cveAlerts).where(whereClause).orderBy(desc(cveAlerts.createdAt)).limit(100)
      : await db.select().from(cveAlerts).orderBy(desc(cveAlerts.createdAt)).limit(100);

    if (alerts.length === 0) {
      res.send('<p style="color:var(--success);">&#9989; No CVE alerts found. Either no vulnerabilities detected or CVE Monitor not yet run.</p>');
      return;
    }

    const html = `<table><thead><tr><th>CVE</th><th>Server</th><th>Package</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Fix</th><th>Actions</th></tr></thead><tbody>${
      alerts.map(a => {
        const cvss = a.cvssScore ? (a.cvssScore / 10).toFixed(1) : '?';
        const cvssNum = Number(cvss);
        const cvssClass = cvssNum >= 9 ? 'severity-critical' : cvssNum >= 7 ? 'severity-high' : cvssNum >= 4 ? 'severity-medium' : 'severity-low';
        const epss = epssMap.get(a.cveId);
        const epssDisplay = epss !== undefined ? `${(epss * 100).toFixed(1)}%` : '—';
        const epssColor = epss !== undefined && epss >= 0.5 ? 'var(--critical)' : epss !== undefined && epss >= 0.1 ? 'var(--warning)' : 'var(--text-dim)';
        const isKev = kevSet.has(a.cveId);
        const actions = a.status === 'pending' ? [
          a.fixedVersion ? `<button hx-post="/api/dashboard/cve/${a.id}/update?token=${token}" hx-swap="outerHTML" hx-target="closest tr" class="success">Patch</button>` : '',
          `<button hx-post="/api/dashboard/cve/${a.id}/ignore?token=${token}" hx-swap="outerHTML" hx-target="closest tr" class="danger">Ignore</button>`,
        ].filter(Boolean).join(' ') : `<span style="color:var(--text-dim)">${escapeHtml(a.status)}</span>`;
        return `<tr>
          <td><code>${escapeHtml(a.cveId)}</code>${isKev ? ' <span class="severity-critical" title="CISA Known Exploited">&#9888;KEV</span>' : ''}</td>
          <td>${escapeHtml(serverMap.get(a.serverId) ?? String(a.serverId))}</td>
          <td>${escapeHtml(a.packageName)} <span style="color:var(--text-dim);font-size:0.72rem">${escapeHtml(a.installedVersion)}</span></td>
          <td><span class="${cvssClass}">${cvss}</span></td>
          <td><span style="color:${epssColor};font-family:var(--font-mono)">${epssDisplay}</span></td>
          <td>${isKev ? '<span class="severity-critical">&#9888; Yes</span>' : '<span style="color:var(--text-dim)">—</span>'}</td>
          <td>${a.fixedVersion ? `<code>${escapeHtml(a.fixedVersion)}</code>` : '<span style="color:var(--text-dim)">—</span>'}</td>
          <td>${actions}</td>
        </tr>`;
      }).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard CVE API error');
    res.status(500).send('<p class="severity-critical">Error loading CVE alerts</p>');
  }
});

dashboardApi.post('/cve/:id/update', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await db.update(cveAlerts).set({ status: 'updating', resolvedAt: dbNow() }).where(eq(cveAlerts.id, id));
    res.send(`<tr><td colspan="5" style="color:var(--success);">&#9989; CVE #${id} — update triggered</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Dashboard CVE update error');
    res.status(500).send('<tr><td colspan="5" class="severity-critical">Error</td></tr>');
  }
});

dashboardApi.post('/cve/:id/ignore', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await db.update(cveAlerts).set({ status: 'ignored', resolvedAt: dbNow(), resolvedBy: 'dashboard' }).where(eq(cveAlerts.id, id));
    res.send(`<tr><td colspan="5" style="color:var(--text-dim);">CVE #${id} — ignored</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Dashboard CVE ignore error');
    res.status(500).send('<tr><td colspan="5" class="severity-critical">Error</td></tr>');
  }
});

// ─── Threat Hunt Findings API ───────────────────────────────────────────────

dashboardApi.get('/hunting', async (_req, res) => {
  try {
    const findings = await db.select()
      .from(threatHuntFindings)
      .orderBy(desc(threatHuntFindings.runAt))
      .limit(50);

    if (findings.length === 0) {
      res.send('<p style="color:var(--text-dim)">Nenhum resultado de threat hunt ainda. O worker executa a cada 4h após 5min de warm-up.</p>');
      return;
    }

    const sevColor: Record<string, string> = {
      critical: 'var(--critical)',
      high: 'var(--warning)',
      medium: '#fbbf24',
      low: 'var(--primary-bright)',
    };

    const sevIcon: Record<string, string> = {
      critical: '&#128308;',
      high: '&#128992;',
      medium: '&#128993;',
      low: '&#128309;',
    };

    // Group findings by hunt run (same minute)
    const runs = new Map<string, typeof findings>();
    for (const f of findings) {
      const key = new Date(f.runAt).toLocaleString();
      if (!runs.has(key)) runs.set(key, []);
      runs.get(key)!.push(f);
    }

    let html = '';
    for (const [runTime, runFindings] of runs) {
      const topSev = runFindings.reduce((max, f) => {
        const rank = (s: string) => ({ critical: 4, high: 3, medium: 2, low: 1 }[s] ?? 0);
        return rank(f.severity ?? 'low') > rank(max) ? (f.severity ?? 'low') : max;
      }, 'low');

      const color = sevColor[topSev] ?? 'var(--text-muted)';
      const provider = runFindings[0].aiProvider ?? 'ai';
      const eventsAnalyzed = runFindings[0].eventsAnalyzed;

      html += `
        <div class="card" style="margin-bottom:1rem;border-left:3px solid ${color};">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;">
            <div style="display:flex;align-items:center;gap:0.75rem;">
              <span style="font-size:1.1rem;">${sevIcon[topSev] ?? '&#9888;'}</span>
              <div>
                <div style="font-weight:600;font-size:0.88rem;">${runTime}</div>
                <div style="font-size:0.72rem;color:var(--text-dim);">${eventsAnalyzed} eventos analisados &middot; via ${escapeHtml(provider)}</div>
              </div>
            </div>
            <span style="font-size:0.7rem;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;color:${color};padding:2px 8px;border:1px solid ${color};border-radius:4px;">${topSev}</span>
          </div>
          <div style="display:grid;gap:0.5rem;">
            ${runFindings.map(f => {
              const lines = (f.finding ?? '').split('\n');
              const description = lines[0] ?? '';
              const recommendation = lines.find((l: string) => l.startsWith('Recommendation:'))?.replace('Recommendation:', '').trim() ?? '';
              const fc = sevColor[f.severity ?? 'low'] ?? 'var(--text-muted)';
              return `
                <div style="background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:var(--radius-sm);padding:0.75rem;">
                  <div style="display:flex;align-items:flex-start;gap:0.5rem;">
                    <span style="font-size:0.85rem;">${sevIcon[f.severity ?? 'low'] ?? '&#9898;'}</span>
                    <div style="flex:1;">
                      <div style="font-size:0.82rem;color:${fc};margin-bottom:${recommendation ? '0.4rem' : '0'};">${escapeHtml(description)}</div>
                      ${recommendation ? `<div style="font-size:0.75rem;color:var(--text-muted);">&#8594; ${escapeHtml(recommendation)}</div>` : ''}
                    </div>
                  </div>
                </div>`;
            }).join('')}
          </div>
        </div>`;
    }

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Threat hunt API error');
    res.status(500).send('<p class="severity-critical">Error loading threat hunt findings</p>');
  }
});

dashboardApi.get('/blocks', async (_req, res) => {
  try {
    const allBlocks = await db.select().from(blockedIps)
      .orderBy(desc(blockedIps.blockedAt))
      .limit(50);

    const blocks = allBlocks.filter(b => b.active);

    const rateLimits = await db.select().from(rateLimitedIps)
      .where(eq(rateLimitedIps.active, true))
      .orderBy(desc(rateLimitedIps.appliedAt))
      .limit(30);

    let html = '';

    if (blocks.length === 0 && rateLimits.length === 0) {
      res.send('<p style="color:var(--success);">&#9989; No active IP blocks or rate limits.</p>');
      return;
    }

    const token = config.dashboard.token || '';

    if (blocks.length > 0) {
      html += `
        <h3 class="section-title">Permanent Blocks (${blocks.length})</h3>
        <table><thead><tr><th>IP</th><th>Server</th><th>Reason</th><th>Blocked At</th><th>Expires</th><th>Actions</th></tr></thead><tbody>${
        blocks.map(b => `<tr>
          <td><span class="ip-tag">${escapeHtml(b.ip)}</span></td>
          <td>Server #${b.serverId}</td>
          <td style="font-size:0.78rem; color:var(--text-muted);">${escapeHtml(b.reason)}</td>
          <td style="color:var(--text-dim)">${new Date(b.blockedAt).toLocaleString()}</td>
          <td style="color:var(--text-dim)">${b.expiresAt ? new Date(b.expiresAt).toLocaleString() : 'permanent'}</td>
          <td><button class="danger" hx-post="/api/dashboard/blocks/${b.id}/unblock?token=${token}" hx-swap="outerHTML" hx-target="closest tr">Unblock</button></td>
        </tr>`).join('')
      }</tbody></table>`;
    } else {
      html += '<p style="color:var(--success);margin-bottom:1.5rem;">&#9989; No active IP blocks.</p>';
    }

    if (rateLimits.length > 0) {
      html += `
        <h3 class="section-title" style="margin-top:2rem;">Rate Limits — DDoS Graduated Response (${rateLimits.length} active)</h3>
        <p style="color:var(--text-muted);font-size:0.78rem;margin-bottom:1rem;">
          IPs em rate-limit são monitorados a cada 2min — se o ataque continuar, são promovidos a bloqueio permanente automaticamente.
        </p>
        <table><thead><tr><th>IP</th><th>Server</th><th>Limite</th><th>Motivo</th><th>Aplicado</th><th>Escalado</th></tr></thead><tbody>${
        rateLimits.map(r => `<tr>
          <td><span class="ip-tag">${escapeHtml(r.ip)}</span></td>
          <td>Server #${r.serverId}</td>
          <td style="font-family:var(--font-mono);font-size:0.78rem;color:var(--warning);">${r.limitPerSec} req/s (burst ${r.burst})</td>
          <td style="font-size:0.78rem;color:var(--text-muted);">${escapeHtml(r.reason ?? '—')}</td>
          <td style="color:var(--text-dim)">${new Date(r.appliedAt).toLocaleString()}</td>
          <td style="color:var(--text-dim)">${r.escalatedAt ? new Date(r.escalatedAt).toLocaleString() : '<span style="color:var(--success)">Não escalado</span>'}</td>
        </tr>`).join('')
      }</tbody></table>`;
    } else {
      html += '<p style="color:var(--success);margin-top:1.5rem;">&#9989; No active rate limits.</p>';
    }

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard blocks API error');
    res.status(500).send('<p class="severity-critical">Error loading blocks</p>');
  }
});

dashboardApi.post('/blocks/:id/unblock', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await db.update(blockedIps).set({ active: dbFalse, unblockedAt: dbNow() }).where(eq(blockedIps.id, id));
    res.send(`<tr><td colspan="6" style="color:var(--success);">&#9989; Block #${id} removed</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Dashboard unblock error');
    res.status(500).send('<tr><td colspan="6" class="severity-critical">Error</td></tr>');
  }
});

// ─── Playbook Execution History API ─────────────────────────────────────────

dashboardApi.get('/playbook-history', async (_req, res) => {
  try {
    const executions = await db.select().from(playbookExecutions)
      .orderBy(desc(playbookExecutions.startedAt))
      .limit(50);

    if (executions.length === 0) {
      res.send('<p style="color:var(--text-dim)">Nenhuma execução de playbook registrada ainda.</p>');
      return;
    }

    const statusIcon: Record<string, string> = {
      completed: '<span style="color:var(--success)">&#10003;</span>',
      failed: '<span style="color:var(--critical)">&#10007;</span>',
      running: '<span style="color:var(--warning)">&#9881;</span>',
      partial: '<span style="color:#fbbf24">&#9888;</span>',
    };

    const html = `<table>
      <thead><tr><th>Playbook</th><th>Status</th><th>Trigger</th><th>Server</th><th>Passos OK</th><th>Passos Falhos</th><th>Início</th><th>Duração</th></tr></thead>
      <tbody>${executions.map(e => {
        const icon = statusIcon[e.status] ?? statusIcon.running;
        const steps = (e.stepsCompleted as string[] | null) ?? [];
        const failed = (e.stepsFailed as string[] | null) ?? [];
        const duration = e.completedAt
          ? `${Math.round((new Date(e.completedAt).getTime() - new Date(e.startedAt).getTime()) / 1000)}s`
          : '—';
        return `<tr>
          <td><strong style="font-size:0.82rem;">${escapeHtml(e.playbookName)}</strong></td>
          <td>${icon} <span style="font-size:0.78rem;color:${e.status === 'completed' ? 'var(--success)' : e.status === 'failed' ? 'var(--critical)' : 'var(--warning)'};">${e.status}</span></td>
          <td style="font-size:0.75rem;color:var(--text-muted);">${escapeHtml(e.triggerType ?? '—')}</td>
          <td style="color:var(--text-dim)">Server #${e.serverId ?? '—'}</td>
          <td style="font-size:0.78rem;">${steps.length > 0 ? `<span style="color:var(--success)">${steps.length}</span> <span style="color:var(--text-dim);font-size:0.7rem;">${steps.slice(0, 2).map(s => escapeHtml(s)).join(', ')}${steps.length > 2 ? '…' : ''}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
          <td style="font-size:0.78rem;">${failed.length > 0 ? `<span style="color:var(--critical)">${failed.length}</span> <span style="color:var(--text-dim);font-size:0.7rem;">${failed.slice(0, 2).map(s => escapeHtml(s)).join(', ')}${failed.length > 2 ? '…' : ''}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
          <td style="color:var(--text-dim);font-size:0.75rem;">${new Date(e.startedAt).toLocaleString()}</td>
          <td style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);">${duration}</td>
        </tr>`;
      }).join('')}</tbody>
    </table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Playbook history API error');
    res.status(500).send('<p class="severity-critical">Error loading playbook history</p>');
  }
});

dashboardApi.get('/events', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit as string) || 100, 200);
    const severity = req.query.severity as string || '';
    const eventType = req.query.type as string || '';
    const sourceIp = req.query.ip as string || '';

    const conditions = [];
    if (severity) conditions.push(eq(securityEvents.severity, severity));
    if (eventType) conditions.push(eq(securityEvents.eventType, eventType));
    if (sourceIp) conditions.push(eq(securityEvents.sourceIp, sourceIp));

    const query = db.select()
      .from(securityEvents)
      .orderBy(desc(securityEvents.timestamp))
      .limit(limit);

    const events = conditions.length > 0
      ? await query.where(and(...conditions))
      : await query;

    if (events.length === 0) {
      res.send('<p style="color:var(--text-dim)">No events found.</p>');
      return;
    }

    const html = `<table><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source IP</th><th>Server</th></tr></thead><tbody>${
      events.map(e => `<tr>
        <td style="color:var(--text-dim)">${new Date(e.timestamp).toLocaleString()}</td>
        <td>${escapeHtml(e.eventType.replace(/_/g, ' '))}</td>
        <td><span class="severity-${e.severity}">${e.severity}</span></td>
        <td>${e.sourceIp ? ipTag(e.sourceIp) : '<span style="color:var(--text-dim)">—</span>'}</td>
        <td>#${e.serverId}</td>
      </tr>`).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard events API error');
    res.status(500).send('<p class="severity-critical">Error loading events</p>');
  }
});

// ─── Fleet Health & Scores API ───────────────────────────────────────────────

dashboardApi.get('/fleet-health', async (_req, res) => {
  try {
    const servers = await db.select().from(socServers).orderBy(socServers.name);

    if (servers.length === 0) {
      res.send('<p style="color:var(--text-dim)">No servers registered.</p>');
      return;
    }

    const token = config.dashboard.token || '';
    let html = '<div class="kpi-grid">';

    const latestScores = await db.select().from(serverScores)
      .orderBy(desc(serverScores.periodStart))
      .limit(servers.length * 2);
    const scoreMap = new Map<number, typeof latestScores[0]>();
    for (const s of latestScores) {
      if (!scoreMap.has(s.serverId)) scoreMap.set(s.serverId, s);
    }

    const latestMetricsAll = await db.select().from(serverMetrics)
      .orderBy(desc(serverMetrics.collectedAt))
      .limit(servers.length * 2);
    const metricsMap = new Map<number, typeof latestMetricsAll[0]>();
    for (const m of latestMetricsAll) {
      if (!metricsMap.has(m.serverId)) metricsMap.set(m.serverId, m);
    }

    for (const server of servers) {
      const latestScore = scoreMap.get(server.id);
      const latestMetrics = metricsMap.get(server.id);

      const overall = latestScore?.overallScore ?? 0;
      const color = overall >= 80 ? 'var(--success)' : overall >= 60 ? 'var(--warning)' : 'var(--critical)';
      const glowColor = overall >= 80 ? 'rgba(34,197,94,0.3)' : overall >= 60 ? 'rgba(245,158,11,0.3)' : 'rgba(239,68,68,0.3)';

      const memPct = latestMetrics?.memTotalBytes
        ? Math.round(((latestMetrics.memUsedBytes ?? 0) / latestMetrics.memTotalBytes) * 100)
        : 0;
      const load = latestMetrics?.load1?.toFixed(1) ?? '-';

      html += `
        <a href="/dashboard/health/${server.id}?token=${token}" style="text-decoration: none;">
          <div class="card" style="box-shadow: 0 0 15px ${glowColor}; border-color: ${color}30;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
              <strong style="color:var(--text)">${escapeHtml(server.name)}</strong>
              <span style="color:${color}; font-family:var(--font-mono); font-size:1.5rem; font-weight:700; text-shadow:0 0 10px ${glowColor};">${overall}</span>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; font-size:0.75rem; color:var(--text-muted);">
              <div>Load: <span style="color:var(--text)">${load}</span></div>
              <div>Mem: <span style="color:var(--text)">${memPct}%</span></div>
            </div>
            <div style="font-size:0.7rem; color:var(--text-dim); margin-top:0.5rem;">${escapeHtml(server.host)}</div>
          </div>
        </a>`;
    }

    html += '</div>';
    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Fleet health API error');
    res.status(500).send('<p class="severity-critical">Error loading fleet health</p>');
  }
});

dashboardApi.get('/server/:id/metrics', async (req, res) => {
  try {
    const serverId = parseInt(req.params.id);
    const metrics = await db.select().from(serverMetrics)
      .where(eq(serverMetrics.serverId, serverId))
      .orderBy(desc(serverMetrics.collectedAt))
      .limit(20);

    if (metrics.length === 0) {
      res.send('<p style="color:var(--text-dim)">No metrics collected yet.</p>');
      return;
    }

    const latest = metrics[0];
    const memPct = latest.memTotalBytes ? Math.round(((latest.memUsedBytes ?? 0) / latest.memTotalBytes) * 100) : 0;
    const loadRatio = ((latest.load1 ?? 0) / Math.max(latest.cpuCount ?? 1, 1)).toFixed(2);
    const disks = (latest.disks as any[]) ?? [];
    const failedUnits = (latest.failedUnits as string[]) ?? [];

    let html = `
      <div class="kpi-grid">
        <div class="kpi kpi-blue">
          <div class="kpi-label">Load Ratio</div>
          <div class="kpi-value kpi-value-blue">${loadRatio}</div>
        </div>
        <div class="kpi ${memPct > 85 ? 'kpi-red' : 'kpi-green'}">
          <div class="kpi-label">Memory</div>
          <div class="kpi-value ${memPct > 85 ? 'kpi-value-red' : 'kpi-value-green'}">${memPct}%</div>
        </div>
        <div class="kpi kpi-cyan">
          <div class="kpi-label">CPUs</div>
          <div class="kpi-value kpi-value-cyan">${latest.cpuCount ?? '-'}</div>
        </div>
        <div class="kpi kpi-green">
          <div class="kpi-label">Uptime</div>
          <div class="kpi-value kpi-value-green">${latest.uptimeSeconds ? Math.floor(latest.uptimeSeconds / 86400) + 'd' : '-'}</div>
        </div>
      </div>`;

    if (disks.length > 0) {
      html += '<h3 class="section-title">Disks</h3><table><thead><tr><th>Mount</th><th>Usage</th><th>Available</th></tr></thead><tbody>';
      for (const d of disks) {
        const diskPct = d.usedPercent ?? d.percent ?? 0;
        const diskColor = diskPct > 85 ? 'severity-critical' : diskPct > 70 ? 'severity-high' : '';
        html += `<tr><td><code>${d.mountpoint ?? d.mount ?? '/'}</code></td><td class="${diskColor}">${diskPct}%</td><td>${d.availableBytes ? Math.round(d.availableBytes / 1073741824) + 'G' : '-'}</td></tr>`;
      }
      html += '</tbody></table>';
    }

    if (failedUnits.length > 0) {
      html += `<h3 class="section-title">Failed Services</h3><div class="threat-card">${
        failedUnits.map((u: string) => `<div class="threat-item"><span class="threat-icon">&#9888;</span><code>${escapeHtml(u)}</code></div>`).join('')
      }</div>`;
    }

    const kernelErrors = latest.kernelErrors ?? 0;
    const journalErrors = latest.journalErrors ?? 0;
    if (kernelErrors > 0 || journalErrors > 0) {
      html += `
        <h3 class="section-title">System Errors</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
          <div class="kpi ${kernelErrors > 5 ? 'kpi-red' : kernelErrors > 0 ? 'kpi-yellow' : 'kpi-green'}">
            <div class="kpi-label">Kernel Errors</div>
            <div class="kpi-value ${kernelErrors > 5 ? 'kpi-value-red' : kernelErrors > 0 ? 'kpi-value-yellow' : 'kpi-value-green'}">${kernelErrors}</div>
          </div>
          <div class="kpi ${journalErrors > 10 ? 'kpi-red' : journalErrors > 0 ? 'kpi-yellow' : 'kpi-green'}">
            <div class="kpi-label">Journal Errors</div>
            <div class="kpi-value ${journalErrors > 10 ? 'kpi-value-red' : journalErrors > 0 ? 'kpi-value-yellow' : 'kpi-value-green'}">${journalErrors}</div>
          </div>
        </div>`;
    }

    const diskIo = latest.diskIo as Record<string, { readBytesPerSec?: number; writeBytesPerSec?: number }> | null;
    const networkIo = latest.networkIo as Record<string, { rxBytesPerSec?: number; txBytesPerSec?: number }> | null;

    if (diskIo && Object.keys(diskIo).length > 0) {
      html += `<h3 class="section-title">Disk I/O</h3>
        <table><thead><tr><th>Device</th><th>Read</th><th>Write</th></tr></thead><tbody>${
        Object.entries(diskIo).map(([dev, io]) => `<tr>
          <td><code>${escapeHtml(dev)}</code></td>
          <td style="font-family:var(--font-mono);font-size:0.78rem;">${io.readBytesPerSec != null ? (io.readBytesPerSec / 1048576).toFixed(1) + ' MB/s' : '—'}</td>
          <td style="font-family:var(--font-mono);font-size:0.78rem;">${io.writeBytesPerSec != null ? (io.writeBytesPerSec / 1048576).toFixed(1) + ' MB/s' : '—'}</td>
        </tr>`).join('')
      }</tbody></table>`;
    }

    if (networkIo && Object.keys(networkIo).length > 0) {
      html += `<h3 class="section-title">Network I/O</h3>
        <table><thead><tr><th>Interface</th><th>RX</th><th>TX</th></tr></thead><tbody>${
        Object.entries(networkIo).map(([iface, io]) => `<tr>
          <td><code>${escapeHtml(iface)}</code></td>
          <td style="font-family:var(--font-mono);font-size:0.78rem;color:var(--cyan);">${io.rxBytesPerSec != null ? (io.rxBytesPerSec / 1048576).toFixed(2) + ' MB/s' : '—'}</td>
          <td style="font-family:var(--font-mono);font-size:0.78rem;color:var(--warning);">${io.txBytesPerSec != null ? (io.txBytesPerSec / 1048576).toFixed(2) + ' MB/s' : '—'}</td>
        </tr>`).join('')
      }</tbody></table>`;
    }

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Server metrics API error');
    res.status(500).send('<p class="severity-critical">Error loading metrics</p>');
  }
});

dashboardApi.get('/server/:id/scores', async (req, res) => {
  try {
    const serverId = parseInt(req.params.id);
    const scores = await db.select().from(serverScores)
      .where(eq(serverScores.serverId, serverId))
      .orderBy(desc(serverScores.periodStart))
      .limit(24);

    if (scores.length === 0) {
      res.send('<p style="color:var(--text-dim)">No scores computed yet.</p>');
      return;
    }

    const html = `<table class="score-grid-table"><thead><tr><th>Period</th><th>Overall</th><th>Health</th><th>Security</th><th>Quality</th><th>Waste</th><th>Vuln</th><th>Avail</th></tr></thead><tbody>${
      scores.map(s => {
        const color = s.overallScore >= 80 ? 'var(--success)' : s.overallScore >= 60 ? 'var(--warning)' : 'var(--critical)';
        return `<tr>
          <td style="color:var(--text-dim)">${new Date(s.periodStart).toLocaleString()}</td>
          <td class="score-cell" style="color:${color};text-shadow:0 0 8px ${color};">${s.overallScore}</td>
          <td class="score-cell">${s.healthScore}</td>
          <td class="score-cell">${s.securityScore}</td>
          <td class="score-cell">${s.qualityScore}</td>
          <td class="score-cell">${s.wasteScore}</td>
          <td class="score-cell">${s.vulnerabilityScore}</td>
          <td class="score-cell">${s.availabilityScore}</td>
        </tr>`;
      }).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Server scores API error');
    res.status(500).send('<p class="severity-critical">Error loading scores</p>');
  }
});

dashboardApi.get('/scores', async (_req, res) => {
  try {
    const servers = await db.select().from(socServers).orderBy(socServers.name);

    if (servers.length === 0) {
      res.send('<p style="color:var(--text-dim)">No servers registered.</p>');
      return;
    }

    let html = '<table class="score-grid-table"><thead><tr><th style="text-align:left">Server</th><th>Overall</th><th>Health</th><th>Security</th><th>Quality</th><th>Waste</th><th>Vuln</th><th>Avail</th></tr></thead><tbody>';

    const latestScores = await db.select().from(serverScores)
      .orderBy(desc(serverScores.periodStart))
      .limit(servers.length * 2);

    const scoreMap = new Map<number, typeof latestScores[0]>();
    for (const score of latestScores) {
      if (!scoreMap.has(score.serverId)) scoreMap.set(score.serverId, score);
    }

    for (const server of servers) {
      const s = scoreMap.get(server.id);

      if (!s) {
        html += `<tr><td style="text-align:left"><strong>${escapeHtml(server.name)}</strong></td><td colspan="7" style="color:var(--text-dim)"><em>No data</em></td></tr>`;
        continue;
      }

      const color = s.overallScore >= 80 ? 'var(--success)' : s.overallScore >= 60 ? 'var(--warning)' : 'var(--critical)';

      const scoreCell = (val: number) => {
        const c = val >= 80 ? 'var(--success)' : val >= 60 ? 'var(--warning)' : 'var(--critical)';
        return `<td class="score-cell" style="color:${c}">${val}</td>`;
      };

      html += `<tr>
        <td style="text-align:left"><strong>${escapeHtml(server.name)}</strong></td>
        <td class="score-cell" style="color:${color};text-shadow:0 0 8px ${color};font-size:1.1rem;">${s.overallScore}</td>
        ${scoreCell(s.healthScore)}
        ${scoreCell(s.securityScore)}
        ${scoreCell(s.qualityScore)}
        ${scoreCell(s.wasteScore)}
        ${scoreCell(s.vulnerabilityScore)}
        ${scoreCell(s.availabilityScore)}
      </tr>`;
    }

    html += '</tbody></table>';
    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Scores API error');
    res.status(500).send('<p class="severity-critical">Error loading scores</p>');
  }
});

// ─── Timeline API ─────────────────────────────────────────────────────────

dashboardApi.get('/timeline', async (_req, res) => {
  try {
    const events = await db.select()
      .from(securityEvents)
      .orderBy(desc(securityEvents.timestamp))
      .limit(50);

    if (events.length === 0) {
      res.send('<p style="color:var(--text-dim)">No events to show.</p>');
      return;
    }

    const grouped = new Map<string, typeof events>();
    for (const e of events) {
      const dateKey = new Date(e.timestamp).toLocaleDateString();
      if (!grouped.has(dateKey)) grouped.set(dateKey, []);
      grouped.get(dateKey)!.push(e);
    }

    const severityIcon: Record<string, string> = {
      critical: '&#128308;',
      high: '&#128992;',
      medium: '&#128993;',
      low: '&#128309;',
      info: '&#9898;',
    };

    let html = '<div style="position:relative;padding-left:2rem;">';
    html += '<div style="position:absolute;left:0.75rem;top:0;bottom:0;width:2px;background:var(--border);"></div>';

    for (const [date, dayEvents] of grouped) {
      html += `<div style="margin-bottom:1.5rem;"><div style="color:var(--cyan);font-weight:600;font-size:0.85rem;margin-bottom:0.75rem;position:relative;">`
        + `<span style="position:absolute;left:-1.65rem;width:12px;height:12px;border-radius:50%;background:var(--cyan);top:2px;box-shadow:0 0 8px var(--cyan);"></span>`
        + `${escapeHtml(date)}</div>`;

      for (const e of dayEvents) {
        const time = new Date(e.timestamp).toLocaleTimeString();
        const icon = severityIcon[e.severity] || '&#9898;';
        const ipLabel = e.sourceIp ? ` ${ipTag(e.sourceIp)}` : '';
        html += `<div style="display:flex;align-items:flex-start;gap:0.5rem;padding:0.35rem 0;font-size:0.8rem;">`
          + `<span style="color:var(--text-dim);min-width:5rem;font-family:var(--font-mono);font-size:0.72rem;">${time}</span>`
          + `<span>${icon}</span>`
          + `<div><span class="severity-${e.severity}">${escapeHtml(e.eventType.replace(/_/g, ' '))}</span>${ipLabel}`
          + `<span style="color:var(--text-dim);font-size:0.72rem;margin-left:0.5rem;">#${e.serverId}</span></div>`
          + `</div>`;
      }
      html += '</div>';
    }

    html += '</div>';
    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Timeline API error');
    res.status(500).send('<p class="severity-critical">Error loading timeline</p>');
  }
});

// ─── System Status API ─────────────────────────────────────────────────────

dashboardApi.get('/system-status', async (_req, res) => {
  try {
    const circuitStatus = ThreatIntelManager.getCircuitStatus();
    const dbOk = await import('../database/connection.js').then(m => m.testConnection()).catch(() => false);

    const statusIcon = (s: string) => s === 'closed' ? '&#128994;' : s === 'open' ? '&#128308;' : '&#128993;';
    const statusLabel = (s: string) => s === 'closed' ? 'Healthy' : s === 'open' ? 'Circuit Open' : 'Recovering';

    const uptimeSeconds = Math.floor(process.uptime());
    const uptimeStr = uptimeSeconds >= 86400
      ? `${Math.floor(uptimeSeconds / 86400)}d ${Math.floor((uptimeSeconds % 86400) / 3600)}h`
      : uptimeSeconds >= 3600
        ? `${Math.floor(uptimeSeconds / 3600)}h ${Math.floor((uptimeSeconds % 3600) / 60)}m`
        : `${Math.floor(uptimeSeconds / 60)}m`;

    const memUsage = process.memoryUsage();
    const heapMB = Math.round(memUsage.heapUsed / 1048576);
    const rssMB = Math.round(memUsage.rss / 1048576);

    let html = `
      <div class="kpi-grid">
        <div class="kpi kpi-green">
          <div class="kpi-label">Uptime</div>
          <div class="kpi-value kpi-value-green">${uptimeStr}</div>
        </div>
        <div class="kpi kpi-blue">
          <div class="kpi-label">Heap Memory</div>
          <div class="kpi-value kpi-value-blue">${heapMB}MB</div>
        </div>
        <div class="kpi kpi-cyan">
          <div class="kpi-label">RSS Memory</div>
          <div class="kpi-value kpi-value-cyan">${rssMB}MB</div>
        </div>
        <div class="kpi ${dbOk ? 'kpi-green' : 'kpi-red'}">
          <div class="kpi-label">Database</div>
          <div class="kpi-value ${dbOk ? 'kpi-value-green' : 'kpi-value-red'}">${dbOk ? 'OK' : 'ERR'}</div>
        </div>
      </div>

      <h3 class="section-title">External API Circuits</h3>
      <table>
        <thead><tr><th>Service</th><th>Status</th><th>Description</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>AbuseIPDB</strong></td>
            <td>${statusIcon(circuitStatus.abuseipdb)} ${statusLabel(circuitStatus.abuseipdb)}</td>
            <td style="color:var(--text-dim)">IP reputation lookups (1000/day free tier)</td>
          </tr>
          <tr>
            <td><strong>VirusTotal</strong></td>
            <td>${statusIcon(circuitStatus.virustotal)} ${statusLabel(circuitStatus.virustotal)}</td>
            <td style="color:var(--text-dim)">IP malware analysis (500/day free tier)</td>
          </tr>
        </tbody>
      </table>

      <h3 class="section-title">Guardian Info</h3>
      <table>
        <thead><tr><th>Property</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>Version</td><td><code>1.5.0</code></td></tr>
          <tr><td>Node.js</td><td><code>${process.version}</code></td></tr>
          <tr><td>Platform</td><td><code>${process.platform} ${process.arch}</code></td></tr>
          <tr><td>PID</td><td><code>${process.pid}</code></td></tr>
        </tbody>
      </table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'System status API error');
    res.status(500).send('<p class="severity-critical">Error loading system status</p>');
  }
});

// ─── Geo Attack Map API ──────────────────────────────────────────────────────

dashboardApi.get('/geo-attacks', async (_req, res) => {
  try {
    const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const attacks = await db.select({
      ip: securityEvents.sourceIp,
      cnt: count(),
      severity: sql<string>`MAX(${securityEvents.severity})`,
    })
      .from(securityEvents)
      .where(and(
        gte(securityEvents.timestamp, weekAgo),
        ne(securityEvents.severity, 'info'),
        sql`${securityEvents.sourceIp} IS NOT NULL AND ${securityEvents.sourceIp} != ''`,
      ))
      .groupBy(securityEvents.sourceIp)
      .orderBy(desc(count()))
      .limit(100);

    const countryMap = new Map<string, { count: number; ips: string[]; topSeverity: string }>();
    const ipList: Array<{ ip: string; count: number; severity: string; country: string }> = [];

    for (const atk of attacks) {
      if (!atk.ip) continue;
      const enrichment = await db.select({ enrichment: securityEvents.enrichment })
        .from(securityEvents)
        .where(eq(securityEvents.sourceIp, atk.ip))
        .limit(1)
        .then(rows => rows[0]?.enrichment as Record<string, any> | null);

      const country = enrichment?.country ?? enrichment?.threatIntel?.country ?? 'Unknown';
      const entry = countryMap.get(country) || { count: 0, ips: [], topSeverity: 'low' };
      entry.count += Number(atk.cnt);
      if (entry.ips.length < 5) entry.ips.push(atk.ip);
      if (severityRank(atk.severity) > severityRank(entry.topSeverity)) entry.topSeverity = atk.severity;
      countryMap.set(country, entry);

      ipList.push({ ip: atk.ip, count: Number(atk.cnt), severity: atk.severity, country });
    }

    const sortedCountries = [...countryMap.entries()].sort((a, b) => b[1].count - a[1].count);
    const totalAttacks = sortedCountries.reduce((s, [, v]) => s + v.count, 0);

    const countryRows = sortedCountries.slice(0, 20).map(([country, data]) => {
      const pct = totalAttacks > 0 ? Math.round((data.count / totalAttacks) * 100) : 0;
      const sevColor = data.topSeverity === 'critical' ? 'var(--critical)' :
                       data.topSeverity === 'high' ? 'var(--warning)' : 'var(--cyan)';
      const bar = `<div style="background:${sevColor};height:8px;width:${Math.max(pct, 2)}%;border-radius:4px;"></div>`;
      return `<tr>
        <td><strong>${escapeHtml(country)}</strong></td>
        <td>${data.count}</td>
        <td style="width:40%">${bar}</td>
        <td>${pct}%</td>
        <td><code style="font-size:11px">${data.ips.slice(0, 3).join(', ')}</code></td>
      </tr>`;
    }).join('');

    const topIPs = ipList.slice(0, 15).map(ip => {
      const sevIcon = ip.severity === 'critical' ? '&#128308;' :
                      ip.severity === 'high' ? '&#128992;' :
                      ip.severity === 'medium' ? '&#128993;' : '&#128309;';
      return `<tr>
        <td>${sevIcon}</td>
        <td>${ipTag(ip.ip)}</td>
        <td>${ip.count}</td>
        <td>${escapeHtml(ip.country)}</td>
        <td>${ip.severity}</td>
      </tr>`;
    }).join('');

    const html = `
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:2rem;">
        <div class="kpi">
          <div class="kpi-label">Countries</div>
          <div class="kpi-value">${sortedCountries.length}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">Unique IPs</div>
          <div class="kpi-value">${attacks.length}</div>
        </div>
        <div class="kpi">
          <div class="kpi-label">Total Events</div>
          <div class="kpi-value">${totalAttacks.toLocaleString()}</div>
        </div>
      </div>

      <h3 class="section-title">Attack Origins by Country</h3>
      <table>
        <thead><tr><th>Country</th><th>Events</th><th>Distribution</th><th>%</th><th>Top IPs</th></tr></thead>
        <tbody>${countryRows || '<tr><td colspan="5" style="text-align:center;color:var(--text-dim)">No attack data in the last 7 days</td></tr>'}</tbody>
      </table>

      <h3 class="section-title" style="margin-top:2rem;">Top Attacking IPs</h3>
      <table>
        <thead><tr><th></th><th>IP</th><th>Events</th><th>Country</th><th>Severity</th></tr></thead>
        <tbody>${topIPs || '<tr><td colspan="5" style="text-align:center;color:var(--text-dim)">No data</td></tr>'}</tbody>
      </table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Geo attacks API error');
    res.status(500).send('<p class="severity-critical">Error loading geo data</p>');
  }
});

function severityRank(s: string): number {
  const ranks: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return ranks[s] ?? 0;
}

// ─── Approvals API ──────────────────────────────────────────────────────────

interface WebPendingApproval {
  id: string;
  playbookName: string;
  serverName: string;
  sourceIp?: string;
  incidentId?: number;
  createdAt: number;
}

const webPendingApprovals = new Map<string, WebPendingApproval & { ctx: PlaybookContext }>();

export function addWebPendingApproval(playbookName: string, ctx: PlaybookContext): string {
  const id = `web_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  webPendingApprovals.set(id, {
    id,
    playbookName,
    serverName: ctx.serverName,
    sourceIp: ctx.sourceIp,
    incidentId: ctx.incidentId,
    createdAt: Date.now(),
    ctx,
  });

  setTimeout(() => { webPendingApprovals.delete(id); }, 30 * 60 * 1000);
  return id;
}

dashboardApi.get('/pending-approvals', async (_req, res) => {
  try {
    const approvals = [...webPendingApprovals.values()].map(a => ({
      id: a.id,
      playbookName: a.playbookName,
      serverName: a.serverName,
      sourceIp: a.sourceIp,
      incidentId: a.incidentId,
      age: Math.round((Date.now() - a.createdAt) / 60_000),
    }));

    if (approvals.length === 0) {
      res.send('<p style="color:var(--success);">No pending approvals.</p>');
      return;
    }

    const token = config.dashboard.token || '';
    const html = `<table><thead><tr><th>Playbook</th><th>Server</th><th>IP</th><th>Age</th><th>Actions</th></tr></thead><tbody>${
      approvals.map(a => `<tr id="approval-${a.id}">
        <td><strong>${escapeHtml(a.playbookName)}</strong></td>
        <td>${escapeHtml(a.serverName)}</td>
        <td>${a.sourceIp ? ipTag(a.sourceIp) : '—'}</td>
        <td style="color:var(--text-dim)">${a.age}min ago</td>
        <td>
          <button class="success" hx-post="/api/dashboard/approvals/${a.id}/approve?token=${token}" hx-target="#approval-${a.id}" hx-swap="outerHTML">Approve</button>
          <button class="danger" hx-post="/api/dashboard/approvals/${a.id}/reject?token=${token}" hx-target="#approval-${a.id}" hx-swap="outerHTML">Reject</button>
        </td>
      </tr>`).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Pending approvals API error');
    res.status(500).send('<p class="severity-critical">Error</p>');
  }
});

dashboardApi.post('/approvals/:id/approve', async (req, res) => {
  try {
    const pending = webPendingApprovals.get(req.params.id);
    if (!pending) {
      res.send('<tr><td colspan="5" style="color:var(--text-dim)">Approval expired or already processed</td></tr>');
      return;
    }

    webPendingApprovals.delete(req.params.id);
    const playbook = PlaybookRegistry.getByName(pending.playbookName);

    if (playbook) {
      PlaybookEngine.execute(playbook, { ...pending.ctx, triggeredBy: 'dashboard:approval' }).catch(err =>
        logger.error({ err, playbook: pending.playbookName }, 'Dashboard-approved playbook failed')
      );
    }

    res.send(`<tr><td colspan="5" style="color:var(--success);">Approved: ${escapeHtml(pending.playbookName)} — executing</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Approval approve error');
    res.status(500).send('<tr><td colspan="5" class="severity-critical">Error</td></tr>');
  }
});

dashboardApi.post('/approvals/:id/reject', async (req, res) => {
  try {
    const pending = webPendingApprovals.get(req.params.id);
    webPendingApprovals.delete(req.params.id);
    const name = pending?.playbookName ?? 'unknown';
    res.send(`<tr><td colspan="5" style="color:var(--text-dim);">Rejected: ${escapeHtml(name)}</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Approval reject error');
    res.status(500).send('<tr><td colspan="5" class="severity-critical">Error</td></tr>');
  }
});

// ─── Incident Feedback API ──────────────────────────────────────────────────

dashboardApi.get('/incidents-feedback', async (_req, res) => {
  try {
    const incidents = await db.select()
      .from(socIncidents)
      .where(eq(socIncidents.status, 'open'))
      .orderBy(desc(socIncidents.lastSeenAt))
      .limit(20);

    if (incidents.length === 0) {
      res.send('<p style="color:var(--text-dim)">No open incidents.</p>');
      return;
    }

    const token = config.dashboard.token || '';
    const html = `<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Events</th><th>Feedback</th></tr></thead><tbody>${
      incidents.map(i => `<tr id="incident-fb-${i.id}">
        <td><code>#${i.id}</code></td>
        <td>${escapeHtml(i.title)}</td>
        <td><span class="severity-${i.severity}">${i.severity}</span></td>
        <td>${i.eventCount}</td>
        <td>
          <button class="success" hx-post="/api/dashboard/incidents/${i.id}/confirm?token=${token}" hx-target="#incident-fb-${i.id}" hx-swap="outerHTML" style="font-size:0.72rem;">Confirm</button>
          <button style="font-size:0.72rem;background:var(--text-dim);" hx-post="/api/dashboard/incidents/${i.id}/false-positive?token=${token}" hx-target="#incident-fb-${i.id}" hx-swap="outerHTML">False Positive</button>
        </td>
      </tr>`).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Incidents feedback API error');
    res.status(500).send('<p class="severity-critical">Error</p>');
  }
});

dashboardApi.post('/incidents/:id/confirm', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await IncidentMemoryService.store(id, 'Confirmed as threat via dashboard', 'resolved');
    await db.update(socIncidents).set({ status: 'resolved', resolvedAt: dbNow() }).where(eq(socIncidents.id, id));
    res.send(`<tr><td colspan="5" style="color:var(--success);">Incident #${id} confirmed & resolved</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Incident confirm error');
    res.status(500).send(`<tr><td colspan="5" class="severity-critical">Error</td></tr>`);
  }
});

dashboardApi.post('/incidents/:id/false-positive', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await IncidentMemoryService.store(id, 'Marked as false positive via dashboard', 'false_positive');
    await db.update(socIncidents).set({ status: 'resolved', resolvedAt: dbNow() }).where(eq(socIncidents.id, id));
    FalsePositiveFilter.invalidateCache();
    res.send(`<tr><td colspan="5" style="color:var(--text-dim);">Incident #${id} — false positive (learned)</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Incident FP error');
    res.status(500).send(`<tr><td colspan="5" class="severity-critical">Error</td></tr>`);
  }
});

dashboardApi.get('/intelligence', async (_req, res) => {
  try {
    const [profileCount] = await db.select({ cnt: count() }).from(behaviorProfiles);
    const sshProfiles = await db.select({
      subjectId: behaviorProfiles.subjectId,
      sampleCount: behaviorProfiles.sampleCount,
      lastUpdated: behaviorProfiles.lastUpdatedAt,
    }).from(behaviorProfiles).where(eq(behaviorProfiles.profileType, 'ssh_user'));

    const containerProfiles = await db.select({
      subjectId: behaviorProfiles.subjectId,
      sampleCount: behaviorProfiles.sampleCount,
      lastUpdated: behaviorProfiles.lastUpdatedAt,
    }).from(behaviorProfiles).where(eq(behaviorProfiles.profileType, 'container'));

    const memoryStats = await IncidentMemoryService.getStats();

    const [latestMetric] = await db.select({ at: serverMetrics.collectedAt }).from(serverMetrics).orderBy(desc(serverMetrics.collectedAt)).limit(1);
    const [latestEvent] = await db.select({ at: securityEvents.timestamp }).from(securityEvents).orderBy(desc(securityEvents.timestamp)).limit(1);
    const [latestScore] = await db.select({ at: serverScores.periodEnd }).from(serverScores).orderBy(desc(serverScores.periodStart)).limit(1);

    const fimResult = await db.execute<{ last_fim: Date | null }>(sql`SELECT MAX(last_seen_at) as last_fim FROM file_baselines`);
    const latestFim = (fimResult.rows?.[0] as any)?.last_fim ?? null;

    const [cveResult] = await db.select({ at: cveAlerts.createdAt }).from(cveAlerts).orderBy(desc(cveAlerts.createdAt)).limit(1);
    const latestCve = cveResult?.at ?? null;

    const vulnResult = await db.execute<{ last_vuln: Date | null }>(sql`SELECT MAX(detected_at) as last_vuln FROM vulnerabilities`);
    const latestVuln = (vulnResult.rows?.[0] as any)?.last_vuln ?? null;

    const fmtTime = (d: Date | null | undefined) => d ? new Date(d).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }) : 'Nunca';
    const fmtAgo = (d: Date | null | undefined) => {
      if (!d) return '—';
      const mins = Math.floor((Date.now() - new Date(d).getTime()) / 60_000);
      if (mins < 1) return 'agora';
      if (mins < 60) return `${mins}min atrás`;
      return `${Math.floor(mins / 60)}h ${mins % 60}min atrás`;
    };

    const html = `
    <div style="display:grid;gap:1.5rem;">

      <!-- Data Freshness -->
      <div class="card">
        <div class="card-header"><span class="dot dot-green"></span> Frequência de Coleta & Última Atualização</div>
        <table style="width:100%;font-size:0.82rem;">
          <thead><tr><th>Sistema</th><th>Intervalo</th><th>Última Execução</th><th>Atualizado</th></tr></thead>
          <tbody>
            <tr><td>Coleta de Eventos (SSH/Docker/UFW)</td><td>2 minutos</td><td>${fmtTime(latestEvent?.at)}</td><td>${fmtAgo(latestEvent?.at)}</td></tr>
            <tr><td>Métricas (CPU/RAM/Disco)</td><td>5 minutos</td><td>${fmtTime(latestMetric?.at)}</td><td>${fmtAgo(latestMetric?.at)}</td></tr>
            <tr><td>Scores de Segurança</td><td>1 hora</td><td>${fmtTime(latestScore?.at)}</td><td>${fmtAgo(latestScore?.at)}</td></tr>
            <tr><td>ML — Perfis Comportamentais</td><td>1 hora</td><td>${fmtTime(sshProfiles[0]?.lastUpdated)}</td><td>${fmtAgo(sshProfiles[0]?.lastUpdated)}</td></tr>
            <tr><td>FIM — Baselines de Arquivo</td><td>4 horas</td><td>${fmtTime(latestFim)}</td><td>${fmtAgo(latestFim)}</td></tr>
            <tr><td>CVE Scanner</td><td>6 horas</td><td>${latestCve ? fmtTime(latestCve) : 'Nenhuma CVE encontrada'}</td><td>${latestCve ? fmtAgo(latestCve) : '<span style="color:var(--success)">Limpo</span>'}</td></tr>
            <tr><td>Vuln Scanner Completo</td><td>Semanal (sáb 09:00)</td><td>${latestVuln ? fmtTime(latestVuln) : 'Nenhuma vulnerabilidade encontrada'}</td><td>${latestVuln ? fmtAgo(latestVuln) : '<span style="color:var(--success)">Limpo</span>'}</td></tr>
          </tbody>
        </table>
      </div>

      <!-- ML Behavioral -->
      <div class="card">
        <div class="card-header"><span class="dot dot-cyan"></span> ML — Perfis Comportamentais</div>
        <p style="color:var(--text-muted);font-size:0.78rem;margin:0.5rem 0;">
          Guardian aprende o comportamento "normal" de cada usuário SSH e container.
          Quando algo foge do padrão (login em horário incomum, IP desconhecido, container usando mais recursos que o normal), gera um score de anomalia.
          <strong>Não é deep learning</strong> — é profiling estatístico incremental (média + desvio padrão) que melhora a cada hora.
        </p>
        <h4 style="margin:1rem 0 0.5rem;font-size:0.85rem;">Perfis SSH (${sshProfiles.length} usuários)</h4>
        ${sshProfiles.length > 0 ? `
        <table style="width:100%;font-size:0.8rem;">
          <thead><tr><th>Usuário</th><th>Amostras</th><th>Status</th><th>Última Atualização</th></tr></thead>
          <tbody>
            ${sshProfiles.map(p => `<tr>
              <td><code>${escapeHtml(p.subjectId)}</code></td>
              <td>${p.sampleCount}</td>
              <td>${p.sampleCount >= 30 ? '<span style="color:var(--success)">Maduro</span>' : p.sampleCount >= 5 ? '<span style="color:var(--warning)">Aprendendo</span>' : '<span style="color:var(--text-dim)">Coletando</span>'}</td>
              <td>${fmtAgo(p.lastUpdated)}</td>
            </tr>`).join('')}
          </tbody>
        </table>` : '<p style="color:var(--text-dim);font-size:0.8rem;">Nenhum perfil SSH ainda. O primeiro será criado após 10 min de operação.</p>'}

        <h4 style="margin:1rem 0 0.5rem;font-size:0.85rem;">Perfis de Container (${containerProfiles.length})</h4>
        ${containerProfiles.length > 0 ? `
        <table style="width:100%;font-size:0.8rem;">
          <thead><tr><th>Container</th><th>Amostras</th><th>Status</th><th>Última Atualização</th></tr></thead>
          <tbody>
            ${containerProfiles.map(p => `<tr>
              <td><code>${escapeHtml(p.subjectId)}</code></td>
              <td>${p.sampleCount}</td>
              <td>${p.sampleCount >= 5 ? '<span style="color:var(--success)">Ativo</span>' : '<span style="color:var(--text-dim)">Coletando</span>'}</td>
              <td>${fmtAgo(p.lastUpdated)}</td>
            </tr>`).join('')}
          </tbody>
        </table>` : '<p style="color:var(--text-dim);font-size:0.8rem;">Nenhum perfil de container ainda. Será criado no próximo ciclo (1h).</p>'}

        <div style="margin-top:1rem;padding:0.75rem;background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.15);border-radius:6px;font-size:0.78rem;">
          <strong>Como funciona o treinamento:</strong><br>
          1. A cada 1h, o IntelligenceWorker coleta dados dos últimos 30 dias<br>
          2. Calcula perfis: horários típicos de login, IPs conhecidos, fingerprints SSH<br>
          3. Para containers: CPU média, memória típica, frequência de restarts<br>
          4. Mínimo 5 amostras para começar a detectar anomalias, 30+ para perfil maduro<br>
          5. Score de anomalia (0-1): usa desvio padrão — quanto mais fora do padrão, maior o score
        </div>
      </div>

      <!-- RAG Memory -->
      <div class="card">
        <div class="card-header"><span class="dot dot-blue"></span> RAG — Memória de Incidentes</div>
        <p style="color:var(--text-muted);font-size:0.78rem;margin:0.5rem 0;">
          Quando um incidente é resolvido (confirmado ou marcado como falso positivo),
          Guardian salva na memória: o que aconteceu, como foi resolvido, e se era legítimo.
          Na próxima vez que algo similar acontece, a AI consulta essa memória para dar contexto melhor.
        </p>
        <table style="width:100%;font-size:0.82rem;">
          <tbody>
            <tr><td>Total de memórias</td><td><strong>${memoryStats.total}</strong></td></tr>
            <tr><td>Taxa de falso positivo</td><td><strong>${memoryStats.falsePositiveRate}%</strong></td></tr>
            <tr><td>Categorias aprendidas</td><td><strong>${Object.keys(memoryStats.byCategory).join(', ') || 'Nenhuma ainda'}</strong></td></tr>
          </tbody>
        </table>
        ${memoryStats.total === 0 ? `
        <div style="margin-top:0.75rem;padding:0.75rem;background:rgba(245,158,11,0.05);border:1px solid rgba(245,158,11,0.15);border-radius:6px;font-size:0.78rem;">
          <strong>RAG ainda vazio — é normal!</strong><br>
          Dados entram na memória quando você:<br>
          • Resolve um incidente via <code>/resolve</code> no Telegram<br>
          • Marca como falso positivo no dashboard (página Approvals)<br>
          • Confirma uma ameaça no dashboard<br>
          Quanto mais incidentes forem resolvidos, melhor Guardian fica em decidir o que é real vs. ruído.
        </div>` : ''}
      </div>

      <!-- GeoIP / Country -->
      <div class="card">
        <div class="card-header"><span class="dot dot-yellow"></span> GeoIP & Threat Intelligence</div>
        <p style="color:var(--text-muted);font-size:0.78rem;margin:0.5rem 0;">
          Country/GeoIP vem da API do AbuseIPDB. Só é consultado para IPs com severidade acima de "info"
          (ou seja, IPs que dispararam algum alerta de segurança real).
        </p>
        <table style="width:100%;font-size:0.82rem;">
          <tbody>
            <tr><td>Provedor de GeoIP</td><td>AbuseIPDB (gratuito: 1000 req/dia)</td></tr>
            <tr><td>Quando consulta</td><td>Quando um evento com <code>severity != info</code> tem um IP de origem</td></tr>
            <tr><td>Por que country está vazio</td><td>Todos os logins são de IPs confiáveis (seu próprio IP). Quando IPs maliciosos atacarem, o country aparecerá automaticamente.</td></tr>
            <tr><td>AbuseIPDB configurado?</td><td>${config.threatIntel.abuseIpDbKey ? '<span style="color:var(--success)">Sim</span>' : '<span style="color:var(--warning)">Não — configure ABUSEIPDB_API_KEY para enriquecer IPs</span>'}</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Anomaly Detection -->
      <div class="card">
        <div class="card-header"><span class="dot dot-green"></span> Detecção de Anomalias</div>
        <p style="color:var(--text-muted);font-size:0.78rem;margin:0.5rem 0;">
          Usa z-score (desvio padrão) sobre 7 dias de métricas. Requer mínimo 10 amostras de métrica.
        </p>
        <table style="width:100%;font-size:0.82rem;">
          <thead><tr><th>Métrica Monitorada</th><th>Threshold</th><th>O que detecta</th></tr></thead>
          <tbody>
            <tr><td>Load ratio (load/cores)</td><td>&gt; 2.5σ</td><td>Picos de CPU incomuns</td></tr>
            <tr><td>Memória usada %</td><td>&gt; 2.5σ</td><td>Memory leaks, processos anormais</td></tr>
            <tr><td>Disco max %</td><td>&gt; 2.5σ</td><td>Crescimento acelerado de disco</td></tr>
            <tr><td>Kernel errors</td><td>&gt; 2.5σ</td><td>Hardware/driver problems</td></tr>
            <tr><td>Journal errors</td><td>&gt; 2.5σ</td><td>Serviços falhando excessivamente</td></tr>
          </tbody>
        </table>
        <p style="color:var(--text-dim);font-size:0.75rem;margin-top:0.5rem;">
          Status atual: ${profileCount.cnt >= 10 ? '<span style="color:var(--success)">Dados suficientes para detecção</span>' : `<span style="color:var(--warning)">${profileCount.cnt} amostras — precisa de 10+ para começar a detectar</span>`}
        </p>
      </div>

      <!-- CVE Intel Feeds — EPSS & KEV -->
      ${await (async () => {
        try {
          const topEpss = await db.select().from(cveEpss)
            .orderBy(desc(cveEpss.epssScore))
            .limit(5);
          const [kevCount] = await db.select({ cnt: count() }).from(cveKev);
          const [latestEpss] = await db.select({ at: cveEpss.fetchedAt }).from(cveEpss).orderBy(desc(cveEpss.fetchedAt)).limit(1);
          const [latestKev] = await db.select({ at: cveKev.fetchedAt }).from(cveKev).orderBy(desc(cveKev.fetchedAt)).limit(1);

          if (topEpss.length === 0 && kevCount.cnt === 0) {
            return `
              <div class="card">
                <div class="card-header"><span class="dot dot-yellow"></span> CVE Intel Feeds — EPSS & CISA KEV</div>
                <p style="color:var(--text-dim);font-size:0.8rem;">
                  Feeds não populados ainda. Configure <code>CVE_INTEL_FEEDS_ENABLED=true</code> e aguarde o próximo ciclo, ou use o botão "Recalcular Agora" acima.
                </p>
              </div>`;
          }

          const epssRows = topEpss.map(e => {
            const pct = (e.epssScore * 100).toFixed(2);
            const barWidth = Math.round(e.epssScore * 100);
            const color = e.epssScore >= 0.5 ? 'var(--critical)' : e.epssScore >= 0.1 ? 'var(--warning)' : 'var(--primary-bright)';
            return `<tr>
              <td><code style="font-size:0.78rem;">${escapeHtml(e.cveId)}</code></td>
              <td>
                <div style="display:flex;align-items:center;gap:0.5rem;">
                  <div style="background:${color};height:6px;width:${Math.max(barWidth, 2)}px;max-width:120px;border-radius:3px;"></div>
                  <span style="font-family:var(--font-mono);font-size:0.78rem;color:${color};">${pct}%</span>
                </div>
              </td>
              <td style="font-size:0.72rem;color:var(--text-dim);">${e.fetchedAt ? fmtAgo(e.fetchedAt) : '—'}</td>
            </tr>`;
          }).join('');

          return `
            <div class="card">
              <div class="card-header"><span class="dot dot-yellow"></span> CVE Intel Feeds — EPSS & CISA KEV</div>
              <p style="color:var(--text-muted);font-size:0.78rem;margin:0.5rem 0 1rem;">
                <strong>EPSS</strong>: probabilidade de exploração nos próximos 30 dias (0–100%).
                <strong>KEV</strong>: lista CISA de CVEs com exploração ativa confirmada em produção.
              </p>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem;">
                <div class="kpi kpi-yellow">
                  <div class="kpi-label">CVEs no CISA KEV</div>
                  <div class="kpi-value kpi-value-yellow">${kevCount.cnt}</div>
                  <div style="font-size:0.7rem;color:var(--text-dim);margin-top:0.25rem;">${latestKev?.at ? 'Atualizado ' + fmtAgo(latestKev.at) : 'Nunca'}</div>
                </div>
                <div class="kpi kpi-red">
                  <div class="kpi-label">CVEs com EPSS</div>
                  <div class="kpi-value kpi-value-red">${topEpss.length > 0 ? '✓' : '0'}</div>
                  <div style="font-size:0.7rem;color:var(--text-dim);margin-top:0.25rem;">${latestEpss?.at ? 'Atualizado ' + fmtAgo(latestEpss.at) : 'Nunca'}</div>
                </div>
              </div>
              ${topEpss.length > 0 ? `
                <h4 style="font-size:0.82rem;margin-bottom:0.5rem;color:var(--text-muted);">Top 5 CVEs por EPSS (maior risco de exploração)</h4>
                <table style="width:100%;font-size:0.82rem;">
                  <thead><tr><th>CVE</th><th>Probabilidade EPSS</th><th>Atualizado</th></tr></thead>
                  <tbody>${epssRows}</tbody>
                </table>` : ''}
            </div>`;
        } catch {
          return '';
        }
      })()}

    </div>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Intelligence API error');
    res.status(500).send('<p class="severity-critical">Erro ao carregar dados de inteligência</p>');
  }
});

dashboardApi.post('/run-workers', async (_req, res) => {
  const token = config.dashboard.token || '';
  try {
    await ScoreCalculatorWorker.computeScores();
    await IntelligenceWorker.run();
    await CVEMonitorWorker.run();

    res.send(`<button disabled style="border-color:var(--success);color:var(--success);cursor:default;">
      &#10003; Atualizado — <a href="/dashboard/intelligence?token=${token}" style="color:var(--success);text-decoration:underline;">Recarregar</a>
    </button>`);
  } catch (err) {
    logger.error({ err }, 'Run workers error');
    res.send(`<button disabled style="border-color:var(--critical);color:var(--critical);cursor:default;">
      &#10007; Erro ao recalcular
    </button>`);
  }
});

dashboardApi.post('/admin/trigger/cve-intel-feeds', requireRole('admin'), (_req, res) => {
  CVEIntelFeedsWorker.run().catch(err =>
    logger.error({ err }, 'Manual CVE intel feeds trigger failed')
  );
  res.status(202).json({
    status: 'triggered',
    message: 'CVE intel feeds ingest started in background — check logs for progress',
  });
});

// ─── Container Alert Description Helper ──────────────────────────────────────

interface AlertDescription {
  icon: string;
  title: string;
  description: string;
  extraTag: string;
  actions: string;
}

function describeContainerAlert(
  eventType: string,
  containerName: string,
  serverName: string,
  meta: Record<string, unknown> | null,
): AlertDescription {
  const token = config.dashboard.token || '';
  const safeContainer = encodeURIComponent(containerName);

  switch (eventType) {
    case 'container_crypto_process':
      return {
        icon: '&#9888;&#65039;',
        title: 'Minerador de Cripto Detectado',
        description: `Processo de mineracao (${escapeHtml((meta?.command as string) ?? 'xmrig/similar')}) rodando dentro do container. Guardian ja matou o processo e reiniciou o container automaticamente.`,
        extraTag: meta?.command ? `<code style="font-size:0.7rem;color:var(--critical);">${escapeHtml(String(meta.command).slice(0, 40))}</code>` : '',
        actions: `
          <button class="danger" style="font-size:0.72rem;padding:3px 8px;"
            hx-post="/api/dashboard/containers/restart?token=${token}&container=${safeContainer}&server=${encodeURIComponent(serverName)}"
            hx-confirm="Reiniciar '${escapeHtml(containerName)}'? Isso vai parar e recriar o container."
            hx-target="closest div[style]"
            hx-swap="outerHTML">&#8635; Reiniciar</button>
          <button style="font-size:0.72rem;padding:3px 8px;"
            hx-post="/api/dashboard/containers/disconnect?token=${token}&container=${safeContainer}&server=${encodeURIComponent(serverName)}"
            hx-confirm="Isolar '${escapeHtml(containerName)}' da rede? O container continuara rodando mas sem acesso externo."
            hx-target="closest div[style]"
            hx-swap="outerHTML">&#128274; Isolar Rede</button>`,
      };

    case 'container_mining_network':
      return {
        icon: '&#128279;',
        title: 'Conexao com Pool de Mineracao',
        description: `Container conectado a porta de mining pool (${meta?.remotePort ?? 'desconhecida'}). Isso indica que um minerador esta ativo e exfiltrando. Guardian isolou o container da rede.`,
        extraTag: meta?.remoteIp ? `<span class="ip-tag">${escapeHtml(String(meta.remoteIp))}:${meta.remotePort ?? ''}</span>` : '',
        actions: `
          <button class="danger" style="font-size:0.72rem;padding:3px 8px;"
            hx-post="/api/dashboard/containers/restart?token=${token}&container=${safeContainer}&server=${encodeURIComponent(serverName)}"
            hx-confirm="Reiniciar '${escapeHtml(containerName)}'?"
            hx-target="closest div[style]"
            hx-swap="outerHTML">&#8635; Reiniciar</button>
          <button style="font-size:0.72rem;padding:3px 8px;"
            hx-post="/api/dashboard/containers/kill-procs?token=${token}&container=${safeContainer}&server=${encodeURIComponent(serverName)}"
            hx-confirm="Matar processos suspeitos dentro de '${escapeHtml(containerName)}'?"
            hx-target="closest div[style]"
            hx-swap="outerHTML">&#9760; Kill Procs</button>`,
      };

    case 'container_suspicious_exec':
      return {
        icon: '&#128065;',
        title: 'Execucao Suspeita em Container',
        description: `Processo iniciado de caminho suspeito (/tmp, /dev/shm) dentro do container. Pode indicar exploit ou backdoor. Investigue o processo antes de tomar acao.`,
        extraTag: meta?.command ? `<code style="font-size:0.7rem;">${escapeHtml(String(meta.command).slice(0, 50))}</code>` : '',
        actions: `
          <button class="danger" style="font-size:0.72rem;padding:3px 8px;"
            hx-post="/api/dashboard/containers/kill-procs?token=${token}&container=${safeContainer}&server=${encodeURIComponent(serverName)}"
            hx-confirm="Matar processos suspeitos dentro de '${escapeHtml(containerName)}'?"
            hx-target="closest div[style]"
            hx-swap="outerHTML">&#9760; Kill Procs</button>
          <button style="font-size:0.72rem;padding:3px 8px;"
            hx-post="/api/dashboard/containers/disconnect?token=${token}&container=${safeContainer}&server=${encodeURIComponent(serverName)}"
            hx-confirm="Isolar '${escapeHtml(containerName)}' da rede?"
            hx-target="closest div[style]"
            hx-swap="outerHTML">&#128274; Isolar</button>`,
      };

    case 'container_fs_tampering':
      return {
        icon: '&#128193;',
        title: 'Arquivo Suspeito Criado em Container',
        description: `Novo binario ou arquivo detectado em caminho suspeito (${escapeHtml((meta?.filePath as string) ?? '/tmp ou /dev/shm')}). Se o container deveria ser imutavel, isso e anomalo.`,
        extraTag: meta?.filePath ? `<code style="font-size:0.7rem;">${escapeHtml(String(meta.filePath).slice(0, 60))}</code>` : '',
        actions: `
          <button style="font-size:0.72rem;padding:3px 8px;"
            hx-post="/api/dashboard/containers/restart?token=${token}&container=${safeContainer}&server=${encodeURIComponent(serverName)}"
            hx-confirm="Reiniciar '${escapeHtml(containerName)}'? Isso descarta alteracoes no filesystem."
            hx-target="closest div[style]"
            hx-swap="outerHTML">&#8635; Reiniciar (descarta mudancas)</button>`,
      };

    case 'container_critical_cve':
      return {
        icon: '&#128736;',
        title: 'CVE Critica em Imagem Docker',
        description: `Vulnerabilidade critica (CVSS >= 9.0) encontrada na imagem deste container. Se existe fix disponivel, atualize a imagem o mais rapido possivel.`,
        extraTag: meta?.cveId ? `<code style="font-size:0.7rem;color:var(--critical);">${escapeHtml(String(meta.cveId))}</code>` : '',
        actions: `
          <button class="success" style="font-size:0.72rem;padding:3px 8px;"
            hx-post="/api/dashboard/containers/update-image?token=${token}&container=${safeContainer}&server=${encodeURIComponent(serverName)}"
            hx-confirm="Atualizar imagem de '${escapeHtml(containerName)}'? Vai puxar a ultima versao e recriar o container."
            hx-target="closest div[style]"
            hx-swap="outerHTML">&#8635; Atualizar Imagem</button>`,
      };

    case 'container_insecure_config':
      return {
        icon: '&#9881;',
        title: 'Container Sem Hardening',
        description: `Container rodando sem protecoes basicas (read_only, cap_drop, no-new-privileges). Nao requer acao imediata, mas deve ser corrigido no docker-compose.yml.`,
        extraTag: '',
        actions: '',
      };

    default:
      return {
        icon: '&#128196;',
        title: eventType.replace(/_/g, ' '),
        description: `Evento de seguranca de container. Verifique os logs para mais detalhes.`,
        extraTag: '',
        actions: '',
      };
  }
}

// ─── Container Security Dashboard API ──────────────────────────────────────

dashboardApi.get('/containers', async (_req, res) => {
  try {
    // Get all container snapshots joined with server names
    const snapshots = await db.select({
      id: containerSnapshots.id,
      serverId: containerSnapshots.serverId,
      containerName: containerSnapshots.containerName,
      imageName: containerSnapshots.imageName,
      processes: containerSnapshots.processes,
      network: containerSnapshots.network,
      filesystemChanges: containerSnapshots.filesystemChanges,
      securityConfig: containerSnapshots.securityConfig,
      cveCount: containerSnapshots.cveCount,
      status: containerSnapshots.status,
      collectedAt: containerSnapshots.collectedAt,
      serverName: socServers.name,
    })
      .from(containerSnapshots)
      .leftJoin(socServers, eq(containerSnapshots.serverId, socServers.id))
      .orderBy(desc(containerSnapshots.collectedAt))
      .limit(200);

    // Get container-related security events (last 24h)
    const containerAlerts = await db.select()
      .from(securityEvents)
      .where(and(
        gte(securityEvents.timestamp, new Date(Date.now() - 24 * 60 * 60 * 1000)),
        sql`${securityEvents.source} LIKE 'container_%'`,
        ne(securityEvents.severity, 'info'),
      ))
      .orderBy(desc(securityEvents.timestamp))
      .limit(50);

    // Get container image CVE alerts
    const imageCves = await db.select()
      .from(cveAlerts)
      .where(eq(cveAlerts.ecosystem, 'docker'))
      .orderBy(desc(cveAlerts.createdAt))
      .limit(20);

    if (snapshots.length === 0 && containerAlerts.length === 0) {
      res.send(`
        <div class="card" style="text-align:center;padding:3rem;">
          <p style="font-size:1.5rem;margin-bottom:0.5rem;">&#128230;</p>
          <p style="color:var(--text-muted);">No container data collected yet.</p>
          <p style="color:var(--text-dim);font-size:0.8rem;margin-top:0.5rem;">
            Container process monitoring starts on next collection cycle (every 2 minutes).
          </p>
        </div>
      `);
      return;
    }

    // Calculate KPIs
    const totalContainers = snapshots.length;
    const hardened = snapshots.filter(s => {
      const cfg = s.securityConfig as { readOnly?: boolean; capDrop?: string[] } | null;
      return cfg && (cfg.readOnly || (cfg.capDrop && cfg.capDrop.length > 0));
    }).length;
    const insecure = totalContainers - hardened;
    const hardenedPct = totalContainers > 0 ? Math.round((hardened / totalContainers) * 100) : 0;
    const alertCount24h = containerAlerts.length;
    const criticalCves = imageCves.filter(c => (c.cvssScore ?? 0) >= 90).length;

    // ── KPI Cards ──
    let html = `
    <div class="kpi-grid" style="margin-bottom:1.5rem;">
      <div class="card">
        <div class="card-header"><span class="dot dot-blue"></span> Total Containers</div>
        <div style="font-size:1.8rem;font-weight:700;font-family:var(--font-mono);">${totalContainers}</div>
        <div style="color:var(--text-dim);font-size:0.75rem;">Across ${new Set(snapshots.map(s => s.serverId)).size} servers</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="dot dot-green"></span> Hardened</div>
        <div style="font-size:1.8rem;font-weight:700;font-family:var(--font-mono);color:var(--success);">${hardened}</div>
        <div style="color:var(--text-dim);font-size:0.75rem;">${hardenedPct}% of fleet</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="dot dot-yellow"></span> Insecure</div>
        <div style="font-size:1.8rem;font-weight:700;font-family:var(--font-mono);color:${insecure > 0 ? 'var(--warning)' : 'var(--text-dim)'};">${insecure}</div>
        <div style="color:var(--text-dim);font-size:0.75rem;">Missing hardening</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="dot dot-red"></span> Critical CVEs</div>
        <div style="font-size:1.8rem;font-weight:700;font-family:var(--font-mono);color:${criticalCves > 0 ? 'var(--critical)' : 'var(--text-dim)'};">${criticalCves}</div>
        <div style="color:var(--text-dim);font-size:0.75rem;">In running images</div>
      </div>
      <div class="card">
        <div class="card-header"><span class="dot ${alertCount24h > 0 ? 'dot-red' : 'dot-cyan'}"></span> Alerts (24h)</div>
        <div style="font-size:1.8rem;font-weight:700;font-family:var(--font-mono);color:${alertCount24h > 0 ? 'var(--critical)' : 'var(--success)'};">${alertCount24h}</div>
        <div style="color:var(--text-dim);font-size:0.75rem;">Security events</div>
      </div>
    </div>`;

    // ── Container Fleet Table ──
    const token = config.dashboard.token || '';
    html += `
    <div class="card" style="margin-bottom:1.5rem;">
      <div class="card-header"><span class="dot dot-cyan"></span> Container Fleet</div>
      <p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:0.75rem;">
        Todos os containers em execucao. Use as acoes para intervir diretamente.
      </p>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Server</th>
              <th>Container</th>
              <th>Image</th>
              <th>Procs</th>
              <th>Net</th>
              <th>Config</th>
              <th>Ultimo</th>
              <th>Acoes</th>
            </tr>
          </thead>
          <tbody>`;

    for (const snap of snapshots) {
      const procs = (snap.processes as Array<unknown>) ?? [];
      const conns = (snap.network as Array<unknown>) ?? [];
      const cfg = snap.securityConfig as { readOnly?: boolean; noNewPrivs?: boolean; capDrop?: string[] } | null;

      let configBadge: string;
      if (cfg && cfg.readOnly && cfg.noNewPrivs) {
        configBadge = '<span style="color:var(--success);" title="read_only + no-new-privileges + cap_drop">&#10003; Hardened</span>';
      } else if (cfg && (cfg.readOnly || (cfg.capDrop && cfg.capDrop.length > 0))) {
        configBadge = '<span style="color:var(--warning);" title="Parcialmente protegido — faltam configs">&#9888; Parcial</span>';
      } else if (cfg) {
        configBadge = '<span style="color:var(--critical);" title="Sem protecoes de security — veja recomendacoes abaixo">&#10007; Inseguro</span>';
      } else {
        configBadge = '<span style="color:var(--text-dim);">—</span>';
      }

      const imageShort = (snap.imageName ?? '').split('/').pop()?.slice(0, 30) ?? '—';
      const lastSeen = snap.collectedAt ? new Date(snap.collectedAt).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }) : '—';
      const safeContainer = encodeURIComponent(snap.containerName);
      const safeServer = encodeURIComponent(snap.serverName ?? '');

      html += `
            <tr id="fleet-${safeContainer}">
              <td><code>${escapeHtml(snap.serverName ?? `#${snap.serverId}`)}</code></td>
              <td><strong>${escapeHtml(snap.containerName)}</strong></td>
              <td style="color:var(--text-muted);font-size:0.78rem;" title="${escapeHtml(snap.imageName ?? '')}">${escapeHtml(imageShort)}</td>
              <td style="text-align:center;" title="${procs.length} processos rodando">${procs.length}</td>
              <td style="text-align:center;" title="${conns.length} conexoes de rede ativas">${conns.length}</td>
              <td>${configBadge}</td>
              <td style="color:var(--text-dim);font-size:0.78rem;">${lastSeen}</td>
              <td style="white-space:nowrap;">
                <button style="font-size:0.68rem;padding:2px 6px;" title="Reiniciar container (para limpar processos maliciosos)"
                  hx-post="/api/dashboard/containers/restart?token=${token}&container=${safeContainer}&server=${safeServer}"
                  hx-confirm="Reiniciar '${escapeHtml(snap.containerName)}'?"
                  hx-target="#fleet-${safeContainer}"
                  hx-swap="outerHTML">&#8635;</button>
                <button style="font-size:0.68rem;padding:2px 6px;" title="Isolar da rede (corta todas conexoes externas)"
                  hx-post="/api/dashboard/containers/disconnect?token=${token}&container=${safeContainer}&server=${safeServer}"
                  hx-confirm="Isolar '${escapeHtml(snap.containerName)}' da rede?"
                  hx-target="#fleet-${safeContainer}"
                  hx-swap="outerHTML">&#128274;</button>
              </td>
            </tr>`;
    }

    html += `
          </tbody>
        </table>
      </div>
    </div>`;

    // ── Security Alerts (last 24h) ──
    if (containerAlerts.length > 0) {
      html += `
      <div class="card" style="margin-bottom:1.5rem;">
        <div class="card-header"><span class="dot dot-red"></span> Security Alerts (24h)</div>
        <div style="display:grid;gap:0.75rem;margin-top:0.5rem;">`;

      for (const alert of containerAlerts.slice(0, 15)) {
        const time = new Date(alert.timestamp).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
        const serverName = snapshots.find(s => s.serverId === alert.serverId)?.serverName ?? `#${alert.serverId}`;
        const meta = alert.metadata as Record<string, unknown> | null;
        const containerName = (meta?.containerName as string) ?? alert.processName ?? '—';
        const alertInfo = describeContainerAlert(alert.eventType, containerName, serverName, meta);
        const borderColor = alert.severity === 'critical' ? 'rgba(239,68,68,0.4)' : 'rgba(245,158,11,0.3)';
        const bgColor = alert.severity === 'critical' ? 'rgba(239,68,68,0.04)' : 'rgba(245,158,11,0.03)';

        html += `
          <div style="background:${bgColor};border:1px solid ${borderColor};border-radius:var(--radius-sm);padding:1rem;">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
              <div style="flex:1;min-width:200px;">
                <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.4rem;">
                  <span style="font-size:1.1rem;">${alertInfo.icon}</span>
                  <strong class="severity-${alert.severity}" style="font-size:0.88rem;">${alertInfo.title}</strong>
                  <span style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-dim);">${time}</span>
                </div>
                <p style="color:var(--text-muted);font-size:0.82rem;margin-bottom:0.4rem;line-height:1.5;">${alertInfo.description}</p>
                <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
                  <code style="font-size:0.72rem;">${escapeHtml(serverName)}</code>
                  <span style="color:var(--text-dim);">&rarr;</span>
                  <code style="font-size:0.72rem;">${escapeHtml(containerName)}</code>
                  ${alertInfo.extraTag}
                </div>
              </div>
              <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:flex-start;">
                ${alertInfo.actions}
              </div>
            </div>
          </div>`;
      }

      html += `
        </div>
      </div>`;
    }

    // ── Image CVEs ──
    if (imageCves.length > 0) {
      html += `
      <div class="card" style="margin-bottom:1.5rem;">
        <div class="card-header"><span class="dot dot-yellow"></span> Image Vulnerabilities</div>
        <p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:1rem;">
          CVEs encontradas em imagens Docker em uso. Imagens com fix disponivel podem ser atualizadas automaticamente.
        </p>
        <div style="overflow-x:auto;">
          <table>
            <thead>
              <tr><th>Image/Package</th><th>CVE</th><th>CVSS</th><th>Instalada</th><th>Fix</th><th>Acao</th></tr>
            </thead>
            <tbody>`;

      for (const cve of imageCves) {
        const cvssVal = (cve.cvssScore ?? 0) / 10;
        const cvssColor = cvssVal >= 9 ? 'var(--critical)' : cvssVal >= 7 ? 'var(--warning)' : 'var(--text-muted)';
        const hasFixAvailable = !!cve.fixedVersion;

        html += `
              <tr>
                <td><code>${escapeHtml(cve.packageName)}</code></td>
                <td style="font-family:var(--font-mono);font-size:0.78rem;">${escapeHtml(cve.cveId)}</td>
                <td style="color:${cvssColor};font-weight:600;">${cvssVal.toFixed(1)}</td>
                <td style="font-size:0.78rem;">${escapeHtml(cve.installedVersion ?? '—')}</td>
                <td style="font-size:0.78rem;color:${hasFixAvailable ? 'var(--success)' : 'var(--text-dim)'};">
                  ${hasFixAvailable ? `&#10003; ${escapeHtml(cve.fixedVersion!)}` : 'Sem fix'}
                </td>
                <td>
                  ${hasFixAvailable && cve.status !== 'resolved'
                    ? `<button class="success" style="font-size:0.72rem;padding:3px 8px;"
                        hx-post="/api/dashboard/containers/update-image?token=${token}&cveId=${encodeURIComponent(cve.cveId)}&serverId=${cve.serverId}&pkg=${encodeURIComponent(cve.packageName)}"
                        hx-confirm="Atualizar imagem para corrigir ${escapeHtml(cve.cveId)}? Isso vai recriar o container."
                        hx-target="closest tr"
                        hx-swap="outerHTML">
                        &#8635; Atualizar</button>`
                    : cve.status === 'resolved'
                      ? '<span style="color:var(--success);font-size:0.78rem;">&#10003; Resolvido</span>'
                      : '<span style="color:var(--text-dim);font-size:0.78rem;">Aguardando fix</span>'}
                </td>
              </tr>`;
      }

      html += `
            </tbody>
          </table>
        </div>
      </div>`;
    }

    // ── Insecure Containers (recommendations) ──
    const insecureContainers = snapshots.filter(s => {
      const cfg = s.securityConfig as { readOnly?: boolean; capDrop?: string[] } | null;
      return cfg && !cfg.readOnly && (!cfg.capDrop || cfg.capDrop.length === 0);
    });

    if (insecureContainers.length > 0) {
      html += `
      <div class="card">
        <div class="card-header"><span class="dot dot-yellow"></span> Hardening Recommendations</div>
        <p style="color:var(--text-muted);font-size:0.8rem;margin-bottom:1rem;">
          Containers abaixo estao rodando sem protecoes basicas. Adicione as configs no docker-compose.yml ou docker run.
        </p>
        <div style="display:grid;gap:0.75rem;">`;

      for (const c of insecureContainers.slice(0, 10)) {
        const cfg = c.securityConfig as { readOnly?: boolean; noNewPrivs?: boolean; capDrop?: string[]; memoryLimit?: number } | null;
        const fixes: Array<{ label: string; compose: string }> = [];
        if (!cfg?.readOnly) fixes.push({ label: 'Filesystem gravavel', compose: 'read_only: true' });
        if (!cfg?.noNewPrivs) fixes.push({ label: 'Permite escalacao', compose: 'security_opt: [no-new-privileges:true]' });
        if (!cfg?.capDrop || cfg.capDrop.length === 0) fixes.push({ label: 'Capabilities abertas', compose: 'cap_drop: [ALL]' });
        if (!cfg?.memoryLimit) fixes.push({ label: 'Sem limite de memoria', compose: 'mem_limit: 512m' });

        html += `
          <div style="background:rgba(245,158,11,0.05);border:1px solid rgba(245,158,11,0.2);border-radius:var(--radius-sm);padding:1rem;">
            <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;">
              <span style="font-size:1rem;">&#9888;</span>
              <strong style="color:var(--warning);">${escapeHtml(c.containerName)}</strong>
              <code style="font-size:0.72rem;color:var(--text-dim);">${escapeHtml(c.serverName ?? '')}</code>
            </div>
            <div style="display:grid;gap:0.3rem;">
              ${fixes.map(f => `
                <div style="display:flex;align-items:center;gap:0.5rem;">
                  <span style="color:var(--critical);font-size:0.8rem;">&#10007;</span>
                  <span style="color:var(--text-muted);font-size:0.8rem;">${f.label}</span>
                  <span style="color:var(--text-dim);font-size:0.7rem;">&rarr;</span>
                  <code style="font-size:0.72rem;color:var(--cyan);">${f.compose}</code>
                </div>
              `).join('')}
            </div>
          </div>`;
      }

      html += `
        </div>
      </div>`;
    }

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Containers dashboard API error');
    res.status(500).send('<p class="severity-critical">Error loading container security data</p>');
  }
});

// ─── Container Action Endpoints ──────────────────────────────────────────────

async function resolveServerCtx(serverName: string, container: string): Promise<PlaybookContext | null> {
  const servers = await ServerService.getEnabled();
  const server = servers.find(s => s.name === serverName);
  if (!server) return null;
  return {
    serverId: server.id,
    serverName: server.name,
    sourceIp: undefined,
    triggeredBy: 'dashboard:manual',
    variables: { containerName: container },
  };
}

function actionResultHtml(success: boolean, message: string): string {
  if (success) {
    return `
      <div style="background:rgba(34,197,94,0.06);border:1px solid rgba(34,197,94,0.3);border-radius:var(--radius-sm);padding:1rem;text-align:center;">
        <span style="color:var(--success);font-size:1.1rem;">&#10003;</span>
        <strong style="color:var(--success);margin-left:0.5rem;">${escapeHtml(message)}</strong>
      </div>`;
  }
  return `
    <div style="background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius-sm);padding:1rem;text-align:center;">
      <span style="color:var(--critical);font-size:1.1rem;">&#10007;</span>
      <strong style="color:var(--critical);margin-left:0.5rem;">${escapeHtml(message)}</strong>
    </div>`;
}

dashboardApi.post('/containers/restart', async (req, res) => {
  const container = req.query.container as string;
  const serverName = req.query.server as string;
  if (!container || !serverName) {
    res.status(400).send(actionResultHtml(false, 'Parametros invalidos'));
    return;
  }

  const ctx = await resolveServerCtx(serverName, container);
  if (!ctx) {
    res.status(404).send(actionResultHtml(false, `Servidor '${serverName}' nao encontrado`));
    return;
  }

  const result = await restartContainer(ctx);
  res.send(actionResultHtml(result.success, result.message));
});

dashboardApi.post('/containers/disconnect', async (req, res) => {
  const container = req.query.container as string;
  const serverName = req.query.server as string;
  if (!container || !serverName) {
    res.status(400).send(actionResultHtml(false, 'Parametros invalidos'));
    return;
  }

  const ctx = await resolveServerCtx(serverName, container);
  if (!ctx) {
    res.status(404).send(actionResultHtml(false, `Servidor '${serverName}' nao encontrado`));
    return;
  }

  const result = await disconnectContainer(ctx);
  res.send(actionResultHtml(result.success, result.message));
});

dashboardApi.post('/containers/kill-procs', async (req, res) => {
  const container = req.query.container as string;
  const serverName = req.query.server as string;
  if (!container || !serverName) {
    res.status(400).send(actionResultHtml(false, 'Parametros invalidos'));
    return;
  }

  const ctx = await resolveServerCtx(serverName, container);
  if (!ctx) {
    res.status(404).send(actionResultHtml(false, `Servidor '${serverName}' nao encontrado`));
    return;
  }

  const result = await killContainerProcess(ctx);
  res.send(actionResultHtml(result.success, result.message));
});

dashboardApi.post('/containers/update-image', async (req, res) => {
  const container = req.query.container as string;
  const serverName = req.query.server as string;
  if (!container || !serverName) {
    res.status(400).send(actionResultHtml(false, 'Parametros invalidos'));
    return;
  }

  const ctx = await resolveServerCtx(serverName, container);
  if (!ctx) {
    res.status(404).send(actionResultHtml(false, `Servidor '${serverName}' nao encontrado`));
    return;
  }

  const pullResult = await pullContainerImage(ctx);
  if (!pullResult.success) {
    res.send(actionResultHtml(false, pullResult.message));
    return;
  }

  const recreateResult = await recreateContainer(ctx);
  res.send(actionResultHtml(recreateResult.success,
    recreateResult.success
      ? `Imagem atualizada e container recriado: ${container}`
      : recreateResult.message
  ));
});