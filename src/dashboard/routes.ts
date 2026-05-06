import { Router } from 'express';
import { db, dbFalse, dbNow } from '../database/connection.js';
import { socServers, securityEvents, socIncidents, blockedIps, cveAlerts, serverMetrics, serverScores, behaviorProfiles } from '../database/schema.js';
import { IntelligenceWorker } from '../workers/intelligence.worker.js';
import { ScoreCalculatorWorker } from '../workers/score-calculator.worker.js';
import { CVEMonitorWorker } from '../workers/cve-monitor.worker.js';
import { eq, count, desc, and, gte, ne, sql } from 'drizzle-orm';
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

    const serverList = await db.select({ name: socServers.name, lastSeen: socServers.lastSeenAt })
      .from(socServers)
      .where(eq(socServers.enabled, true));

    const content = overviewPage({
      servers: serversCount.cnt,
      openIncidents: openCount.cnt,
      blockedIps: blockedCount.cnt,
      pendingCves: cveCount.cnt,
      eventsToday: eventsCount.cnt,
      overallScore,
      serverList: serverList.map(s => ({ name: s.name, lastSeen: s.lastSeen })),
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
    <div id="cve-list" hx-get="/api/dashboard/cve-alerts?token=${token}" hx-trigger="load" hx-swap="innerHTML">
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
    <h2>Intelligence & Learning</h2>
    <p style="color:var(--text-muted);font-size:0.82rem;margin-bottom:1.5rem;">
      How Guardian learns, when it updates, and what data feeds each system.
    </p>
    <div hx-get="/api/dashboard/intelligence?token=${token}" hx-trigger="load" hx-swap="innerHTML">
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
  `;
  res.send(layout('Approvals', content));
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
      const ipTag = e.sourceIp ? ` <span class="ip-tag">${escapeHtml(e.sourceIp)}</span>` : '';
      const name = serverName || `Server #${e.serverId}`;
      return `<div class="threat-item">
        <span class="threat-icon">${icon}</span>
        <div style="flex:1">
          <div style="font-size:0.82rem;"><span class="severity-${e.severity}">${escapeHtml(e.eventType.replace(/_/g, ' '))}</span>${ipTag}</div>
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

dashboardApi.get('/cve-alerts', async (_req, res) => {
  try {
    const alerts = await db.select().from(cveAlerts)
      .where(eq(cveAlerts.status, 'pending'))
      .orderBy(desc(cveAlerts.createdAt))
      .limit(50);

    if (alerts.length === 0) {
      res.send('<p style="color:var(--success);">&#9989; No pending CVE alerts.</p>');
      return;
    }

    const token = config.dashboard.token || '';
    const html = `<table><thead><tr><th>CVE</th><th>Package</th><th>CVSS</th><th>Fix Available</th><th>Actions</th></tr></thead><tbody>${
      alerts.map(a => {
        const cvss = a.cvssScore ? (a.cvssScore / 10).toFixed(1) : '?';
        const cvssNum = Number(cvss);
        const cvssClass = cvssNum >= 9 ? 'severity-critical' : cvssNum >= 7 ? 'severity-high' : 'severity-medium';
        const actions = [
          a.fixedVersion ? `<button hx-post="/api/dashboard/cve/${a.id}/update?token=${token}" hx-swap="outerHTML" hx-target="closest tr" class="success">Patch</button>` : '',
          `<button hx-post="/api/dashboard/cve/${a.id}/ignore?token=${token}" hx-swap="outerHTML" hx-target="closest tr" class="danger">Ignore</button>`,
        ].filter(Boolean).join(' ');
        return `<tr>
          <td><code>${escapeHtml(a.cveId)}</code></td>
          <td>${escapeHtml(a.packageName)} <span style="color:var(--text-dim)">${escapeHtml(a.installedVersion)}</span></td>
          <td><span class="${cvssClass}">${cvss}</span></td>
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

dashboardApi.get('/blocks', async (_req, res) => {
  try {
    const allBlocks = await db.select().from(blockedIps)
      .orderBy(desc(blockedIps.blockedAt))
      .limit(50);

    const blocks = allBlocks.filter(b => b.active);

    if (blocks.length === 0) {
      res.send('<p style="color:var(--success);">&#9989; No active IP blocks.</p>');
      return;
    }

    const token = config.dashboard.token || '';
    const html = `<table><thead><tr><th>IP</th><th>Server</th><th>Reason</th><th>Blocked At</th><th>Expires</th><th>Actions</th></tr></thead><tbody>${
      blocks.map(b => `<tr>
        <td><span class="ip-tag">${escapeHtml(b.ip)}</span></td>
        <td>Server #${b.serverId}</td>
        <td style="font-size:0.78rem; color:var(--text-muted);">${escapeHtml(b.reason)}</td>
        <td style="color:var(--text-dim)">${new Date(b.blockedAt).toLocaleString()}</td>
        <td style="color:var(--text-dim)">${b.expiresAt ? new Date(b.expiresAt).toLocaleString() : 'permanent'}</td>
        <td><button class="danger" hx-post="/api/dashboard/blocks/${b.id}/unblock?token=${token}" hx-swap="outerHTML" hx-target="closest tr">Unblock</button></td>
      </tr>`).join('')
    }</tbody></table>`;

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
        <td>${e.sourceIp ? `<span class="ip-tag">${escapeHtml(e.sourceIp)}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
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
        const ipTag = e.sourceIp ? ` <span class="ip-tag">${escapeHtml(e.sourceIp)}</span>` : '';
        html += `<div style="display:flex;align-items:flex-start;gap:0.5rem;padding:0.35rem 0;font-size:0.8rem;">`
          + `<span style="color:var(--text-dim);min-width:5rem;font-family:var(--font-mono);font-size:0.72rem;">${time}</span>`
          + `<span>${icon}</span>`
          + `<div><span class="severity-${e.severity}">${escapeHtml(e.eventType.replace(/_/g, ' '))}</span>${ipTag}`
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
        <td><code>${escapeHtml(ip.ip)}</code></td>
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
        <td>${a.sourceIp ? `<span class="ip-tag">${escapeHtml(a.sourceIp)}</span>` : '—'}</td>
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
            <tr><td>FIM — Baselines de Arquivo</td><td>4 horas</td><td colspan="2">Verifica alterações em arquivos críticos</td></tr>
            <tr><td>CVE Scanner</td><td>6 horas</td><td colspan="2">Verifica vulnerabilidades em pacotes</td></tr>
            <tr><td>Vuln Scanner Completo</td><td>Semanal (sáb 09:00)</td><td colspan="2">Scan profundo de vulnerabilidades</td></tr>
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

    </div>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Intelligence API error');
    res.status(500).send('<p class="severity-critical">Erro ao carregar dados de inteligência</p>');
  }
});

dashboardApi.post('/run-workers', async (_req, res) => {
  try {
    const results: string[] = [];

    await ScoreCalculatorWorker.computeScores();
    results.push('Scores computed');

    await IntelligenceWorker.run();
    results.push('Intelligence (ML profiles + anomaly detection) complete');

    await CVEMonitorWorker.run();
    results.push('CVE scan complete');

    res.json({ ok: true, results });
  } catch (err) {
    logger.error({ err }, 'Run workers error');
    res.status(500).json({ ok: false, error: String(err) });
  }
});
