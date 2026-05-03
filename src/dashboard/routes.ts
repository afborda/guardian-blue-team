import { Router } from 'express';
import { db, dbFalse, dbNow } from '../database/connection.js';
import { socServers, securityEvents, socIncidents, blockedIps, cveAlerts, serverMetrics, serverScores } from '../database/schema.js';
import { eq, count, desc } from 'drizzle-orm';
import { layout } from './views/layout.js';
import { overviewPage } from './views/overview.js';
import { logger } from '../utils/logger.js';

export const dashboardPages = Router();
export const dashboardApi = Router();

// ─── HTML Pages ──────────────────────────────────────────────────────────────

dashboardPages.get('/', async (_req, res) => {
  try {
    const [serversCount] = await db.select({ cnt: count() }).from(socServers);
    const [openCount] = await db.select({ cnt: count() }).from(socIncidents).where(eq(socIncidents.status, 'open'));
    const [blockedCount] = await db.select({ cnt: count() }).from(blockedIps);
    const [cveCount] = await db.select({ cnt: count() }).from(cveAlerts).where(eq(cveAlerts.status, 'notified'));
    const [eventsCount] = await db.select({ cnt: count() }).from(securityEvents);

    const content = overviewPage({
      servers: serversCount.cnt,
      openIncidents: openCount.cnt,
      blockedIps: blockedCount.cnt,
      pendingCves: cveCount.cnt,
      eventsToday: eventsCount.cnt,
    });

    res.send(layout('Overview', content));
  } catch (err) {
    logger.error({ err }, 'Dashboard overview error');
    res.status(500).send(layout('Error', '<p>Failed to load dashboard</p>'));
  }
});

dashboardPages.get('/incidents', (_req, res) => {
  const token = process.env.DASHBOARD_TOKEN || '';
  const content = `
    <h2>Incidents</h2>
    <div hx-get="/api/dashboard/incidents?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Incidents', content));
});

dashboardPages.get('/servers', (_req, res) => {
  const token = process.env.DASHBOARD_TOKEN || '';
  const content = `
    <h2>Servers</h2>
    <div hx-get="/api/dashboard/servers?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Servers', content));
});

dashboardPages.get('/cve', (_req, res) => {
  const token = process.env.DASHBOARD_TOKEN || '';
  const content = `
    <h2>CVE Alerts</h2>
    <div id="cve-list" hx-get="/api/dashboard/cve-alerts?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('CVE Alerts', content));
});

dashboardPages.get('/blocks', (_req, res) => {
  const token = process.env.DASHBOARD_TOKEN || '';
  const content = `
    <h2>Active IP Blocks</h2>
    <div id="blocks-list" hx-get="/api/dashboard/blocks?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Blocks', content));
});

dashboardPages.get('/logs', (_req, res) => {
  const token = process.env.DASHBOARD_TOKEN || '';
  const content = `
    <h2>Security Events</h2>
    <div hx-get="/api/dashboard/events?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading...</p>
    </div>
  `;
  res.send(layout('Logs', content));
});

dashboardPages.get('/health', (_req, res) => {
  const token = process.env.DASHBOARD_TOKEN || '';
  const content = `
    <h2>Fleet Health</h2>
    <div hx-get="/api/dashboard/fleet-health?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading fleet status...</p>
    </div>
  `;
  res.send(layout('Fleet Health', content));
});

dashboardPages.get('/health/:id', (req, res) => {
  const token = process.env.DASHBOARD_TOKEN || '';
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
  const token = process.env.DASHBOARD_TOKEN || '';
  const content = `
    <h2>Server Scores</h2>
    <div hx-get="/api/dashboard/scores?token=${token}" hx-trigger="load" hx-swap="innerHTML">
      <p aria-busy="true">Loading scores...</p>
    </div>
  `;
  res.send(layout('Scores', content));
});

// ─── API Routes (JSON/HTML fragments for HTMX) ─────────────────────────────

dashboardApi.get('/stats', async (_req, res) => {
  try {
    const [servers] = await db.select({ cnt: count() }).from(socServers);
    const [incidents] = await db.select({ cnt: count() }).from(socIncidents).where(eq(socIncidents.status, 'open'));
    const [blocks] = await db.select({ cnt: count() }).from(blockedIps);
    const [cves] = await db.select({ cnt: count() }).from(cveAlerts).where(eq(cveAlerts.status, 'notified'));
    const [events] = await db.select({ cnt: count() }).from(securityEvents);

    res.json({ servers: servers.cnt, openIncidents: incidents.cnt, blockedIps: blocks.cnt, pendingCves: cves.cnt, eventsToday: events.cnt });
  } catch (err) {
    logger.error({ err }, 'Dashboard stats API error');
    res.status(500).json({ error: 'internal' });
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

    const html = incidents.length === 0
      ? '<p>No incidents found.</p>'
      : `<table role="grid"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Events</th><th>Last Seen</th></tr></thead><tbody>${
        incidents.map(i => `<tr><td>#${i.id}</td><td>${i.title}</td><td><span class="severity-${i.severity}">${i.severity}</span></td><td>${i.eventCount}</td><td>${i.lastSeenAt.toLocaleString()}</td></tr>`).join('')
      }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard incidents API error');
    res.status(500).send('<p>Error loading incidents</p>');
  }
});

dashboardApi.get('/servers', async (_req, res) => {
  try {
    const servers = await db.select().from(socServers).orderBy(socServers.name);

    const html = servers.length === 0
      ? '<p>No servers registered.</p>'
      : `<table role="grid"><thead><tr><th>Name</th><th>Host</th><th>Enabled</th><th>Last Seen</th></tr></thead><tbody>${
        servers.map(s => `<tr><td><strong>${s.name}</strong></td><td>${s.host}:${s.sshPort}</td><td>${s.enabled ? '✅' : '❌'}</td><td>${s.lastSeenAt?.toLocaleString() ?? 'never'}</td></tr>`).join('')
      }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard servers API error');
    res.status(500).send('<p>Error loading servers</p>');
  }
});

dashboardApi.get('/cve-alerts', async (_req, res) => {
  try {
    const alerts = await db.select().from(cveAlerts)
      .where(eq(cveAlerts.status, 'notified'))
      .orderBy(desc(cveAlerts.createdAt))
      .limit(50);

    if (alerts.length === 0) {
      res.send('<p>No pending CVE alerts.</p>');
      return;
    }

    const token = process.env.DASHBOARD_TOKEN || '';
    const html = `<table role="grid"><thead><tr><th>CVE</th><th>Package</th><th>CVSS</th><th>Fix</th><th>Actions</th></tr></thead><tbody>${
      alerts.map(a => {
        const cvss = a.cvssScore ? (a.cvssScore / 10).toFixed(1) : '?';
        const actions = [
          a.fixedVersion ? `<button hx-post="/api/dashboard/cve/${a.id}/update?token=${token}" hx-swap="outerHTML" hx-target="closest tr">Update</button>` : '',
          `<button class="secondary" hx-post="/api/dashboard/cve/${a.id}/ignore?token=${token}" hx-swap="outerHTML" hx-target="closest tr">Ignore</button>`,
        ].filter(Boolean).join(' ');
        return `<tr><td><code>${a.cveId}</code></td><td>${a.packageName} ${a.installedVersion}</td><td><span class="severity-${Number(cvss) >= 9 ? 'critical' : 'high'}">${cvss}</span></td><td>${a.fixedVersion ?? '-'}</td><td>${actions}</td></tr>`;
      }).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard CVE API error');
    res.status(500).send('<p>Error loading CVE alerts</p>');
  }
});

dashboardApi.post('/cve/:id/update', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await db.update(cveAlerts).set({ status: 'updating', resolvedAt: dbNow() }).where(eq(cveAlerts.id, id));
    res.send(`<tr><td colspan="5">CVE #${id} — update triggered</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Dashboard CVE update error');
    res.status(500).send('<tr><td colspan="5">Error</td></tr>');
  }
});

dashboardApi.post('/cve/:id/ignore', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await db.update(cveAlerts).set({ status: 'ignored', resolvedAt: dbNow(), resolvedBy: 'dashboard' }).where(eq(cveAlerts.id, id));
    res.send(`<tr><td colspan="5">CVE #${id} — ignored</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Dashboard CVE ignore error');
    res.status(500).send('<tr><td colspan="5">Error</td></tr>');
  }
});

dashboardApi.get('/blocks', async (_req, res) => {
  try {
    const allBlocks = await db.select().from(blockedIps)
      .orderBy(desc(blockedIps.blockedAt))
      .limit(50);

    const blocks = allBlocks.filter(b => b.active);

    if (blocks.length === 0) {
      res.send('<p>No active IP blocks.</p>');
      return;
    }

    const token = process.env.DASHBOARD_TOKEN || '';
    const html = `<table role="grid"><thead><tr><th>IP</th><th>Server</th><th>Blocked At</th><th>Expires</th><th>Actions</th></tr></thead><tbody>${
      blocks.map(b => `<tr><td><code>${b.ip}</code></td><td>Server #${b.serverId}</td><td>${b.blockedAt.toLocaleString()}</td><td>${b.expiresAt?.toLocaleString() ?? 'permanent'}</td><td><button class="secondary" hx-post="/api/dashboard/blocks/${b.id}/unblock?token=${token}" hx-swap="outerHTML" hx-target="closest tr">Unblock</button></td></tr>`).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard blocks API error');
    res.status(500).send('<p>Error loading blocks</p>');
  }
});

dashboardApi.post('/blocks/:id/unblock', async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    await db.update(blockedIps).set({ active: dbFalse, unblockedAt: dbNow() }).where(eq(blockedIps.id, id));
    res.send(`<tr><td colspan="5">Block #${id} — removed</td></tr>`);
  } catch (err) {
    logger.error({ err }, 'Dashboard unblock error');
    res.status(500).send('<tr><td colspan="5">Error</td></tr>');
  }
});

dashboardApi.get('/events', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit as string) || 100, 200);

    const events = await db.select()
      .from(securityEvents)
      .orderBy(desc(securityEvents.timestamp))
      .limit(limit);

    if (events.length === 0) {
      res.send('<p>No events found.</p>');
      return;
    }

    const html = `<table role="grid"><thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source IP</th><th>Server</th></tr></thead><tbody>${
      events.map(e => `<tr><td>${e.timestamp.toLocaleString()}</td><td>${e.eventType}</td><td><span class="severity-${e.severity}">${e.severity}</span></td><td><code>${e.sourceIp ?? '-'}</code></td><td>#${e.serverId}</td></tr>`).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Dashboard events API error');
    res.status(500).send('<p>Error loading events</p>');
  }
});

// ─── Fleet Health & Scores API ───────────────────────────────────────────────

dashboardApi.get('/fleet-health', async (_req, res) => {
  try {
    const servers = await db.select().from(socServers).orderBy(socServers.name);

    if (servers.length === 0) {
      res.send('<p>No servers registered.</p>');
      return;
    }

    const token = process.env.DASHBOARD_TOKEN || '';
    let html = '<div class="grid-stats">';

    for (const server of servers) {
      const [latestScore] = await db.select().from(serverScores)
        .where(eq(serverScores.serverId, server.id))
        .orderBy(desc(serverScores.periodStart))
        .limit(1);

      const overall = latestScore?.overallScore ?? '-';
      const color = typeof overall === 'number'
        ? (overall >= 80 ? '#27ae60' : overall >= 60 ? '#f1c40f' : overall >= 40 ? '#e67e22' : '#e74c3c')
        : 'var(--pico-muted-color)';

      html += `
        <a href="/dashboard/health/${server.id}?token=${token}" style="text-decoration: none;">
          <div class="card">
            <strong>${server.name}</strong><br>
            <span class="stat-value" style="color: ${color}">${overall}</span>
            <small>/100</small><br>
            <small>${server.host}</small>
          </div>
        </a>`;
    }

    html += '</div>';
    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Fleet health API error');
    res.status(500).send('<p>Error loading fleet health</p>');
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
      res.send('<p>No metrics collected yet.</p>');
      return;
    }

    const latest = metrics[0];
    const memPct = latest.memTotalBytes ? Math.round(((latest.memUsedBytes ?? 0) / latest.memTotalBytes) * 100) : 0;
    const loadRatio = ((latest.load1 ?? 0) / Math.max(latest.cpuCount ?? 1, 1)).toFixed(2);
    const disks = (latest.disks as any[]) ?? [];
    const failedUnits = (latest.failedUnits as string[]) ?? [];

    let html = `
      <div class="grid-stats">
        <div class="card"><small>Load Ratio</small><br><span class="stat-value">${loadRatio}</span></div>
        <div class="card"><small>Memory</small><br><span class="stat-value">${memPct}%</span></div>
        <div class="card"><small>CPUs</small><br><span class="stat-value">${latest.cpuCount ?? '-'}</span></div>
        <div class="card"><small>Uptime</small><br><span class="stat-value">${latest.uptimeSeconds ? Math.floor(latest.uptimeSeconds / 86400) + 'd' : '-'}</span></div>
      </div>`;

    if (disks.length > 0) {
      html += '<h4>Disks</h4><table role="grid"><thead><tr><th>Mount</th><th>Used</th><th>Available</th></tr></thead><tbody>';
      for (const d of disks) {
        html += `<tr><td>${d.mountpoint}</td><td>${d.usedPercent}%</td><td>${Math.round(d.availableBytes / 1073741824)}G</td></tr>`;
      }
      html += '</tbody></table>';
    }

    if (failedUnits.length > 0) {
      html += `<h4>Failed Units</h4><ul>${failedUnits.map(u => `<li><code>${u}</code></li>`).join('')}</ul>`;
    }

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Server metrics API error');
    res.status(500).send('<p>Error loading metrics</p>');
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
      res.send('<p>No scores computed yet.</p>');
      return;
    }

    const html = `<table role="grid"><thead><tr><th>Period</th><th>Overall</th><th>Health</th><th>Security</th><th>Quality</th><th>Waste</th><th>Vuln</th><th>Avail</th></tr></thead><tbody>${
      scores.map(s => {
        const color = s.overallScore >= 80 ? '#27ae60' : s.overallScore >= 60 ? '#f1c40f' : s.overallScore >= 40 ? '#e67e22' : '#e74c3c';
        return `<tr><td>${new Date(s.periodStart).toLocaleString()}</td><td style="color:${color};font-weight:bold">${s.overallScore}</td><td>${s.healthScore}</td><td>${s.securityScore}</td><td>${s.qualityScore}</td><td>${s.wasteScore}</td><td>${s.vulnerabilityScore}</td><td>${s.availabilityScore}</td></tr>`;
      }).join('')
    }</tbody></table>`;

    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Server scores API error');
    res.status(500).send('<p>Error loading scores</p>');
  }
});

dashboardApi.get('/scores', async (_req, res) => {
  try {
    const servers = await db.select().from(socServers).orderBy(socServers.name);

    if (servers.length === 0) {
      res.send('<p>No servers registered.</p>');
      return;
    }

    let html = '<table role="grid"><thead><tr><th>Server</th><th>Overall</th><th>Health</th><th>Security</th><th>Quality</th><th>Waste</th><th>Vuln</th><th>Avail</th></tr></thead><tbody>';

    for (const server of servers) {
      const [s] = await db.select().from(serverScores)
        .where(eq(serverScores.serverId, server.id))
        .orderBy(desc(serverScores.periodStart))
        .limit(1);

      if (!s) {
        html += `<tr><td>${server.name}</td><td colspan="7"><em>No data</em></td></tr>`;
        continue;
      }

      const color = s.overallScore >= 80 ? '#27ae60' : s.overallScore >= 60 ? '#f1c40f' : s.overallScore >= 40 ? '#e67e22' : '#e74c3c';
      html += `<tr><td><strong>${server.name}</strong></td><td style="color:${color};font-weight:bold">${s.overallScore}</td><td>${s.healthScore}</td><td>${s.securityScore}</td><td>${s.qualityScore}</td><td>${s.wasteScore}</td><td>${s.vulnerabilityScore}</td><td>${s.availabilityScore}</td></tr>`;
    }

    html += '</tbody></table>';
    res.send(html);
  } catch (err) {
    logger.error({ err }, 'Scores API error');
    res.status(500).send('<p>Error loading scores</p>');
  }
});
