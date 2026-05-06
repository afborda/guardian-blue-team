import { Router } from 'express';
import { db, dbFalse, dbNow } from '../database/connection.js';
import { socServers, securityEvents, socIncidents, blockedIps, cveAlerts, serverMetrics, serverScores } from '../database/schema.js';
import { eq, count, desc } from 'drizzle-orm';
import { config } from '../config/environment.js';
import { layout } from './views/layout.js';
import { overviewPage } from './views/overview.js';
import { logger } from '../utils/logger.js';
import { escapeHtml } from '../utils/sanitize.js';

export const dashboardPages = Router();
export const dashboardApi = Router();

// ─── HTML Pages ──────────────────────────────────────────────────────────────

dashboardPages.get('/', async (_req, res) => {
  try {
    const [serversCount] = await db.select({ cnt: count() }).from(socServers);
    const [openCount] = await db.select({ cnt: count() }).from(socIncidents).where(eq(socIncidents.status, 'open'));
    const [blockedCount] = await db.select({ cnt: count() }).from(blockedIps);
    const [cveCount] = await db.select({ cnt: count() }).from(cveAlerts).where(eq(cveAlerts.status, 'pending'));
    const [eventsCount] = await db.select({ cnt: count() }).from(securityEvents);

    const allScores = await db.select({ overall: serverScores.overallScore }).from(serverScores)
      .orderBy(desc(serverScores.periodStart))
      .limit(10);

    const overallScore = allScores.length > 0
      ? Math.round(allScores.reduce((sum, s) => sum + s.overall, 0) / allScores.length)
      : 0;

    const content = overviewPage({
      servers: serversCount.cnt,
      openIncidents: openCount.cnt,
      blockedIps: blockedCount.cnt,
      pendingCves: cveCount.cnt,
      eventsToday: eventsCount.cnt,
      overallScore,
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
    <div hx-get="/api/dashboard/events?token=${token}" hx-trigger="load" hx-swap="innerHTML">
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
    const events = await db.select()
      .from(securityEvents)
      .orderBy(desc(securityEvents.timestamp))
      .limit(5);

    if (events.length === 0) {
      res.send('<div class="action-item"><span>&#9989;</span> No threats detected</div>');
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

    const html = events.map(e => {
      const icon = threatIcons[e.eventType] || '&#9888;';
      const ipTag = e.sourceIp ? ` <span class="ip-tag">${escapeHtml(e.sourceIp)}</span>` : '';
      return `<div class="threat-item">
        <span class="threat-icon">${icon}</span>
        <div style="flex:1">
          <div style="font-size:0.82rem;"><span class="severity-${e.severity}">${escapeHtml(e.eventType.replace(/_/g, ' '))}</span>${ipTag}</div>
          <div style="font-size:0.7rem; color:var(--text-dim)">Server #${e.serverId} &middot; ${new Date(e.timestamp).toLocaleTimeString()}</div>
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

    const events = await db.select()
      .from(securityEvents)
      .orderBy(desc(securityEvents.timestamp))
      .limit(limit);

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

    for (const server of servers) {
      const [latestScore] = await db.select().from(serverScores)
        .where(eq(serverScores.serverId, server.id))
        .orderBy(desc(serverScores.periodStart))
        .limit(1);

      const [latestMetrics] = await db.select().from(serverMetrics)
        .where(eq(serverMetrics.serverId, server.id))
        .orderBy(desc(serverMetrics.collectedAt))
        .limit(1);

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
