export function overviewPage(stats: { servers: number; openIncidents: number; blockedIps: number; pendingCves: number; eventsToday: number }): string {
  return `
    <h2>Dashboard</h2>
    <div class="grid-stats">
      <article class="card">
        <small>Servers</small>
        <div class="stat-value">${stats.servers}</div>
      </article>
      <article class="card">
        <small>Open Incidents</small>
        <div class="stat-value severity-high">${stats.openIncidents}</div>
      </article>
      <article class="card">
        <small>Blocked IPs</small>
        <div class="stat-value">${stats.blockedIps}</div>
      </article>
      <article class="card">
        <small>Pending CVEs</small>
        <div class="stat-value severity-critical">${stats.pendingCves}</div>
      </article>
      <article class="card">
        <small>Events (24h)</small>
        <div class="stat-value">${stats.eventsToday}</div>
      </article>
    </div>
    <section>
      <h3>Recent Incidents</h3>
      <div hx-get="/api/dashboard/incidents?limit=5&token=${process.env.DASHBOARD_TOKEN || ''}" hx-trigger="load" hx-swap="innerHTML">
        <p aria-busy="true">Loading...</p>
      </div>
    </section>
  `;
}
