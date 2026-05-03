export function layout(title: string, content: string): string {
  const token = process.env.DASHBOARD_TOKEN || '';
  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — Guardian</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <style>
    :root { --pico-font-size: 15px; }
    .card { padding: 1rem; border: 1px solid var(--pico-muted-border-color); border-radius: 8px; }
    .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-value { font-size: 2rem; font-weight: bold; }
    .severity-critical { color: #e74c3c; }
    .severity-high { color: #e67e22; }
    .severity-medium { color: #f1c40f; }
    .severity-low { color: #3498db; }
    nav a.active { font-weight: bold; text-decoration: underline; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; }
    .badge-open { background: #e74c3c; color: white; }
    .badge-resolved { background: #27ae60; color: white; }
  </style>
</head>
<body>
  <nav class="container-fluid">
    <ul>
      <li><strong>Guardian</strong></li>
    </ul>
    <ul>
      <li><a href="/dashboard?token=${token}">Overview</a></li>
      <li><a href="/dashboard/health?token=${token}">Fleet Health</a></li>
      <li><a href="/dashboard/scores?token=${token}">Scores</a></li>
      <li><a href="/dashboard/incidents?token=${token}">Incidents</a></li>
      <li><a href="/dashboard/servers?token=${token}">Servers</a></li>
      <li><a href="/dashboard/cve?token=${token}">CVE</a></li>
      <li><a href="/dashboard/blocks?token=${token}">Blocks</a></li>
      <li><a href="/dashboard/logs?token=${token}">Logs</a></li>
    </ul>
  </nav>
  <main class="container">
    ${content}
  </main>
  <footer class="container">
    <small>Guardian Blue Team — Lightweight SOAR</small>
  </footer>
</body>
</html>`;
}
