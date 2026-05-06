import { config } from '../../config/environment.js';

export function layout(title: string, content: string): string {
  const token = config.dashboard.token || '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — Guardian</title>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg-deep: #0b1220;
      --bg-card: #0f1a2e;
      --bg-card-hover: #142240;
      --border: rgba(0, 102, 204, 0.25);
      --border-glow: rgba(0, 102, 204, 0.4);
      --primary: #0066cc;
      --primary-bright: #0088ff;
      --cyan: #00d4ff;
      --success: #22c55e;
      --warning: #f59e0b;
      --critical: #ef4444;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      --font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', monospace;
      --glow-blue: 0 0 12px rgba(0, 102, 204, 0.4);
      --glow-cyan: 0 0 12px rgba(0, 212, 255, 0.3);
      --glow-red: 0 0 12px rgba(239, 68, 68, 0.4);
      --glow-green: 0 0 10px rgba(34, 197, 94, 0.3);
      --radius: 12px;
      --radius-sm: 8px;
    }

    body {
      font-family: var(--font);
      background: var(--bg-deep);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.5;
      font-size: 14px;
    }

    /* ─── HEADER ─────────────────────────────────── */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1rem 2rem;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(180deg, #0d1526 0%, var(--bg-deep) 100%);
    }

    .header-brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .header-brand .shield {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      background: radial-gradient(circle, var(--primary) 0%, #003d7a 100%);
      box-shadow: var(--glow-blue);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
    }

    .header-brand h1 {
      font-size: 1.2rem;
      font-weight: 700;
      background: linear-gradient(135deg, var(--cyan), var(--primary-bright));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .header-badges {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.7rem;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border: 1px solid var(--border);
      background: rgba(0, 102, 204, 0.08);
      color: var(--cyan);
    }

    .badge::before {
      content: '';
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--cyan);
      box-shadow: 0 0 6px var(--cyan);
    }

    /* ─── NAV ─────────────────────────────────── */
    .nav {
      display: flex;
      gap: 0;
      padding: 0 2rem;
      border-bottom: 1px solid var(--border);
      background: rgba(15, 26, 46, 0.6);
      overflow-x: auto;
    }

    .nav a {
      padding: 0.75rem 1.25rem;
      color: var(--text-muted);
      text-decoration: none;
      font-size: 0.82rem;
      font-weight: 500;
      border-bottom: 2px solid transparent;
      transition: all 0.2s;
      white-space: nowrap;
    }

    .nav a:hover {
      color: var(--cyan);
      background: rgba(0, 212, 255, 0.04);
    }

    .nav a.active {
      color: var(--cyan);
      border-bottom-color: var(--cyan);
      background: rgba(0, 212, 255, 0.06);
    }

    /* ─── MAIN CONTENT ────────────────────────── */
    .main {
      padding: 1.5rem 2rem;
      max-width: 1440px;
      margin: 0 auto;
    }

    /* ─── CARDS ───────────────────────────────── */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.25rem;
      box-shadow: var(--glow-blue);
      transition: all 0.2s;
    }

    .card:hover {
      background: var(--bg-card-hover);
      border-color: var(--primary);
      box-shadow: 0 0 20px rgba(0, 102, 204, 0.3);
    }

    .card-header {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 1rem;
      color: var(--text-muted);
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .card-header .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .card-header .dot-blue { background: var(--primary); box-shadow: 0 0 8px var(--primary); }
    .card-header .dot-green { background: var(--success); box-shadow: 0 0 8px var(--success); }
    .card-header .dot-red { background: var(--critical); box-shadow: 0 0 8px var(--critical); }
    .card-header .dot-yellow { background: var(--warning); box-shadow: 0 0 8px var(--warning); }
    .card-header .dot-cyan { background: var(--cyan); box-shadow: 0 0 8px var(--cyan); }

    /* ─── STAT CARDS (KPIs) ───────────────────── */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }

    .kpi {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.25rem;
      box-shadow: var(--glow-blue);
      position: relative;
      overflow: hidden;
    }

    .kpi::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      border-radius: var(--radius) var(--radius) 0 0;
    }

    .kpi-blue::before { background: var(--primary); box-shadow: 0 0 10px var(--primary); }
    .kpi-red::before { background: var(--critical); box-shadow: 0 0 10px var(--critical); }
    .kpi-yellow::before { background: var(--warning); box-shadow: 0 0 10px var(--warning); }
    .kpi-green::before { background: var(--success); box-shadow: 0 0 10px var(--success); }
    .kpi-cyan::before { background: var(--cyan); box-shadow: 0 0 10px var(--cyan); }

    .kpi-label {
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }

    .kpi-value {
      font-size: 2rem;
      font-weight: 700;
      font-family: var(--font-mono);
      line-height: 1;
    }

    .kpi-value-blue { color: var(--primary-bright); text-shadow: 0 0 10px rgba(0, 136, 255, 0.4); }
    .kpi-value-red { color: var(--critical); text-shadow: 0 0 10px rgba(239, 68, 68, 0.4); }
    .kpi-value-yellow { color: var(--warning); text-shadow: 0 0 10px rgba(245, 158, 11, 0.4); }
    .kpi-value-green { color: var(--success); text-shadow: 0 0 10px rgba(34, 197, 94, 0.4); }
    .kpi-value-cyan { color: var(--cyan); text-shadow: 0 0 10px rgba(0, 212, 255, 0.4); }

    /* ─── SCORE CIRCLE (Central) ─────────────── */
    .score-ring {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 2rem;
    }

    .score-circle {
      width: 140px;
      height: 140px;
      border-radius: 50%;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      position: relative;
    }

    .score-circle::before {
      content: '';
      position: absolute;
      inset: -4px;
      border-radius: 50%;
      padding: 4px;
      background: conic-gradient(var(--score-color, var(--primary)) calc(var(--score-pct, 0) * 3.6deg), rgba(255,255,255,0.05) 0);
      -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 6px), #fff calc(100% - 5px));
      mask: radial-gradient(farthest-side, transparent calc(100% - 6px), #fff calc(100% - 5px));
    }

    .score-circle .value {
      font-size: 2.5rem;
      font-weight: 800;
      font-family: var(--font-mono);
    }

    .score-circle .label {
      font-size: 0.7rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
    }

    .score-status {
      margin-top: 1rem;
      font-size: 0.85rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1px;
      padding: 4px 16px;
      border-radius: 20px;
    }

    .status-protected { color: var(--success); border: 1px solid var(--success); box-shadow: var(--glow-green); }
    .status-warning { color: var(--warning); border: 1px solid var(--warning); }
    .status-critical { color: var(--critical); border: 1px solid var(--critical); box-shadow: var(--glow-red); }

    /* ─── PIPELINE STEPPER ────────────────────── */
    .pipeline {
      display: flex;
      align-items: center;
      gap: 0;
      padding: 1rem;
      justify-content: center;
    }

    .pipeline-step {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 0.3rem;
      padding: 0.6rem 1.2rem;
      border-radius: var(--radius-sm);
      border: 1px solid var(--border);
      background: var(--bg-card);
      min-width: 100px;
    }

    .pipeline-step .step-icon { font-size: 1.2rem; }
    .pipeline-step .step-label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }

    .pipeline-arrow {
      color: var(--cyan);
      font-size: 1.2rem;
      padding: 0 0.5rem;
      text-shadow: 0 0 8px var(--cyan);
      animation: pulse-arrow 2s ease-in-out infinite;
    }

    @keyframes pulse-arrow {
      0%, 100% { opacity: 0.5; }
      50% { opacity: 1; }
    }

    /* ─── TABLES ──────────────────────────────── */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.82rem;
    }

    thead th {
      text-align: left;
      padding: 0.75rem 1rem;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.7rem;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border);
      background: rgba(0, 102, 204, 0.04);
    }

    tbody td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }

    tbody tr:hover {
      background: rgba(0, 102, 204, 0.06);
    }

    /* ─── SEVERITY BADGES ─────────────────────── */
    .severity-critical {
      color: var(--critical);
      text-shadow: 0 0 6px rgba(239, 68, 68, 0.4);
      font-weight: 600;
    }
    .severity-high {
      color: var(--warning);
      text-shadow: 0 0 6px rgba(245, 158, 11, 0.3);
      font-weight: 600;
    }
    .severity-medium {
      color: #fbbf24;
      font-weight: 500;
    }
    .severity-low {
      color: var(--primary-bright);
      font-weight: 500;
    }
    .severity-info {
      color: var(--text-muted);
    }

    /* ─── TERMINAL BLOCK ──────────────────────── */
    .terminal {
      background: #030810;
      border: 1px solid rgba(34, 197, 94, 0.2);
      border-radius: var(--radius-sm);
      padding: 1rem;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--success);
      line-height: 1.8;
      overflow-x: auto;
      box-shadow: 0 0 15px rgba(34, 197, 94, 0.08) inset;
    }

    .terminal .prompt { color: var(--cyan); }
    .terminal .ok { color: var(--success); }
    .terminal .fail { color: var(--critical); }
    .terminal .dim { color: var(--text-dim); }

    /* ─── THREAT CARD ─────────────────────────── */
    .threat-card {
      background: rgba(239, 68, 68, 0.04);
      border: 1px solid rgba(239, 68, 68, 0.2);
      border-radius: var(--radius);
      padding: 1.25rem;
      box-shadow: 0 0 15px rgba(239, 68, 68, 0.08);
    }

    .threat-item {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.5rem 0;
      border-bottom: 1px solid rgba(239, 68, 68, 0.08);
    }

    .threat-item:last-child { border-bottom: none; }

    .threat-icon { font-size: 1.1rem; }

    .ip-tag {
      font-family: var(--font-mono);
      font-size: 0.75rem;
      background: rgba(239, 68, 68, 0.12);
      border: 1px solid rgba(239, 68, 68, 0.3);
      padding: 2px 8px;
      border-radius: 4px;
      color: var(--critical);
    }

    /* ─── ACTION / RESPONSE CARD ──────────────── */
    .action-card {
      background: rgba(0, 102, 204, 0.04);
      border: 1px solid rgba(0, 102, 204, 0.2);
      border-radius: var(--radius);
      padding: 1.25rem;
      box-shadow: var(--glow-blue);
    }

    .action-item {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.5rem 0;
      font-size: 0.82rem;
      border-bottom: 1px solid rgba(0, 102, 204, 0.08);
    }

    .action-item:last-child { border-bottom: none; }

    /* ─── BUTTONS ─────────────────────────────── */
    button, .btn {
      font-family: var(--font);
      font-size: 0.78rem;
      font-weight: 600;
      padding: 0.5rem 1rem;
      border-radius: var(--radius-sm);
      border: 1px solid var(--primary);
      background: rgba(0, 102, 204, 0.15);
      color: var(--primary-bright);
      cursor: pointer;
      transition: all 0.2s;
    }

    button:hover, .btn:hover {
      background: rgba(0, 102, 204, 0.25);
      box-shadow: var(--glow-blue);
    }

    button.danger {
      border-color: var(--critical);
      color: var(--critical);
      background: rgba(239, 68, 68, 0.1);
    }

    button.danger:hover {
      background: rgba(239, 68, 68, 0.2);
      box-shadow: var(--glow-red);
    }

    button.success {
      border-color: var(--success);
      color: var(--success);
      background: rgba(34, 197, 94, 0.1);
    }

    /* ─── CODE / MONO ─────────────────────────── */
    code {
      font-family: var(--font-mono);
      font-size: 0.78rem;
      background: rgba(0, 212, 255, 0.08);
      border: 1px solid rgba(0, 212, 255, 0.15);
      padding: 1px 6px;
      border-radius: 4px;
      color: var(--cyan);
    }

    /* ─── SECTIONS ────────────────────────────── */
    .section-title {
      font-size: 1rem;
      font-weight: 700;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .section-title::before {
      content: '';
      width: 4px;
      height: 20px;
      background: var(--primary);
      border-radius: 2px;
      box-shadow: 0 0 8px var(--primary);
    }

    h2 { font-size: 1.3rem; font-weight: 700; margin-bottom: 1.5rem; }
    h3 { font-size: 1rem; font-weight: 600; margin: 1.5rem 0 1rem; color: var(--text-muted); }

    /* ─── GRID LAYOUTS ────────────────────────── */
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1.5rem; }

    @media (max-width: 1024px) {
      .grid-2, .grid-3 { grid-template-columns: 1fr; }
      .header { flex-direction: column; gap: 1rem; }
      .header-badges { justify-content: center; }
      .pipeline { flex-wrap: wrap; }
    }

    /* ─── LINKS / A ──────────────────────────── */
    a { color: var(--cyan); text-decoration: none; transition: color 0.2s; }
    a:hover { color: var(--primary-bright); }

    /* ─── LOADING STATE ──────────────────────── */
    [aria-busy="true"] {
      color: var(--text-dim);
      font-style: italic;
    }

    /* ─── SCROLLBAR ──────────────────────────── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-deep); }
    ::-webkit-scrollbar-thumb { background: var(--primary); border-radius: 3px; }

    /* ─── FOOTER ─────────────────────────────── */
    .footer {
      padding: 1.5rem 2rem;
      text-align: center;
      color: var(--text-dim);
      font-size: 0.72rem;
      border-top: 1px solid var(--border);
      margin-top: 2rem;
    }

    /* ─── SCORE GRID ─────────────────────────── */
    .score-grid-table td, .score-grid-table th {
      text-align: center;
    }

    .score-cell {
      font-family: var(--font-mono);
      font-weight: 600;
      font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <header class="header">
    <div class="header-brand">
      <div class="shield">&#128737;</div>
      <h1>Guardian Blue Team</h1>
    </div>
    <div class="header-badges">
      <span class="badge">Setup 30s</span>
      <span class="badge">Agentless SSH</span>
      <span class="badge">AI-Powered</span>
      <span class="badge">Mobile-First</span>
    </div>
  </header>

  <nav class="nav">
    <a href="/dashboard?token=${token}" class="${title === 'Overview' ? 'active' : ''}">Overview</a>
    <a href="/dashboard/health?token=${token}" class="${title === 'Fleet Health' ? 'active' : ''}">Fleet Health</a>
    <a href="/dashboard/scores?token=${token}" class="${title === 'Scores' ? 'active' : ''}">Scores</a>
    <a href="/dashboard/incidents?token=${token}" class="${title === 'Incidents' ? 'active' : ''}">Incidents</a>
    <a href="/dashboard/servers?token=${token}" class="${title === 'Servers' ? 'active' : ''}">Servers</a>
    <a href="/dashboard/cve?token=${token}" class="${title === 'CVE Alerts' ? 'active' : ''}">CVE</a>
    <a href="/dashboard/blocks?token=${token}" class="${title === 'Blocks' ? 'active' : ''}">Blocks</a>
    <a href="/dashboard/logs?token=${token}" class="${title === 'Logs' ? 'active' : ''}">Logs</a>
  </nav>

  <main class="main">
    ${content}
  </main>

  <footer class="footer">
    Guardian Blue Team — Lightweight SIEM/SOAR &middot; Agentless SSH Monitoring
  </footer>
</body>
</html>`;
}
