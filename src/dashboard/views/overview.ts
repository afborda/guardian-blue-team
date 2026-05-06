import { config } from '../../config/environment.js';

interface OverviewStats {
  servers: number;
  openIncidents: number;
  blockedIps: number;
  pendingCves: number;
  eventsToday: number;
  overallScore?: number;
  recentThreats?: Array<{ type: string; ip?: string; server: string; time: string }>;
  recentActions?: Array<{ action: string; target: string; time: string }>;
}

function getScoreColor(score: number): string {
  if (score >= 80) return 'var(--success)';
  if (score >= 60) return 'var(--warning)';
  return 'var(--critical)';
}

function getScoreStatus(score: number): { label: string; cls: string } {
  if (score >= 80) return { label: 'Protected', cls: 'status-protected' };
  if (score >= 60) return { label: 'Warning', cls: 'status-warning' };
  return { label: 'Under Attack', cls: 'status-critical' };
}

export function overviewPage(stats: OverviewStats): string {
  const score = stats.overallScore ?? 0;
  const scoreColor = getScoreColor(score);
  const status = getScoreStatus(score);
  const token = config.dashboard.token || '';

  return `
    <!-- ─── KPI BAR ──────────────────────────────── -->
    <div class="kpi-grid">
      <div class="kpi kpi-blue">
        <div class="kpi-label">Servers Monitored</div>
        <div class="kpi-value kpi-value-blue">${stats.servers}</div>
      </div>
      <div class="kpi kpi-red">
        <div class="kpi-label">Open Incidents</div>
        <div class="kpi-value kpi-value-red">${stats.openIncidents}</div>
      </div>
      <div class="kpi kpi-yellow">
        <div class="kpi-label">Blocked IPs</div>
        <div class="kpi-value kpi-value-yellow">${stats.blockedIps}</div>
      </div>
      <div class="kpi kpi-cyan">
        <div class="kpi-label">Pending CVEs</div>
        <div class="kpi-value kpi-value-cyan">${stats.pendingCves}</div>
      </div>
      <div class="kpi kpi-green">
        <div class="kpi-label">Events (24h)</div>
        <div class="kpi-value kpi-value-green">${stats.eventsToday}</div>
      </div>
    </div>

    <!-- ─── MAIN GRID: Score Center + Sides ─────── -->
    <div class="grid-3" style="margin-bottom: 1.5rem;">
      <!-- LEFT: SSH Monitoring terminal -->
      <div class="card">
        <div class="card-header">
          <span class="dot dot-green"></span>
          SSH Collection
        </div>
        <div class="terminal">
          <div><span class="prompt">guardian</span> <span class="dim">collecting metrics...</span></div>
          <div><span class="prompt">&#10003;</span> <span class="ok">hetzner-fsn1</span> <span class="dim">load=1.2 mem=67% disk=45%</span></div>
          <div><span class="prompt">&#10003;</span> <span class="ok">ovh-db-1</span> <span class="dim">load=0.3 mem=42% disk=28%</span></div>
          <div><span class="prompt">&#10003;</span> <span class="ok">ovh-web-1</span> <span class="dim">load=4.8 mem=91% disk=82%</span></div>
          <div style="margin-top: 0.5rem; border-top: 1px solid rgba(34,197,94,0.15); padding-top: 0.5rem;">
            <span class="dim">&#9656; logs</span> &middot; <span class="dim">&#9656; metrics</span> &middot; <span class="dim">&#9656; system</span>
          </div>
        </div>
      </div>

      <!-- CENTER: Score Ring -->
      <div class="card" style="display: flex; flex-direction: column; align-items: center; justify-content: center;">
        <div class="card-header" style="align-self: flex-start;">
          <span class="dot dot-blue"></span>
          Fleet Status
        </div>
        <div class="score-ring">
          <div class="score-circle" style="--score-color: ${scoreColor}; --score-pct: ${score};">
            <span class="value" style="color: ${scoreColor}; text-shadow: 0 0 15px ${scoreColor};">${score}</span>
            <span class="label">/ 100</span>
          </div>
          <div class="score-status ${status.cls}">${status.label}</div>
        </div>
      </div>

      <!-- RIGHT: Automated Response -->
      <div class="card">
        <div class="card-header">
          <span class="dot dot-cyan"></span>
          Automated Response
        </div>
        <div class="action-card" style="border: none; background: transparent; padding: 0; box-shadow: none;">
          <div hx-get="/api/dashboard/recent-actions?token=${token}" hx-trigger="load" hx-swap="innerHTML">
            <div class="action-item"><span>&#128737;</span> <span class="dim">Loading actions...</span></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ─── PIPELINE STEPPER ──────────────────────── -->
    <div class="card" style="margin-bottom: 1.5rem;">
      <div class="card-header">
        <span class="dot dot-cyan"></span>
        Data Pipeline
      </div>
      <div class="pipeline">
        <div class="pipeline-step">
          <span class="step-icon">&#128225;</span>
          <span class="step-label">Collect</span>
        </div>
        <span class="pipeline-arrow">&#10142;</span>
        <div class="pipeline-step" style="border-color: rgba(245,158,11,0.3);">
          <span class="step-icon">&#9881;</span>
          <span class="step-label">Bronze</span>
        </div>
        <span class="pipeline-arrow">&#10142;</span>
        <div class="pipeline-step" style="border-color: rgba(192,192,192,0.3);">
          <span class="step-icon">&#128202;</span>
          <span class="step-label">Silver</span>
        </div>
        <span class="pipeline-arrow">&#10142;</span>
        <div class="pipeline-step" style="border-color: rgba(255,215,0,0.3);">
          <span class="step-icon">&#129351;</span>
          <span class="step-label">Gold</span>
        </div>
        <span class="pipeline-arrow">&#10142;</span>
        <div class="pipeline-step" style="border-color: rgba(0,212,255,0.3);">
          <span class="step-icon">&#129504;</span>
          <span class="step-label">AI Intel</span>
        </div>
      </div>
    </div>

    <!-- ─── BOTTOM: Threats + Incidents ───────────── -->
    <div class="grid-2">
      <!-- Threats detected -->
      <div>
        <h3 class="section-title">Threat Detection</h3>
        <div class="threat-card">
          <div hx-get="/api/dashboard/recent-threats?token=${token}" hx-trigger="load" hx-swap="innerHTML">
            <p aria-busy="true">Scanning...</p>
          </div>
        </div>
      </div>

      <!-- Recent incidents -->
      <div>
        <h3 class="section-title">Active Incidents</h3>
        <div class="card" style="padding: 0;">
          <div hx-get="/api/dashboard/incidents?limit=5&token=${token}" hx-trigger="load" hx-swap="innerHTML">
            <p aria-busy="true" style="padding: 1rem;">Loading...</p>
          </div>
        </div>
      </div>
    </div>
  `;
}
