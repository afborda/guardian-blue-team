import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { logger } from '../utils/logger.js';

export interface RuntimeVersion {
  name: string;
  version: string;
  major: number;
  eolDate: string | null;
  isEol: boolean;
  isNearEol: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  remediation: string;
}

interface EolEntry {
  eolDate: string; // YYYY-MM-DD
  severity: 'critical' | 'high' | 'medium' | 'low';
}

// EOL schedule — Node.js LTS: https://nodejs.org/en/about/previous-releases
// Docker Engine, nginx, Python — check vendor release schedule
const EOL_SCHEDULE: Record<string, Record<string, EolEntry>> = {
  node: {
    '14': { eolDate: '2023-04-30', severity: 'critical' },
    '16': { eolDate: '2023-09-11', severity: 'critical' },
    '18': { eolDate: '2025-04-30', severity: 'high' },
    '20': { eolDate: '2026-04-30', severity: 'medium' },
    '22': { eolDate: '2027-04-30', severity: 'low' },
  },
  python3: {
    '3.7': { eolDate: '2023-06-27', severity: 'critical' },
    '3.8': { eolDate: '2024-10-07', severity: 'high' },
    '3.9': { eolDate: '2025-10-05', severity: 'medium' },
    '3.10': { eolDate: '2026-10-04', severity: 'low' },
    '3.11': { eolDate: '2027-10-24', severity: 'low' },
    '3.12': { eolDate: '2028-10-31', severity: 'low' },
  },
  nginx: {
    '1.18': { eolDate: '2022-04-12', severity: 'critical' },
    '1.20': { eolDate: '2023-05-01', severity: 'high' },
    '1.22': { eolDate: '2024-04-01', severity: 'high' },
    '1.24': { eolDate: '2025-04-01', severity: 'medium' },
    '1.26': { eolDate: '2026-04-01', severity: 'low' },
  },
  docker: {
    '20': { eolDate: '2023-10-26', severity: 'high' },
    '23': { eolDate: '2024-07-01', severity: 'high' },
    '24': { eolDate: '2025-02-01', severity: 'medium' },
    '25': { eolDate: '2025-08-01', severity: 'medium' },
    '26': { eolDate: '2026-03-01', severity: 'low' },
    '27': { eolDate: '2027-06-01', severity: 'low' },
  },
};

// Near-EOL warning window: 90 days before EOL date
const NEAR_EOL_DAYS = 90;

function parseMajor(version: string): number {
  return parseInt(version.split('.')[0] ?? '0', 10);
}

function parseMinorKey(runtime: string, version: string): string | null {
  if (runtime === 'python3') {
    const m = version.match(/^(\d+\.\d+)/);
    return m ? m[1] : null;
  }
  if (runtime === 'nginx') {
    const m = version.match(/^(\d+\.\d+)/);
    return m ? m[1] : null;
  }
  return String(parseMajor(version));
}

function checkEol(runtime: string, version: string): Pick<RuntimeVersion, 'eolDate' | 'isEol' | 'isNearEol' | 'severity' | 'remediation'> {
  const schedule = EOL_SCHEDULE[runtime];
  if (!schedule) {
    return { eolDate: null, isEol: false, isNearEol: false, severity: 'low', remediation: 'Keep the runtime updated to the latest stable release.' };
  }

  const key = parseMinorKey(runtime, version);
  if (!key) return { eolDate: null, isEol: false, isNearEol: false, severity: 'low', remediation: '' };

  const entry = schedule[key];
  if (!entry) {
    return { eolDate: null, isEol: false, isNearEol: false, severity: 'low', remediation: `${runtime} ${version} — no EOL data found; verify manually.` };
  }

  const now = Date.now();
  const eolMs = new Date(entry.eolDate).getTime();
  const nearEolMs = eolMs - NEAR_EOL_DAYS * 86_400_000;
  const isEol = now > eolMs;
  const isNearEol = !isEol && now > nearEolMs;

  const remediation = isEol
    ? `${runtime} ${version} reached EOL on ${entry.eolDate}. Upgrade immediately — no security patches are released for this version.`
    : isNearEol
      ? `${runtime} ${version} reaches EOL on ${entry.eolDate} (${Math.ceil((eolMs - now) / 86_400_000)} days). Plan upgrade soon.`
      : `${runtime} ${version} is supported until ${entry.eolDate}.`;

  return { eolDate: entry.eolDate, isEol, isNearEol, severity: isEol ? entry.severity : (isNearEol ? 'medium' : 'low'), remediation };
}

// Single SSH command that collects all runtime versions at once
const COLLECT_CMD = [
  "echo NODE=$(node --version 2>/dev/null || echo '')",
  "echo NPM=$(npm --version 2>/dev/null || echo '')",
  "echo PYTHON=$(python3 --version 2>/dev/null | awk '{print $2}' || echo '')",
  "echo NGINX=$(nginx -v 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' || echo '')",
  "echo DOCKER=$(docker --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || echo '')",
  "echo CONTAINERD=$(containerd --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || echo '')",
].join('; ');

export class RuntimeVersionScanner {
  static async scan(target: SSHTarget): Promise<RuntimeVersion[]> {
    const result = await SSHCollector.run(target, COLLECT_CMD, 15_000);
    if (!result.success) {
      logger.debug({ host: target.host }, 'Runtime version scan SSH failed');
      return [];
    }

    const parsed: Record<string, string> = {};
    for (const line of result.stdout.split('\n')) {
      const eq = line.indexOf('=');
      if (eq === -1) continue;
      const key = line.slice(0, eq).trim();
      const val = line.slice(eq + 1).trim().replace(/^v/, '');
      if (val) parsed[key] = val;
    }

    const versions: RuntimeVersion[] = [];

    const runtimeMap: Array<[string, string, string]> = [
      ['NODE', 'node', 'Node.js'],
      ['NPM', 'npm', 'npm'],
      ['PYTHON', 'python3', 'Python 3'],
      ['NGINX', 'nginx', 'nginx'],
      ['DOCKER', 'docker', 'Docker Engine'],
      ['CONTAINERD', 'containerd', 'containerd'],
    ];

    for (const [key, runtime, displayName] of runtimeMap) {
      const version = parsed[key];
      if (!version) continue;

      const major = parseMajor(version);
      const eolInfo = checkEol(runtime, version);

      versions.push({
        name: displayName,
        version,
        major,
        ...eolInfo,
      });
    }

    return versions;
  }
}
