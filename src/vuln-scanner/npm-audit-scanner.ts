import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { logger } from '../utils/logger.js';

const execFileAsync = promisify(execFile);

const EXEC_TIMEOUT_MS = 2 * 60_000;
const MAX_FINDINGS_PER_CONTAINER = 50;

export interface NpmAuditFinding {
  containerId: string;
  imageRef: string;
  cveId: string;
  severity: 'critical' | 'high';
  packageName: string;
  installedVersion: string;
  fixedVersion: string | null;
  title: string;
  url: string | null;
}

interface NpmAuditJson {
  vulnerabilities?: Record<string, {
    severity: string;
    via?: Array<string | {
      source?: number;
      name?: string;
      dependency?: string;
      title?: string;
      url?: string;
      severity?: string;
      cvss?: { score?: number };
      cwe?: string[];
    }>;
    fixAvailable?: boolean | { name: string; version: string };
    nodes?: string[];
    range?: string;
  }>;
  metadata?: { vulnerabilities?: { critical?: number; high?: number } };
}

export class NpmAuditScanner {
  static async detectNodeContainers(): Promise<Array<{ id: string; image: string }>> {
    try {
      const { stdout } = await execFileAsync(
        'docker',
        ['ps', '--format', '{{.ID}}\t{{.Image}}\t{{.Names}}'],
        { timeout: 10_000 },
      );
      const containers: Array<{ id: string; image: string }> = [];
      for (const line of stdout.trim().split('\n').filter(Boolean)) {
        const [id, image, name] = line.split('\t');
        if (this.looksLikeNodeContainer(image, name)) {
          containers.push({ id, image });
        }
      }
      return containers;
    } catch (err) {
      logger.warn({ err }, 'NpmAuditScanner: failed to list containers');
      return [];
    }
  }

  private static looksLikeNodeContainer(image: string, name: string): boolean {
    const lower = `${image} ${name}`.toLowerCase();
    return (
      lower.includes('node') ||
      lower.includes('next') ||
      lower.includes('automabothub') ||
      lower.includes('ninho') ||
      lower.includes('guardian') ||
      lower.includes('nuxt') ||
      lower.includes('express') ||
      lower.includes('nestjs')
    );
  }

  static async auditContainer(containerId: string, imageRef: string): Promise<NpmAuditFinding[]> {
    let stdout: string;
    try {
      const result = await execFileAsync(
        'docker',
        ['exec', containerId, 'npm', 'audit', '--json', '--audit-level=high'],
        { timeout: EXEC_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 },
      );
      stdout = result.stdout;
    } catch (err: unknown) {
      // npm audit exits non-zero when it finds vulnerabilities — that's expected
      const e = err as { stdout?: string; code?: number };
      if (e.stdout && e.code && e.code > 0) {
        stdout = e.stdout;
      } else {
        const msg = err instanceof Error ? err.message : String(err);
        if (!msg.includes('npm: not found') && !msg.includes('npm: executable file not found')) {
          logger.debug({ containerId, err: msg }, 'NpmAuditScanner: audit failed');
        }
        return [];
      }
    }

    return this.parseAuditOutput(containerId, imageRef, stdout);
  }

  private static parseAuditOutput(containerId: string, imageRef: string, raw: string): NpmAuditFinding[] {
    if (!raw.trim()) return [];

    let report: NpmAuditJson;
    try {
      report = JSON.parse(raw) as NpmAuditJson;
    } catch {
      return [];
    }

    const findings: NpmAuditFinding[] = [];

    for (const [pkgName, vuln] of Object.entries(report.vulnerabilities ?? {})) {
      const sev = vuln.severity?.toUpperCase();
      if (sev !== 'CRITICAL' && sev !== 'HIGH') continue;

      // Extract CVE ID and advisory details from the via array
      let cveId = `NPM-${pkgName}`;
      let title = pkgName;
      let url: string | null = null;
      let fixedVersion: string | null = null;

      for (const via of vuln.via ?? []) {
        if (typeof via === 'object' && via.url) {
          url = via.url;
          if (via.title) title = via.title;
          // npm advisory URLs contain the advisory ID
          const match = via.url.match(/advisories\/(\d+)/);
          if (match) cveId = `GHSA-npm-${match[1]}`;
          break;
        }
      }

      if (typeof vuln.fixAvailable === 'object' && vuln.fixAvailable.version) {
        fixedVersion = vuln.fixAvailable.version;
      }

      findings.push({
        containerId,
        imageRef,
        cveId,
        severity: sev === 'CRITICAL' ? 'critical' : 'high',
        packageName: pkgName,
        installedVersion: vuln.range ?? 'unknown',
        fixedVersion,
        title: title.slice(0, 200),
        url,
      });

      if (findings.length >= MAX_FINDINGS_PER_CONTAINER) break;
    }

    return findings;
  }

  /** Audit all Node.js containers. Returns map containerId → findings. Never throws. */
  static async scanAll(): Promise<Map<string, NpmAuditFinding[]>> {
    const result = new Map<string, NpmAuditFinding[]>();

    const containers = await this.detectNodeContainers();
    if (containers.length === 0) return result;

    logger.info({ count: containers.length }, 'NpmAuditScanner: auditing Node containers');

    const settled = await Promise.allSettled(
      containers.map(async c => ({
        id: c.id,
        findings: await this.auditContainer(c.id, c.image),
      })),
    );

    for (const s of settled) {
      if (s.status === 'fulfilled') {
        result.set(s.value.id, s.value.findings);
      }
    }

    const totalFindings = [...result.values()].reduce((n, f) => n + f.length, 0);
    logger.info({ containers: result.size, findings: totalFindings }, 'NpmAuditScanner: audit complete');

    return result;
  }
}
