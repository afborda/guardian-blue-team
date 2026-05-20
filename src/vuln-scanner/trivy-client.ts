/**
 * Trivy client — runs the `trivy` CLI on the target host in client mode,
 * talking to a centrally-deployed `trivy server` over RPC.
 *
 * Why on-host: Trivy needs to introspect the local Docker daemon to enumerate
 * running/cached images. Pulling images centrally would either require the
 * docker socket exposed over the network (security regression) or full image
 * pulls per scan (bandwidth + storage cost). Trivy's client/server split keeps
 * the heavy vuln database centralized while the scanner itself runs locally.
 *
 * Why a server at all: the Trivy DB is ~600 MB and refreshed every 6h. One
 * server downloads it once; clients piggyback. Without `--server`, every host
 * pulls the DB independently and re-pulls on cache miss.
 *
 * Failure mode: if Trivy isn't installed on the target, or the server URL is
 * unset, scanImage() returns []. The caller (DockerAuditor) falls back to the
 * cheap heuristics. This service must NEVER be the reason a scan crashes.
 */

import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

export interface TrivyFinding {
  image: string;
  tag: string;
  cveId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  packageName: string;
  installedVersion: string;
  fixedVersion: string | null;
  title: string;
}

// Trivy JSON output shape — only the fields we consume.
interface TrivyJsonReport {
  Results?: Array<{
    Target?: string;
    Vulnerabilities?: Array<{
      VulnerabilityID: string;
      PkgName: string;
      InstalledVersion: string;
      FixedVersion?: string;
      Severity: string;
      Title?: string;
      Description?: string;
    }>;
  }>;
}

const SCAN_TIMEOUT_MS = 90_000;
const MAX_FINDINGS_PER_IMAGE = 50;

export class TrivyClient {
  static isConfigured(): boolean {
    return config.trivy.serverUrl !== null;
  }

  /**
   * Scan a single image:tag on a remote target. Returns CVE findings, or []
   * on any failure (binary missing, server unreachable, parse error).
   */
  static async scanImage(target: SSHTarget, image: string, tag: string): Promise<TrivyFinding[]> {
    if (!this.isConfigured()) return [];

    const ref = `${image}:${tag}`;
    // --quiet: suppress progress lines. --format json: machine-readable.
    // --severity: skip noisy LOW/UNKNOWN by default; bump if needed.
    // --timeout: scanner-side cap; SSHCollector timeout is the outer bound.
    // --scanners vuln: skip secret/config/license — those are different signals.
    const tokenFlag = config.trivy.token
      ? `--token ${shellQuote(config.trivy.token)} `
      : '';
    const cmd = `trivy image --server ${shellQuote(config.trivy.serverUrl!)} ${tokenFlag}` +
      `--quiet --format json --scanners vuln --severity HIGH,CRITICAL --timeout 60s ` +
      `${shellQuote(ref)} 2>/dev/null`;

    const result = await SSHCollector.run(target, cmd, SCAN_TIMEOUT_MS);

    if (!result.success || !result.stdout.trim()) {
      logger.debug({ ref, host: target.host, error: result.error }, 'Trivy scan returned no output');
      return [];
    }

    return this.parseReport(result.stdout, image, tag);
  }

  static parseReport(raw: string, image: string, tag: string): TrivyFinding[] {
    let report: TrivyJsonReport;
    try {
      report = JSON.parse(raw) as TrivyJsonReport;
    } catch (err) {
      logger.debug({ err, image, tag }, 'Trivy: failed to parse JSON report');
      return [];
    }

    const out: TrivyFinding[] = [];
    for (const result of report.Results ?? []) {
      for (const vuln of result.Vulnerabilities ?? []) {
        out.push({
          image,
          tag,
          cveId: vuln.VulnerabilityID,
          severity: normalizeSeverity(vuln.Severity),
          packageName: vuln.PkgName,
          installedVersion: vuln.InstalledVersion,
          fixedVersion: vuln.FixedVersion ?? null,
          title: (vuln.Title ?? vuln.Description ?? '').slice(0, 200),
        });
        if (out.length >= MAX_FINDINGS_PER_IMAGE) {
          // Truncate noisy images (e.g. an outdated python:3.8 with 200+ CVEs).
          // Anything past the top-N by severity isn't actionable in a single alert.
          return out;
        }
      }
    }
    return out;
  }
}

function normalizeSeverity(raw: string): TrivyFinding['severity'] {
  const s = (raw ?? '').toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MEDIUM') return 'medium';
  if (s === 'LOW') return 'low';
  return 'unknown';
}

// Single-quote escaping for safe interpolation into a remote shell command.
// Trivy server URLs and image refs come from operator config or local docker
// output, but we still defend against an image tag containing a quote.
function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}
