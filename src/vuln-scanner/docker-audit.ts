/**
 * Docker image auditor — two-layer scan:
 *
 * 1. Cheap local heuristics (always run): unpinned :latest tag, stale images
 *    (>=6 months old). These catch hygiene issues Trivy doesn't flag.
 *
 * 2. Trivy CVE scan (when configured): real vulnerability lookup against the
 *    Trivy DB. Adds CVE-grade findings on top of the heuristics. When Trivy
 *    is unconfigured or unreachable, this layer silently no-ops and the
 *    caller still gets the heuristics.
 *
 * The two layers complement each other:
 *   - Heuristics warn on operational debt (you're running 18-month-old images);
 *     Trivy warns on actual exploitable CVEs in those images.
 *   - Heuristics need zero infra; Trivy needs a server. Make them independent.
 */

import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { TrivyClient, type TrivyFinding } from './trivy-client.js';
import { logger } from '../utils/logger.js';

export interface DockerVuln {
  image: string;
  tag: string;
  issue: string;
  severity: string;
  // Set when the finding came from Trivy (CVE-backed). Heuristics leave undefined.
  cveId?: string;
  packageName?: string;
  fixedVersion?: string | null;
}

const MAX_IMAGES_TO_SCAN = 30;
const MAX_TRIVY_TARGETS = 10; // cap per host to avoid 30×60s scans

export class DockerAuditor {
  static async audit(target: SSHTarget): Promise<DockerVuln[]> {
    const result = await SSHCollector.run(target,
      "docker images --format '{{.Repository}}:{{.Tag}} {{.CreatedSince}}' 2>/dev/null | head -30",
      15_000,
    );

    if (!result.success) return [];

    const lines = result.stdout.trim().split('\n').filter(Boolean).slice(0, MAX_IMAGES_TO_SCAN);
    const heuristicFindings = collectHeuristicFindings(lines);

    if (!TrivyClient.isConfigured()) return heuristicFindings;

    // Build the list of images to deep-scan: dedupe by image:tag, drop dangling
    // (<none>) refs that Trivy can't resolve, cap to keep scan time bounded.
    const scanTargets = pickScanTargets(lines, MAX_TRIVY_TARGETS);
    const trivyFindings = await runTrivyScans(target, scanTargets);

    return [...heuristicFindings, ...trivyFindings];
  }
}

function collectHeuristicFindings(lines: string[]): DockerVuln[] {
  const out: DockerVuln[] = [];
  for (const line of lines) {
    const parts = line.split(' ');
    const imageTag = parts[0];
    const age = parts.slice(1).join(' ');
    const [image, tag] = imageTag.split(':');
    if (!image || !tag) continue;

    if (tag === 'latest') {
      out.push({ image, tag, issue: 'Using :latest tag (unpinned version)', severity: 'medium' });
    }

    if (age.includes('months') || age.includes('years')) {
      const months = age.includes('years') ? parseInt(age) * 12 : parseInt(age);
      if (months >= 6) {
        out.push({
          image,
          tag,
          issue: `Image is ${age} old`,
          severity: months >= 12 ? 'high' : 'medium',
        });
      }
    }
  }
  return out;
}

function pickScanTargets(lines: string[], limit: number): Array<{ image: string; tag: string }> {
  const seen = new Set<string>();
  const out: Array<{ image: string; tag: string }> = [];
  for (const line of lines) {
    const imageTag = line.split(' ')[0];
    // Split on the LAST colon — image refs like `registry:5000/img:tag`
    // contain a port colon in the host segment; only the trailing colon
    // separates the tag. `imageTag.split(':')` was producing
    // image='registry', tag='5000/img', which made Trivy scan a
    // nonexistent ref and silently skip the alert.
    const lastColon = imageTag.lastIndexOf(':');
    if (lastColon <= 0) continue;
    const image = imageTag.slice(0, lastColon);
    const tag = imageTag.slice(lastColon + 1);
    if (!image || !tag) continue;
    if (image === '<none>' || tag === '<none>') continue;
    const key = `${image}:${tag}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ image, tag });
    if (out.length >= limit) break;
  }
  return out;
}

async function runTrivyScans(
  target: SSHTarget,
  scanTargets: Array<{ image: string; tag: string }>,
): Promise<DockerVuln[]> {
  const out: DockerVuln[] = [];
  for (const { image, tag } of scanTargets) {
    try {
      const findings = await TrivyClient.scanImage(target, image, tag);
      for (const f of findings) {
        out.push(trivyToDockerVuln(f));
      }
    } catch (err) {
      logger.debug({ err, image, tag, host: target.host }, 'Trivy scan failed for image');
      // Skip and continue — one bad image shouldn't tank the whole audit.
    }
  }
  return out;
}

function trivyToDockerVuln(f: TrivyFinding): DockerVuln {
  const fixHint = f.fixedVersion
    ? ` — fix in ${f.fixedVersion}`
    : ' — no fix available';
  return {
    image: f.image,
    tag: f.tag,
    issue: `${f.cveId} in ${f.packageName} ${f.installedVersion}${fixHint}`,
    severity: f.severity === 'unknown' ? 'medium' : f.severity,
    cveId: f.cveId,
    packageName: f.packageName,
    fixedVersion: f.fixedVersion,
  };
}
