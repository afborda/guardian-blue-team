import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';
import { logger } from '../utils/logger.js';

export interface ContainerImageInfo {
  serverId: number;
  imageName: string;
  imageTag: string;
  imageDigest: string;
  size: string;
  containers: string[];
}

export interface ImageCVE {
  cveId: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion: string | null;
  severity: string;
  title: string;
  cvss: number;
}

export class ContainerImageCollector {
  /**
   * Collects inventory of images used by running containers.
   * Lightweight: 1 SSH call, ~1KB output.
   */
  static async collectImages(target: SSHTarget): Promise<ContainerImageInfo[]> {
    const cmd = `docker ps --format '{{.Image}}\t{{.Names}}' 2>/dev/null && echo '---IMAGES---' && docker images --format '{{.Repository}}\t{{.Tag}}\t{{.Digest}}\t{{.Size}}' 2>/dev/null | head -50`;

    const result = await SSHCollector.run(target, cmd, 15_000);
    if (!result.success) return [];

    const lines = result.stdout.trim().split('\n');
    const separatorIdx = lines.indexOf('---IMAGES---');

    // Parse running containers: image → container names
    const imageToContainers = new Map<string, string[]>();
    for (let i = 0; i < (separatorIdx >= 0 ? separatorIdx : lines.length); i++) {
      const [image, containerName] = (lines[i] ?? '').split('\t');
      if (!image || !containerName) continue;
      const existing = imageToContainers.get(image) ?? [];
      existing.push(containerName);
      imageToContainers.set(image, existing);
    }

    // Parse image metadata
    const images: ContainerImageInfo[] = [];
    for (let i = (separatorIdx >= 0 ? separatorIdx + 1 : lines.length); i < lines.length; i++) {
      const [repo, tag, digest, size] = (lines[i] ?? '').split('\t');
      if (!repo || repo === '<none>') continue;

      const fullName = tag && tag !== '<none>' ? `${repo}:${tag}` : repo;
      const containers = imageToContainers.get(fullName) ?? imageToContainers.get(repo) ?? [];

      // Only include images that are actually running
      if (containers.length === 0) continue;

      images.push({
        serverId: target.id,
        imageName: repo,
        imageTag: tag ?? 'latest',
        imageDigest: digest ?? '',
        size: size ?? '',
        containers,
      });
    }

    return images;
  }

  /**
   * Scans a single image for CVEs using Trivy.
   * Heavy: 10-30s per image, 50-200MB I/O on first run (cached after).
   * Only call if Trivy is installed on target server.
   */
  static async scanImageCVEs(target: SSHTarget, imageName: string): Promise<ImageCVE[]> {
    // Sanitize image name to prevent injection
    const safeImage = imageName.replace(/[^a-zA-Z0-9./_:@-]/g, '');
    if (!safeImage) return [];

    const cmd = `trivy image --severity CRITICAL,HIGH --format json --quiet "${safeImage}" 2>/dev/null | head -c 500000`;

    const result = await SSHCollector.run(target, cmd, 120_000);
    if (!result.success || !result.stdout.trim()) return [];

    try {
      const report = JSON.parse(result.stdout);
      const cves: ImageCVE[] = [];

      for (const resultItem of report.Results ?? []) {
        for (const vuln of resultItem.Vulnerabilities ?? []) {
          cves.push({
            cveId: vuln.VulnerabilityID ?? '',
            pkgName: vuln.PkgName ?? '',
            installedVersion: vuln.InstalledVersion ?? '',
            fixedVersion: vuln.FixedVersion || null,
            severity: (vuln.Severity ?? '').toLowerCase(),
            title: vuln.Title ?? vuln.Description?.slice(0, 200) ?? '',
            cvss: vuln.CVSS?.nvd?.V3Score ?? vuln.CVSS?.redhat?.V3Score ?? 0,
          });
        }
      }

      return cves;
    } catch (err) {
      logger.warn({ err, image: safeImage }, 'Failed to parse Trivy output');
      return [];
    }
  }

  /**
   * Checks if Trivy is installed on the target server.
   */
  static async isTrivyAvailable(target: SSHTarget): Promise<boolean> {
    const result = await SSHCollector.run(target, 'which trivy 2>/dev/null', 5_000);
    return result.success && result.stdout.trim().length > 0;
  }

  /**
   * Generates RawLogEntry events from CVE scan results for the detection pipeline.
   */
  static cvesToRawEntries(target: SSHTarget, imageName: string, cves: ImageCVE[]): RawLogEntry[] {
    return cves
      .filter(cve => cve.cvss >= 7.0)
      .map(cve => ({
        serverId: target.id,
        serverName: target.name,
        source: 'container_image_cve',
        timestamp: new Date(),
        line: `${imageName}|${cve.cveId}|${cve.severity}|${cve.cvss}|${cve.pkgName}|${cve.installedVersion}|${cve.fixedVersion ?? 'none'}|${cve.title}`,
      }));
  }
}
