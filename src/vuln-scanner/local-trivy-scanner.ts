/**
 * LocalTrivyScanner — runs `trivy image` directly inside the Guardian container,
 * targeting the local Docker daemon via the mounted docker.sock.
 *
 * Unlike TrivyClient (which SSHes to a remote host), this runs trivy as a
 * child process here and needs no SSH at all. The heavy vuln DB is kept in
 * the guardian-trivy server container; we use --server to avoid downloading it.
 *
 * TODO: when remote servers also need scanning, add a per-server scan path
 * that SSHes in and runs trivy --server pointing back to guardian-trivy.
 */

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { logger } from '../utils/logger.js';
import { config } from '../config/environment.js';

const execFileAsync = promisify(execFile);

const CACHE_DIR = '/data/trivy-cache';
const SCAN_TIMEOUT_MS = 5 * 60_000;
const MAX_FINDINGS_PER_IMAGE = 100;

export interface LocalTrivyFinding {
  imageRef: string;
  cveId: string;
  severity: 'critical' | 'high';
  packageName: string;
  packageType: string;
  installedVersion: string;
  fixedVersion: string | null;
  title: string;
}

interface TrivyJsonReport {
  Results?: Array<{
    Target?: string;
    Type?: string;
    Vulnerabilities?: Array<{
      VulnerabilityID: string;
      PkgName: string;
      PkgType?: string;
      Type?: string;
      InstalledVersion: string;
      FixedVersion?: string;
      Severity: string;
      Title?: string;
      Description?: string;
    }>;
  }>;
}

export class LocalTrivyScanner {
  static async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync('which', ['trivy'], { timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  static async getRunningImages(): Promise<string[]> {
    try {
      const { stdout } = await execFileAsync('docker', ['ps', '--format', '{{.Image}}'], { timeout: 10_000 });
      const images = stdout.trim().split('\n').filter(Boolean);
      return [...new Set(images)];
    } catch (err) {
      logger.warn({ err }, 'LocalTrivyScanner: failed to list running images');
      return [];
    }
  }

  static async scanImage(imageRef: string): Promise<LocalTrivyFinding[]> {
    const args = [
      'image',
      '--cache-dir', CACHE_DIR,
      '--quiet',
      '--format', 'json',
      '--scanners', 'vuln',
      '--severity', 'HIGH,CRITICAL',
      '--timeout', '4m30s',
    ];

    const trivyServerUrl = config.trivy?.serverUrl;
    if (trivyServerUrl) {
      args.push('--server', trivyServerUrl);
      if (config.trivy?.token) args.push('--token', config.trivy.token);
    }

    args.push(imageRef);

    try {
      const { stdout } = await execFileAsync('trivy', args, {
        timeout: SCAN_TIMEOUT_MS,
        maxBuffer: 20 * 1024 * 1024,
      });

      if (!stdout.trim()) return [];
      return this.parseReport(imageRef, stdout);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('timeout')) {
        logger.warn({ imageRef }, 'LocalTrivyScanner: scan timed out');
      } else {
        logger.debug({ imageRef, err: msg }, 'LocalTrivyScanner: scan failed');
      }
      return [];
    }
  }

  private static parseReport(imageRef: string, raw: string): LocalTrivyFinding[] {
    let report: TrivyJsonReport;
    try {
      report = JSON.parse(raw) as TrivyJsonReport;
    } catch {
      return [];
    }

    const findings: LocalTrivyFinding[] = [];
    for (const result of report.Results ?? []) {
      for (const v of result.Vulnerabilities ?? []) {
        const sev = v.Severity?.toUpperCase();
        if (sev !== 'CRITICAL' && sev !== 'HIGH') continue;

        findings.push({
          imageRef,
          cveId: v.VulnerabilityID,
          severity: sev === 'CRITICAL' ? 'critical' : 'high',
          packageName: v.PkgName,
          packageType: v.PkgType ?? v.Type ?? result.Type ?? 'os',
          installedVersion: v.InstalledVersion,
          fixedVersion: v.FixedVersion ?? null,
          title: (v.Title ?? v.Description ?? '').slice(0, 200),
        });

        if (findings.length >= MAX_FINDINGS_PER_IMAGE) return findings;
      }
    }
    return findings;
  }

  /** Scan all running images. Returns map imageRef → findings. Never throws. */
  static async scanAll(): Promise<Map<string, LocalTrivyFinding[]>> {
    const result = new Map<string, LocalTrivyFinding[]>();

    const images = await this.getRunningImages();
    if (images.length === 0) return result;

    logger.info({ count: images.length }, 'LocalTrivyScanner: scanning running images');

    // Sequential scan — Trivy server handles one image at a time to avoid
    // overloading the server while it's loading the vuln DB.
    for (const img of images) {
      try {
        const findings = await this.scanImage(img);
        result.set(img, findings);
      } catch {
        // scanImage already catches internally; this is a safety net
      }
    }

    const totalFindings = [...result.values()].reduce((n, f) => n + f.length, 0);
    logger.info({ images: result.size, findings: totalFindings }, 'LocalTrivyScanner: scan complete');

    return result;
  }
}
