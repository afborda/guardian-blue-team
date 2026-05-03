import { ServerService } from '../services/server.service.js';
import { PortScanner } from './port-scanner.js';
import { PackageAuditor } from './package-audit.js';
import { DockerAuditor } from './docker-audit.js';
import { db } from '../database/connection.js';
import { vulnerabilities } from '../database/schema.js';
import { eq, and } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export interface ScanResult {
  serverName: string;
  portsOpen: number;
  portsUnexpected: number;
  packagesUpgradable: number;
  securityUpdates: number;
  dockerIssues: number;
  sslIssues: number;
  totalFindings: number;
}

export class VulnScanner {
  static async scanServer(serverId: number): Promise<ScanResult | null> {
    const servers = await ServerService.getAll();
    const server = servers.find(s => s.id === serverId);
    if (!server) return null;

    const target = ServerService.toSSHTarget(server);

    const [ports, packages, docker] = await Promise.all([
      PortScanner.scan(target, server.tags),
      PackageAuditor.audit(target),
      DockerAuditor.audit(target),
    ]);

    for (const p of ports.unexpected) {
      await this.upsertVuln(serverId, 'port', 'medium', `Unexpected open port: ${p.port} (${p.service})`);
    }

    for (const pkg of packages.upgradable.filter(p => p.severity === 'high')) {
      await this.upsertVuln(serverId, 'package', 'high', `Security update: ${pkg.package} ${pkg.installedVersion} → ${pkg.availableVersion}`);
    }

    for (const d of docker) {
      await this.upsertVuln(serverId, 'docker', d.severity, `${d.image}:${d.tag} — ${d.issue}`);
    }

    return {
      serverName: server.name,
      portsOpen: ports.open.length,
      portsUnexpected: ports.unexpected.length,
      packagesUpgradable: packages.upgradable.length,
      securityUpdates: packages.securityUpdates,
      dockerIssues: docker.length,
      sslIssues: 0,
      totalFindings: ports.unexpected.length + packages.securityUpdates + docker.length,
    };
  }

  static async scanAll(): Promise<ScanResult[]> {
    const servers = await ServerService.getEnabled();
    const results: ScanResult[] = [];

    for (const server of servers) {
      const result = await this.scanServer(server.id);
      if (result) results.push(result);
    }

    logger.info({ servers: results.length, findings: results.reduce((t, r) => t + r.totalFindings, 0) }, 'Vulnerability scan complete');
    return results;
  }

  static async getSummary(): Promise<Array<{ serverId: number; serverName: string; open: number; bySeverity: Record<string, number> }>> {
    const servers = await ServerService.getAll();
    const allVulns = await db.select().from(vulnerabilities).where(eq(vulnerabilities.status, 'open'));

    return servers.map(server => {
      const serverVulns = allVulns.filter(v => v.serverId === server.id);
      const bySeverity: Record<string, number> = {};
      for (const v of serverVulns) {
        const sev = v.severity ?? 'unknown';
        bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
      }
      return {
        serverId: server.id,
        serverName: server.name,
        open: serverVulns.length,
        bySeverity,
      };
    });
  }

  private static async upsertVuln(serverId: number, category: string, severity: string, title: string): Promise<void> {
    const existing = await db.select()
      .from(vulnerabilities)
      .where(and(
        eq(vulnerabilities.serverId, serverId),
        eq(vulnerabilities.title, title),
        eq(vulnerabilities.status, 'open'),
      ))
      .then(rows => rows[0]);

    if (!existing) {
      await db.insert(vulnerabilities).values({ serverId, category, severity, title });
    }
  }
}
