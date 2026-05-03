import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';

export interface PackageVuln {
  package: string;
  installedVersion: string;
  availableVersion: string;
  severity: string;
}

export class PackageAuditor {
  static async audit(target: SSHTarget): Promise<{ upgradable: PackageVuln[]; securityUpdates: number }> {
    const result = await SSHCollector.run(target,
      "apt list --upgradable 2>/dev/null | tail -n +2 | head -30",
      20_000
    );

    if (!result.success) return { upgradable: [], securityUpdates: 0 };

    const lines = result.stdout.trim().split('\n').filter(Boolean);
    let securityUpdates = 0;

    const upgradable: PackageVuln[] = lines.map(line => {
      const match = line.match(/^(\S+)\/\S+ (\S+) \S+ \[upgradable from: (\S+)\]/);
      if (!match) return null;

      const isSecurity = line.includes('-security');
      if (isSecurity) securityUpdates++;

      return {
        package: match[1],
        availableVersion: match[2],
        installedVersion: match[3],
        severity: isSecurity ? 'high' : 'low',
      };
    }).filter((x): x is PackageVuln => x !== null);

    return { upgradable, securityUpdates };
  }
}
