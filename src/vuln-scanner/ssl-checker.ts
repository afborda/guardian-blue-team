import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';

export interface SSLFinding {
  domain: string;
  daysUntilExpiry: number;
  issuer: string;
  severity: string;
}

export class SSLChecker {
  static async check(target: SSHTarget, domains: string[]): Promise<SSLFinding[]> {
    const findings: SSLFinding[] = [];

    for (const domain of domains) {
      const result = await SSHCollector.run(target,
        `echo | openssl s_client -servername ${domain} -connect ${domain}:443 2>/dev/null | openssl x509 -noout -dates -issuer 2>/dev/null`,
        10_000
      );

      if (!result.success) continue;

      const notAfter = result.stdout.match(/notAfter=(.+)/);
      const issuerMatch = result.stdout.match(/issuer=(.+)/);

      if (notAfter) {
        const expiryDate = new Date(notAfter[1]);
        const daysUntilExpiry = Math.floor((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));

        let severity = 'info';
        if (daysUntilExpiry <= 7) severity = 'critical';
        else if (daysUntilExpiry <= 30) severity = 'high';
        else if (daysUntilExpiry <= 60) severity = 'medium';

        findings.push({
          domain,
          daysUntilExpiry,
          issuer: issuerMatch?.[1]?.trim() ?? 'unknown',
          severity,
        });
      }
    }

    return findings;
  }
}
