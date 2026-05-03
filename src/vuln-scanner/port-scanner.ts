import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';

export interface PortFinding {
  port: number;
  service: string;
  state: string;
}

export class PortScanner {
  private static readonly EXPECTED_OPEN: Record<string, number[]> = {
    default: [22, 80, 443],
  };

  static async scan(target: SSHTarget, tags: string[] = []): Promise<{ open: PortFinding[]; unexpected: PortFinding[] }> {
    const result = await SSHCollector.run(target,
      "sudo ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | grep -oP '\\d+$' | sort -un",
      15_000
    );

    if (!result.success) return { open: [], unexpected: [] };

    const openPorts = result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(p => parseInt(p))
      .filter(p => !isNaN(p));

    const open: PortFinding[] = openPorts.map(port => ({
      port,
      service: this.guessService(port),
      state: 'open',
    }));

    const expectedPorts = this.EXPECTED_OPEN[tags[0]] ?? this.EXPECTED_OPEN.default;
    const unexpected = open.filter(p => !expectedPorts.includes(p.port) && p.port > 1024);

    return { open, unexpected };
  }

  private static guessService(port: number): string {
    const services: Record<number, string> = {
      22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
      5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-alt',
      27017: 'MongoDB', 9090: 'Prometheus', 3000: 'Grafana',
    };
    return services[port] ?? `unknown-${port}`;
  }
}
