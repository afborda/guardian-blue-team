import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';

export interface ContainerInfo {
  name: string;
  image: string;
  status: string;
  ports: string;
  cpuPercent: number;
  memUsage: string;
}

export class DockerCollector {
  static async collectContainerEvents(target: SSHTarget, sinceMinutes = 5): Promise<RawLogEntry[]> {
    const since = Math.floor((Date.now() - sinceMinutes * 60_000) / 1000);

    const result = await SSHCollector.run(target,
      `docker events --since ${since} --until $(date +%s) --format '{{json .}}' 2>/dev/null | head -50 || echo ''`,
      15_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(line => line.startsWith('{'))
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'docker',
        timestamp: new Date(),
        line,
      }));
  }

  static async listContainers(target: SSHTarget): Promise<ContainerInfo[]> {
    const result = await SSHCollector.run(target,
      "docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' 2>/dev/null | head -40",
      15_000
    );

    if (!result.success) return [];

    return result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(line => {
        const [name, cpu, mem] = line.split('\t');
        return {
          name: name ?? '',
          image: '',
          status: 'running',
          ports: '',
          cpuPercent: parseFloat(cpu?.replace('%', '') ?? '0'),
          memUsage: mem ?? '0',
        };
      });
  }

  static async detectAnomalies(target: SSHTarget): Promise<RawLogEntry[]> {
    const result = await SSHCollector.run(target,
      "docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | grep -i 'restarting\\|unhealthy' || echo ''",
      10_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(Boolean)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'docker',
        timestamp: new Date(),
        line: `ANOMALY: ${line}`,
      }));
  }
}
