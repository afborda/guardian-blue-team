import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';
import { isPrivateIp } from '../utils/sanitize.js';
import { logger } from '../utils/logger.js';

export interface SynSentConnection {
  pid: number;
  process: string;
  remoteIp: string;
  remotePort: number;
}

export interface EgressSummary {
  container: string;
  synSent: number;
  distinctDst: number;
  distinctPorts: number;
  web: number;
  rfc1918: number;
  sample: string[];
}

const SYN_LINE = /SYN-SENT\s+\d+\s+\d+\s+\S+\s+(\S+)\s+users:\(\("([^"]+)",pid=(\d+)/;

function splitHostPort(value: string): { host: string; port: number } | null {
  const match = value.match(/^\[?([^\]]+?)\]?:(\d+)$/);
  if (!match) return null;
  const port = Number.parseInt(match[2] ?? '0', 10);
  if (!match[1] || port <= 0) return null;
  return { host: match[1], port };
}

/** Parseia `ss -tnp state syn-sent` (host network namespace). */
export function parseSynSent(output: string): SynSentConnection[] {
  const rows: SynSentConnection[] = [];

  for (const line of output.split('\n')) {
    const match = line.match(SYN_LINE);
    if (!match) continue;
    const peer = splitHostPort(match[1] ?? '');
    if (!peer) continue;
    rows.push({
      pid: Number.parseInt(match[3] ?? '0', 10),
      process: match[2] ?? 'unknown',
      remoteIp: peer.host,
      remotePort: peer.port,
    });
  }

  return rows;
}

/**
 * Agrega conexões SYN_SENT de UMA rede de container (já coletadas via
 * `nsenter -n ss`). `pidToContainer` é opcional: quando presente, só conta
 * conexões de PIDs mapeados (usado nos testes e em coletas host-level).
 */
export function summarizeEgress(
  connections: SynSentConnection[],
  pidToContainer: Map<number, string>,
): EgressSummary[] {
  const byContainer = new Map<string, {
    synSent: number;
    destinations: Set<string>;
    ports: Set<number>;
    web: Set<string>;
    rfc1918: Set<string>;
    sample: string[];
  }>();

  for (const connection of connections) {
    const container = pidToContainer.get(connection.pid);
    if (!container) continue;

    const entry = byContainer.get(container) ?? {
      synSent: 0,
      destinations: new Set<string>(),
      ports: new Set<number>(),
      web: new Set<string>(),
      rfc1918: new Set<string>(),
      sample: [],
    };

    entry.synSent++;
    entry.destinations.add(connection.remoteIp);
    entry.ports.add(connection.remotePort);
    if (connection.remotePort === 80 || connection.remotePort === 443) {
      entry.web.add(connection.remoteIp);
    }
    if (isPrivateIp(connection.remoteIp)) {
      entry.rfc1918.add(connection.remoteIp);
    }
    if (entry.sample.length < 3) {
      entry.sample.push(`${connection.remoteIp}:${connection.remotePort}`);
    }

    byContainer.set(container, entry);
  }

  return [...byContainer.entries()]
    .map(([container, entry]) => ({
      container,
      synSent: entry.synSent,
      distinctDst: entry.destinations.size,
      distinctPorts: entry.ports.size,
      web: entry.web.size,
      rfc1918: entry.rfc1918.size,
      sample: entry.sample,
    }))
    .sort((a, b) => b.distinctDst - a.distinctDst);
}

export function summarizeContainer(container: string, connections: SynSentConnection[]): EgressSummary | null {
  if (connections.length === 0) return null;
  const destinations = new Set<string>();
  const ports = new Set<number>();
  const web = new Set<string>();
  const rfc1918 = new Set<string>();
  const sample: string[] = [];

  for (const connection of connections) {
    destinations.add(connection.remoteIp);
    ports.add(connection.remotePort);
    if (connection.remotePort === 80 || connection.remotePort === 443) web.add(connection.remoteIp);
    if (isPrivateIp(connection.remoteIp)) rfc1918.add(connection.remoteIp);
    if (sample.length < 3) sample.push(`${connection.remoteIp}:${connection.remotePort}`);
  }

  return {
    container,
    synSent: connections.length,
    distinctDst: destinations.size,
    distinctPorts: ports.size,
    web: web.size,
    rfc1918: rfc1918.size,
    sample,
  };
}

export class EgressCollector {
  /**
   * Coleta, por container, conexões de saída em SYN_SENT e agrega fan-out.
   * Cada container custa um `docker top` (leitura curta) — sem loops shell,
   * para funcionar com o guardian-shell (hash allowlist).
   */
  static async collect(target: SSHTarget): Promise<RawLogEntry[]> {
    const list = await SSHCollector.run(
      target,
      "docker ps --format '{{.ID}}\\t{{.Names}}' 2>/dev/null | head -40",
      10_000,
    );
    if (!list.success || !list.stdout.trim()) return [];

    const containers = list.stdout.trim().split('\n').map(line => {
      const [id, name] = line.split('\t');
      return { id: id?.trim() ?? '', name: name?.trim() ?? '' };
    }).filter(item => item.id.length >= 12 && item.name.length > 0);

    const entries: RawLogEntry[] = [];

    for (const container of containers) {
      const inspect = await SSHCollector.run(
        target,
        `docker inspect --format '{{.State.Pid}}|{{.HostConfig.NetworkMode}}' ${container.id} 2>/dev/null`,
        10_000,
      );
      const [pidRaw, networkMode = ''] = inspect.stdout.trim().split('|');
      const pid = Number.parseInt(pidRaw ?? '', 10);
      if (!inspect.success || !Number.isFinite(pid) || pid <= 0) continue;
      // Container em host network compartilha o netns do host; os sockets não
      // são atribuíveis só a ele e gerariam falso positivo.
      if (networkMode === 'host') continue;

      const syn = await SSHCollector.run(
        target,
        `sudo nsenter -t ${pid} -n ss -tnp state syn-sent 2>/dev/null | head -200`,
        10_000,
      );
      if (!syn.success || !syn.stdout.trim()) continue;

      const summary = summarizeContainer(container.name, parseSynSent(syn.stdout));
      if (!summary) continue;

      entries.push({
        serverId: target.id,
        serverName: target.name,
        source: 'container_egress',
        timestamp: new Date(),
        line: [
          summary.container,
          `syn=${summary.synSent}`,
          `dst=${summary.distinctDst}`,
          `ports=${summary.distinctPorts}`,
          `web=${summary.web}`,
          `rfc=${summary.rfc1918}`,
          `sample=${summary.sample.join(',')}`,
        ].join('|'),
      });
    }

    if (entries.length > 0) {
      logger.info({ server: target.name, containers: entries.length }, 'Egress collector found SYN_SENT fan-out');
    } else {
      logger.debug({ server: target.name, containers: containers.length }, 'Egress collector cycle: no SYN_SENT');
    }

    return entries;
  }
}
