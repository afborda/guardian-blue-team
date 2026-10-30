import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';
import { isPrivateIp } from '../utils/sanitize.js';
import { logger } from '../utils/logger.js';

export interface SocketConnection {
  state: 'syn-sent' | 'established' | 'other';
  localPort: number;
  pid: number;
  process: string;
  remoteIp: string;
  remotePort: number;
}

/** Compatibilidade com o nome antigo usado nos testes. */
export type SynSentConnection = SocketConnection;

export interface EgressSummary {
  container: string;
  synSent: number;
  distinctDst: number;
  distinctPorts: number;
  web: number;
  rfc1918: number;
  /** Conexões established de saída para 80/443. */
  establishedWeb: number;
  /** Destinos distintos nessas conexões established. */
  establishedDst: number;
  sample: string[];
}

const SOCKET_LINE = /^(SYN-SENT|ESTAB|ESTABLISHED|TIME-WAIT|CLOSE-WAIT|FIN-WAIT-[12]|LAST-ACK|CLOSING)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+users:\(\("([^"]+)",pid=(\d+)/;

function splitHostPort(value: string): { host: string; port: number } | null {
  const match = value.match(/^\[?([^\]]+?)\]?:(\d+)$/);
  if (!match) return null;
  const port = Number.parseInt(match[2] ?? '0', 10);
  if (!match[1] || port <= 0) return null;
  return { host: match[1], port };
}

function normalizeState(value: string): SocketConnection['state'] {
  if (value === 'SYN-SENT') return 'syn-sent';
  if (value === 'ESTAB' || value === 'ESTABLISHED') return 'established';
  return 'other';
}

/** Parseia `ss -tnp` (todos os estados) dentro do netns do container. */
export function parseSockets(output: string): SocketConnection[] {
  const rows: SocketConnection[] = [];

  for (const line of output.split('\n')) {
    const match = line.trim().match(SOCKET_LINE);
    if (!match) continue;
    const local = splitHostPort(match[2] ?? '');
    const peer = splitHostPort(match[3] ?? '');
    if (!local || !peer) continue;
    rows.push({
      state: normalizeState(match[1] ?? ''),
      localPort: local.port,
      pid: Number.parseInt(match[5] ?? '0', 10),
      process: match[4] ?? 'unknown',
      remoteIp: peer.host,
      remotePort: peer.port,
    });
  }

  return rows;
}

/** Mantido para os testes/consumidores antigos: só SYN_SENT. */
export function parseSynSent(output: string): SocketConnection[] {
  return parseSockets(output).filter(connection => connection.state === 'syn-sent');
}

function isOutboundWeb(connection: SocketConnection): boolean {
  // Inbound em servidor web tem localPort 80/443 e peer efêmero; egress tem
  // o inverso. Só contamos o segundo caso.
  return connection.state === 'established'
    && (connection.remotePort === 80 || connection.remotePort === 443)
    && connection.localPort !== 80
    && connection.localPort !== 443;
}

export function summarizeContainer(container: string, connections: SocketConnection[]): EgressSummary | null {
  if (connections.length === 0) return null;

  const synDestinations = new Set<string>();
  const synPorts = new Set<number>();
  const synWeb = new Set<string>();
  const rfc1918 = new Set<string>();
  const establishedDst = new Set<string>();
  const sample: string[] = [];
  let synSent = 0;
  let establishedWeb = 0;

  for (const connection of connections) {
    if (connection.state === 'syn-sent') {
      synSent++;
      synDestinations.add(connection.remoteIp);
      synPorts.add(connection.remotePort);
      if (connection.remotePort === 80 || connection.remotePort === 443) {
        synWeb.add(connection.remoteIp);
      }
      if (isPrivateIp(connection.remoteIp)) rfc1918.add(connection.remoteIp);
      if (sample.length < 3) sample.push(`${connection.remoteIp}:${connection.remotePort}`);
    }

    if (isOutboundWeb(connection)) {
      establishedWeb++;
      establishedDst.add(connection.remoteIp);
    }
  }

  // Um container com apenas conexões inbound (ex.: servidor web atendendo)
  // não é egress: não gera evento nem log a cada ciclo.
  if (synSent === 0 && establishedWeb === 0) return null;

  return {
    container,
    synSent,
    distinctDst: synDestinations.size,
    distinctPorts: synPorts.size,
    web: synWeb.size,
    rfc1918: rfc1918.size,
    establishedWeb,
    establishedDst: establishedDst.size,
    sample,
  };
}

/** Agrupa sockets por PID → container e resume cada container. */
export function summarizeEgress(
  connections: SocketConnection[],
  pidToContainer: Map<number, string>,
): EgressSummary[] {
  const byContainer = new Map<string, SocketConnection[]>();

  for (const connection of connections) {
    const container = pidToContainer.get(connection.pid);
    if (!container) continue;
    const rows = byContainer.get(container) ?? [];
    rows.push(connection);
    byContainer.set(container, rows);
  }

  return [...byContainer.entries()]
    .map(([container, rows]) => summarizeContainer(container, rows))
    .filter((summary): summary is EgressSummary => summary !== null)
    .sort((a, b) => (b.distinctDst + b.establishedDst) - (a.distinctDst + a.establishedDst));
}

/** Evita gravar telemetria de conexões isoladas/normais a cada ciclo. */
export function isInterestingEgress(summary: EgressSummary): boolean {
  return summary.synSent >= 5
    || summary.establishedWeb >= 5
    || summary.distinctDst >= 5
    || summary.rfc1918 >= 3;
}

export class EgressCollector {
  /**
   * Coleta, por container, sockets SYN_SENT e established no netns e agrega
   * fan-out de saída. Uma chamada `nsenter` por container; sem loops shell.
   */
  static async collect(target: SSHTarget): Promise<RawLogEntry[]> {
    const list = await SSHCollector.run(
      target,
      "docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null | head -40",
      10_000,
    );
    logger.debug({
      server: target.name,
      success: list.success,
      stdoutLen: list.stdout.length,
      error: list.error,
    }, 'Egress collector: resultado do docker ps');
    if (!list.success || !list.stdout.trim()) return [];

    const containers = list.stdout.trim().split('\n').map(line => {
      const [id, ...nameParts] = line.trim().split(/\s+/);
      return { id: id ?? '', name: nameParts.join(' ') };
    }).filter(item => item.id.length >= 12 && item.name.length > 0);

    logger.info({ server: target.name, containers: containers.length }, 'Egress collector: containers listados');
    if (containers.length === 0) return [];

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
      logger.info({ server: target.name, container: container.name, pid, networkMode }, 'Egress collector: inspect');
      // Container em host network compartilha o netns do host; os sockets não
      // são atribuíveis só a ele e gerariam falso positivo.
      if (networkMode === 'host') continue;

      const sockets = await SSHCollector.run(
        target,
        `sudo nsenter -t ${pid} -n ss -tnp 2>/dev/null | head -400`,
        10_000,
      );
      if (!sockets.success || !sockets.stdout.trim()) continue;

      const parsedSockets = parseSockets(sockets.stdout);
      const summary = summarizeContainer(container.name, parsedSockets);
      logger.info({
        server: target.name,
        container: container.name,
        sockets: parsedSockets.length,
        summary,
      }, 'Egress collector: resumo do container');
      if (!summary || !isInterestingEgress(summary)) continue;

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
          `est=${summary.establishedWeb}`,
          `estdst=${summary.establishedDst}`,
          `sample=${summary.sample.join(',')}`,
        ].join('|'),
      });
    }

    if (entries.length > 0) {
      logger.info({ server: target.name, containers: entries.length }, 'Egress collector found fan-out');
    } else {
      logger.debug({ server: target.name, containers: containers.length }, 'Egress collector cycle: no fan-out');
    }

    return entries;
  }
}
