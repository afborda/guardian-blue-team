import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';

export interface DiskIoSample {
  device: string;
  readBps: number;
  writeBps: number;
}

export interface NetworkIoSample {
  iface: string;
  rxBps: number;
  txBps: number;
}

export interface RawPerformanceMetrics {
  serverId: number;
  serverName: string;
  collectedAt: Date;
  diskIo: DiskIoSample[];
  networkIo: NetworkIoSample[];
}

export class PerformanceCollector {
  static async collect(target: SSHTarget): Promise<RawPerformanceMetrics | null> {
    const result = await SSHCollector.run(target, [
      'cat /proc/diskstats',
      'echo "---PSEP---"',
      'cat /proc/net/dev',
      'echo "---PSEP---"',
      'sleep 1',
      'echo "---PSEP---"',
      'cat /proc/diskstats',
      'echo "---PSEP---"',
      'cat /proc/net/dev',
    ].join(' && '), 20_000);

    if (!result.success) {
      logger.debug({ server: target.name }, 'Performance collection failed');
      return null;
    }

    try {
      return this.parse(target, result.stdout);
    } catch (err) {
      logger.debug({ server: target.name, err }, 'Performance parsing failed');
      return null;
    }
  }

  private static parse(target: SSHTarget, stdout: string): RawPerformanceMetrics {
    const sections = stdout.split('---PSEP---').map(s => s.trim());

    const diskStatsBefore = this.parseDiskStats(sections[0]);
    const netDevBefore = this.parseNetDev(sections[1]);
    const diskStatsAfter = this.parseDiskStats(sections[3]);
    const netDevAfter = this.parseNetDev(sections[4]);

    const diskIo: DiskIoSample[] = [];
    for (const [device, after] of diskStatsAfter.entries()) {
      const before = diskStatsBefore.get(device);
      if (!before) continue;
      const sectorSize = 512;
      const readBps = (after.sectorsRead - before.sectorsRead) * sectorSize;
      const writeBps = (after.sectorsWritten - before.sectorsWritten) * sectorSize;
      if (readBps > 0 || writeBps > 0) {
        diskIo.push({ device, readBps, writeBps });
      }
    }

    const networkIo: NetworkIoSample[] = [];
    for (const [iface, after] of netDevAfter.entries()) {
      const before = netDevBefore.get(iface);
      if (!before) continue;
      if (this.isVirtualInterface(iface)) continue;
      const rxBps = after.rxBytes - before.rxBytes;
      const txBps = after.txBytes - before.txBytes;
      networkIo.push({ iface, rxBps, txBps });
    }

    return {
      serverId: target.id,
      serverName: target.name,
      collectedAt: new Date(),
      diskIo,
      networkIo,
    };
  }

  // Excludes loopback and container/orchestrator virtual interfaces from
  // network totals. Docker traffic flows host-eth0 ↔ docker0/br-* ↔ veth* ↔
  // container eth0; counting all of them triples each byte and the resulting
  // sum bears no relation to actual link utilization. We keep physical NICs
  // (eth*, enp*, eno*, ens*, wl*) and VPN tunnels (tun*, tap*, wg*).
  private static isVirtualInterface(iface: string): boolean {
    if (iface === 'lo') return true;
    return /^(veth|docker|br-|cni|cali|flannel|weave|kube-)/.test(iface);
  }

  private static parseDiskStats(section: string): Map<string, { sectorsRead: number; sectorsWritten: number }> {
    const result = new Map<string, { sectorsRead: number; sectorsWritten: number }>();
    if (!section) return result;

    for (const line of section.split('\n')) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 14) continue;
      const device = parts[2];
      if (device.match(/^(loop|ram|dm-)\d+$/)) continue;
      const sectorsRead = parseInt(parts[5]) || 0;
      const sectorsWritten = parseInt(parts[9]) || 0;
      result.set(device, { sectorsRead, sectorsWritten });
    }
    return result;
  }

  private static parseNetDev(section: string): Map<string, { rxBytes: number; txBytes: number }> {
    const result = new Map<string, { rxBytes: number; txBytes: number }>();
    if (!section) return result;

    // /proc/net/dev format (modern kernels): "  eth0: <rx_bytes> <rx_pkts> ... <tx_bytes> <tx_pkts> ..."
    // The label always ends in `:` followed by whitespace, so after trim+split,
    // parts[0] = "eth0:", parts[1] = rx_bytes, parts[9] = tx_bytes.
    for (const line of section.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.includes(':')) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 10 || !parts[0].endsWith(':')) continue;
      const iface = parts[0].slice(0, -1);
      if (!iface) continue;
      const rxBytes = parseInt(parts[1]) || 0;
      const txBytes = parseInt(parts[9]) || 0;
      result.set(iface, { rxBytes, txBytes });
    }
    return result;
  }
}
