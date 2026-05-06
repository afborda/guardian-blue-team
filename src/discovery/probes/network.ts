import type { Executor } from '../executor.js';
import type { ProbeResult, NetworkData } from '../types.js';

export async function probeNetwork(exec: Executor): Promise<ProbeResult<NetworkData>> {
  const start = Date.now();
  try {
    const [portsResult, ifaceResult, dnsResult, hostnameResult] = await Promise.all([
      exec.run('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null'),
      exec.run('ip -o addr show 2>/dev/null || ifconfig 2>/dev/null'),
      exec.run('cat /etc/resolv.conf 2>/dev/null'),
      exec.run('hostname -f 2>/dev/null || hostname'),
    ]);

    const listeningPorts = parseListeningPorts(portsResult.stdout);
    const sshPort = detectSSHPort(listeningPorts);
    const interfaces = parseInterfaces(ifaceResult.stdout);
    const dns = parseDNS(dnsResult.stdout);
    const hostname = hostnameResult.stdout.trim();

    return {
      name: 'network',
      success: true,
      data: { hostname, sshPort, listeningPorts, interfaces, dns },
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      name: 'network',
      success: false,
      data: { hostname: '', sshPort: null, listeningPorts: [], interfaces: [], dns: [] },
      error: String(error),
      durationMs: Date.now() - start,
    };
  }
}

function parseListeningPorts(raw: string): NetworkData['listeningPorts'] {
  const ports: NetworkData['listeningPorts'] = [];
  for (const line of raw.split('\n')) {
    const match = line.match(/LISTEN\s+\d+\s+\d+\s+([\d.*:]+):(\d+)\s+.*users:\(\("([^"]+)"/);
    if (match) {
      ports.push({ address: match[1], port: parseInt(match[2]), process: match[3] });
      continue;
    }
    const match2 = line.match(/LISTEN\s+\d+\s+\d+\s+([\d.*:]+):(\d+)/);
    if (match2) {
      ports.push({ address: match2[1], port: parseInt(match2[2]), process: 'unknown' });
    }
  }
  return ports;
}

function detectSSHPort(ports: NetworkData['listeningPorts']): number | null {
  const sshd = ports.find(p => p.process === 'sshd' || p.process === 'ssh');
  return sshd?.port ?? null;
}

function parseInterfaces(raw: string): NetworkData['interfaces'] {
  const ifaces: NetworkData['interfaces'] = [];
  for (const line of raw.split('\n')) {
    const match = line.match(/^\d+:\s+(\S+)\s+inet\s+([\d.]+)/);
    if (match && match[1] !== 'lo') {
      ifaces.push({ name: match[1], ipv4: match[2] });
    }
  }
  return ifaces;
}

function parseDNS(raw: string): string[] {
  return raw.split('\n')
    .filter(l => l.startsWith('nameserver'))
    .map(l => l.replace('nameserver', '').trim());
}
