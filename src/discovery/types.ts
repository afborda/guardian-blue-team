import { z } from 'zod';

export interface ProbeResult<T = unknown> {
  name: string;
  success: boolean;
  data: T;
  error?: string;
  durationMs: number;
}

export interface NetworkData {
  hostname: string;
  sshPort: number | null;
  listeningPorts: Array<{ port: number; process: string; address: string }>;
  interfaces: Array<{ name: string; ipv4: string; ipv6?: string }>;
  dns: string[];
}

export interface ProxyData {
  detected: 'traefik' | 'nginx' | 'caddy' | 'haproxy' | 'none';
  version: string | null;
  config: string | null;
  domains: string[];
  sslCerts: Array<{ domain: string; expiresAt: string | null }>;
  traefikLabels: Record<string, string>[];
}

export interface DockerData {
  installed: boolean;
  runtime: 'docker' | 'podman' | null;
  version: string | null;
  containers: Array<{ name: string; image: string; state: string; ports: string }>;
  networks: string[];
  volumes: string[];
  composeFiles: string[];
}

export interface SecurityData {
  firewall: { tool: 'iptables' | 'nftables' | 'ufw' | 'none'; rules: string };
  fail2ban: { active: boolean; jails: string[]; recentBans: number };
  sshConfig: { port: number; permitRoot: string; passwordAuth: string; keyAuth: string };
  mac: { type: 'selinux' | 'apparmor' | 'none'; status: string };
  users: Array<{ name: string; shell: string; hasSudo: boolean }>;
  cronJobs: string[];
}

export interface SystemData {
  os: { name: string; version: string; id: string };
  kernel: string;
  cpu: { cores: number; model: string };
  memoryMb: { total: number; used: number; available: number };
  disks: Array<{ mount: string; sizeMb: number; usedPercent: number }>;
  packages: string[];
  services: Array<{ name: string; active: boolean }>;
  uptime: string;
  load: number[];
  recentAuthLogs: string[];
  recentSysLogs: string[];
}

export interface ServerSnapshot {
  timestamp: string;
  scanDurationMs: number;
  transport: 'local' | 'ssh';
  target: { host: string; port: number; user: string };
  probes: {
    network: ProbeResult<NetworkData>;
    proxy: ProbeResult<ProxyData>;
    docker: ProbeResult<DockerData>;
    security: ProbeResult<SecurityData>;
    system: ProbeResult<SystemData>;
  };
}

export const discoveryResultSchema = z.object({
  summary: z.string(),
  architecture: z.enum([
    'traefik-docker', 'nginx-standalone', 'nginx-docker',
    'caddy', 'haproxy', 'bare-metal', 'unknown',
  ]),
  confidence: z.number().min(0).max(100),
  env: z.record(z.string(), z.string()),
  dockerCompose: z.string().optional(),
  systemdUnit: z.string().optional(),
  proxyConfig: z.string().optional(),
  warnings: z.array(z.string()),
  recommendations: z.array(z.string()),
  monitoringProfile: z.object({
    services: z.array(z.string()),
    logPaths: z.array(z.string()),
    criticalPorts: z.array(z.number()),
    customChecks: z.array(z.union([z.string(), z.object({}).passthrough()])).transform(arr =>
      arr.map(item => typeof item === 'string' ? item : JSON.stringify(item))
    ),
  }),
});

export type DiscoveryResult = z.infer<typeof discoveryResultSchema>;
