# Auto-Discovery Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an AI-driven auto-discovery system that probes server environments and auto-configures Guardian to adapt to any architecture.

**Architecture:** A `src/discovery/` module with 5 parallel probes (network, proxy, docker, security, system) that collect a structured snapshot, send it to the AI provider for analysis, and present a generated configuration for user approval. Two entry points: CLI (install.sh local scan) and remote (SSH-based for /add-server via Telegram).

**Tech Stack:** TypeScript (ESM), Zod validation, existing SSHCollector + AIProvider, node child_process for local commands, Express routes for Telegram callbacks.

---

## File Structure

```
src/discovery/
├── types.ts                # All types: ServerSnapshot, DiscoveryResult, ProbeResult
├── executor.ts             # Shell command runner (local or SSH via SSHCollector)
├── probes/
│   ├── index.ts            # Parallel probe runner with timeouts
│   ├── network.ts          # Ports, interfaces, DNS, hostname
│   ├── proxy.ts            # Traefik/Nginx/Caddy/HAProxy detection
│   ├── docker.ts           # Container runtime, networks, volumes
│   ├── security.ts         # Firewall, fail2ban, SSH config, users, cron
│   └── system.ts           # OS, kernel, CPU/RAM/disk, packages, services, logs
├── analyzer.ts             # AI prompt construction + Zod response validation + fallback
├── templates.ts            # Heuristic fallback configs (traefik, nginx, caddy, bare-metal)
├── config-generator.ts     # DiscoveryResult → .env string + docker-compose.yml string
├── presenter.ts            # Terminal box display + Telegram message formatting
├── cli.ts                  # Entry point for install.sh (npx tsx src/discovery/cli.ts)
└── remote.ts               # Entry point for add-server (called from telegram/commands.ts)
```

**Modified files:**
- `src/telegram/commands.ts` — enhance `/add-server` to use discovery
- `src/telegram/callbacks.ts` — add discovery approval callbacks
- `install.sh` — integrate discovery CLI call

---

### Task 1: Types and Executor

**Files:**
- Create: `src/discovery/types.ts`
- Create: `src/discovery/executor.ts`

- [ ] **Step 1: Create types.ts with all interfaces**

```typescript
// src/discovery/types.ts
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
    customChecks: z.array(z.string()),
  }),
});

export type DiscoveryResult = z.infer<typeof discoveryResultSchema>;
```

- [ ] **Step 2: Create executor.ts**

```typescript
// src/discovery/executor.ts
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';

const execFileAsync = promisify(execFile);

export interface CommandResult {
  stdout: string;
  success: boolean;
}

export interface Executor {
  run(command: string, timeoutMs?: number): Promise<CommandResult>;
}

export class LocalExecutor implements Executor {
  async run(command: string, timeoutMs = 10_000): Promise<CommandResult> {
    try {
      const { stdout } = await execFileAsync('bash', ['-c', command], {
        encoding: 'utf-8',
        timeout: timeoutMs,
      });
      return { stdout, success: true };
    } catch {
      return { stdout: '', success: false };
    }
  }
}

export class SSHExecutor implements Executor {
  constructor(private target: SSHTarget) {}

  async run(command: string, timeoutMs = 10_000): Promise<CommandResult> {
    const result = await SSHCollector.run(this.target, command, timeoutMs);
    return { stdout: result.stdout, success: result.success };
  }
}
```

- [ ] **Step 3: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit --pretty 2>&1 | head -30`
Expected: No errors related to discovery files (there may be pre-existing errors in other files)

- [ ] **Step 4: Commit**

```bash
git add src/discovery/types.ts src/discovery/executor.ts
git commit -m "feat(discovery): add types and executor abstraction

ServerSnapshot, DiscoveryResult (Zod-validated), ProbeResult types.
LocalExecutor for install.sh, SSHExecutor for remote servers."
```

---

### Task 2: Network Probe

**Files:**
- Create: `src/discovery/probes/network.ts`

- [ ] **Step 1: Create network probe**

```typescript
// src/discovery/probes/network.ts
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
    // ss format: LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("traefik",pid=123,fd=7))
    const match = line.match(/LISTEN\s+\d+\s+\d+\s+([\d.*:]+):(\d+)\s+.*users:\(\("([^"]+)"/);
    if (match) {
      ports.push({ address: match[1], port: parseInt(match[2]), process: match[3] });
      continue;
    }
    // ss without users
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
  // ip -o addr format: 2: eth0 inet 192.168.1.5/24 ...
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
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/probes/network.ts
git commit -m "feat(discovery): add network probe

Detects listening ports, SSH port, network interfaces, DNS servers."
```

---

### Task 3: Proxy Probe

**Files:**
- Create: `src/discovery/probes/proxy.ts`

- [ ] **Step 1: Create proxy probe**

```typescript
// src/discovery/probes/proxy.ts
import type { Executor } from '../executor.js';
import type { ProbeResult, ProxyData } from '../types.js';

export async function probeProxy(exec: Executor): Promise<ProbeResult<ProxyData>> {
  const start = Date.now();
  try {
    const [traefikResult, nginxResult, caddyResult, haproxyResult, certsResult] = await Promise.all([
      detectTraefik(exec),
      detectNginx(exec),
      detectCaddy(exec),
      detectHAProxy(exec),
      detectCerts(exec),
    ]);

    const detected = traefikResult.found ? 'traefik'
      : nginxResult.found ? 'nginx'
      : caddyResult.found ? 'caddy'
      : haproxyResult.found ? 'haproxy'
      : 'none';

    const version = traefikResult.version ?? nginxResult.version ?? caddyResult.version ?? haproxyResult.version ?? null;
    const config = nginxResult.config ?? caddyResult.config ?? haproxyResult.config ?? null;
    const domains = [...new Set([...traefikResult.domains, ...nginxResult.domains, ...caddyResult.domains])];

    return {
      name: 'proxy',
      success: true,
      data: {
        detected,
        version,
        config,
        domains,
        sslCerts: certsResult,
        traefikLabels: traefikResult.labels,
      },
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      name: 'proxy',
      success: false,
      data: { detected: 'none', version: null, config: null, domains: [], sslCerts: [], traefikLabels: [] },
      error: String(error),
      durationMs: Date.now() - start,
    };
  }
}

interface ProxyDetection {
  found: boolean;
  version: string | null;
  config: string | null;
  domains: string[];
  labels: Record<string, string>[];
}

async function detectTraefik(exec: Executor): Promise<ProxyDetection> {
  const result = await exec.run(
    'docker ps --format "{{.Names}}|{{.Image}}|{{.Labels}}" 2>/dev/null | grep -i traefik'
  );
  if (!result.success || !result.stdout.trim()) {
    return { found: false, version: null, config: null, domains: [], labels: [] };
  }

  const versionResult = await exec.run(
    'docker exec $(docker ps -q --filter "ancestor=traefik" | head -1) traefik version 2>/dev/null | head -1'
  );
  const version = versionResult.stdout.match(/Version:\s*(\S+)/)?.[1] ?? null;

  const labelsResult = await exec.run(
    `docker inspect --format '{{json .Config.Labels}}' $(docker ps -q --filter "ancestor=traefik" | head -1) 2>/dev/null`
  );

  const domains: string[] = [];
  const labels: Record<string, string>[] = [];
  const containerLabelsResult = await exec.run(
    'docker ps --format "{{.Labels}}" 2>/dev/null'
  );

  for (const line of containerLabelsResult.stdout.split('\n')) {
    const hostMatch = line.match(/traefik\.http\.routers\.\w+\.rule=Host\(`([^`]+)`\)/);
    if (hostMatch) domains.push(hostMatch[1]);
  }

  return { found: true, version, config: null, domains, labels };
}

async function detectNginx(exec: Executor): Promise<ProxyDetection> {
  const testResult = await exec.run('nginx -v 2>&1');
  if (!testResult.success && !testResult.stdout.includes('nginx')) {
    const dockerNginx = await exec.run('docker ps --format "{{.Image}}" 2>/dev/null | grep nginx');
    if (!dockerNginx.stdout.trim()) {
      return { found: false, version: null, config: null, domains: [], labels: [] };
    }
  }

  const version = testResult.stdout.match(/nginx\/([\d.]+)/)?.[1] ?? null;
  const configResult = await exec.run(
    'cat /etc/nginx/sites-enabled/* 2>/dev/null || cat /etc/nginx/conf.d/*.conf 2>/dev/null'
  );
  const domains = [...configResult.stdout.matchAll(/server_name\s+([^;]+)/g)]
    .flatMap(m => m[1].split(/\s+/).filter(d => d !== '_' && d.includes('.')));

  return { found: true, version, config: configResult.stdout.slice(0, 2000), domains, labels: [] };
}

async function detectCaddy(exec: Executor): Promise<ProxyDetection> {
  const result = await exec.run('caddy version 2>&1');
  if (!result.success || !result.stdout.includes('v')) {
    return { found: false, version: null, config: null, domains: [], labels: [] };
  }

  const version = result.stdout.match(/v([\d.]+)/)?.[1] ?? null;
  const configResult = await exec.run('cat /etc/caddy/Caddyfile 2>/dev/null || cat ~/Caddyfile 2>/dev/null');
  const domains = [...configResult.stdout.matchAll(/^([\w.-]+\.[\w]+)\s*\{/gm)].map(m => m[1]);

  return { found: true, version, config: configResult.stdout.slice(0, 2000), domains, labels: [] };
}

async function detectHAProxy(exec: Executor): Promise<ProxyDetection> {
  const result = await exec.run('haproxy -v 2>&1');
  if (!result.success || !result.stdout.includes('HAProxy')) {
    return { found: false, version: null, config: null, domains: [], labels: [] };
  }

  const version = result.stdout.match(/version\s+([\d.]+)/)?.[1] ?? null;
  const configResult = await exec.run('cat /etc/haproxy/haproxy.cfg 2>/dev/null');

  return { found: true, version, config: configResult.stdout.slice(0, 2000), domains: [], labels: [] };
}

async function detectCerts(exec: Executor): Promise<ProxyData['sslCerts']> {
  const result = await exec.run(
    'find /etc/letsencrypt/live -name "cert.pem" 2>/dev/null | head -10'
  );
  if (!result.stdout.trim()) return [];

  const certs: ProxyData['sslCerts'] = [];
  for (const certPath of result.stdout.trim().split('\n')) {
    const domain = certPath.match(/live\/([^/]+)/)?.[1] ?? 'unknown';
    const expiryResult = await exec.run(
      `openssl x509 -enddate -noout -in "${certPath}" 2>/dev/null`
    );
    const expiresAt = expiryResult.stdout.match(/notAfter=(.+)/)?.[1] ?? null;
    certs.push({ domain, expiresAt });
  }
  return certs;
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/probes/proxy.ts
git commit -m "feat(discovery): add reverse proxy probe

Detects Traefik (Docker labels), Nginx, Caddy, HAProxy.
Extracts version, config snippets, domains, SSL cert expiry."
```

---

### Task 4: Docker Probe

**Files:**
- Create: `src/discovery/probes/docker.ts`

- [ ] **Step 1: Create docker probe**

```typescript
// src/discovery/probes/docker.ts
import type { Executor } from '../executor.js';
import type { ProbeResult, DockerData } from '../types.js';

export async function probeDocker(exec: Executor): Promise<ProbeResult<DockerData>> {
  const start = Date.now();
  try {
    const versionResult = await exec.run('docker version --format "{{.Server.Version}}" 2>/dev/null');
    const podmanResult = !versionResult.success
      ? await exec.run('podman version --format "{{.Version}}" 2>/dev/null')
      : { stdout: '', success: false };

    const installed = versionResult.success || podmanResult.success;
    const runtime: DockerData['runtime'] = versionResult.success ? 'docker' : podmanResult.success ? 'podman' : null;
    const version = versionResult.stdout.trim() || podmanResult.stdout.trim() || null;

    if (!installed) {
      return {
        name: 'docker',
        success: true,
        data: { installed: false, runtime: null, version: null, containers: [], networks: [], volumes: [], composeFiles: [] },
        durationMs: Date.now() - start,
      };
    }

    const cmd = runtime === 'podman' ? 'podman' : 'docker';
    const [containersResult, networksResult, volumesResult, composeResult] = await Promise.all([
      exec.run(`${cmd} ps --format '{{.Names}}|{{.Image}}|{{.State}}|{{.Ports}}' 2>/dev/null`),
      exec.run(`${cmd} network ls --format '{{.Name}}' 2>/dev/null`),
      exec.run(`${cmd} volume ls --format '{{.Name}}' 2>/dev/null`),
      exec.run('find / -maxdepth 4 -name "docker-compose.yml" -o -name "docker-compose.yaml" -o -name "compose.yml" -o -name "compose.yaml" 2>/dev/null | head -20'),
    ]);

    const containers = containersResult.stdout.trim().split('\n').filter(Boolean).map(line => {
      const [name, image, state, ports] = line.split('|');
      return { name: name || '', image: image || '', state: state || '', ports: ports || '' };
    });

    const networks = networksResult.stdout.trim().split('\n').filter(Boolean);
    const volumes = volumesResult.stdout.trim().split('\n').filter(Boolean);
    const composeFiles = composeResult.stdout.trim().split('\n').filter(Boolean);

    return {
      name: 'docker',
      success: true,
      data: { installed, runtime, version, containers, networks, volumes, composeFiles },
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      name: 'docker',
      success: false,
      data: { installed: false, runtime: null, version: null, containers: [], networks: [], volumes: [], composeFiles: [] },
      error: String(error),
      durationMs: Date.now() - start,
    };
  }
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/probes/docker.ts
git commit -m "feat(discovery): add Docker/Podman probe

Detects container runtime, lists running containers, networks,
volumes, and compose files on the system."
```

---

### Task 5: Security Probe

**Files:**
- Create: `src/discovery/probes/security.ts`

- [ ] **Step 1: Create security probe**

```typescript
// src/discovery/probes/security.ts
import type { Executor } from '../executor.js';
import type { ProbeResult, SecurityData } from '../types.js';

export async function probeSecurity(exec: Executor): Promise<ProbeResult<SecurityData>> {
  const start = Date.now();
  try {
    const [firewallData, fail2banData, sshConfigData, macData, usersData, cronData] = await Promise.all([
      detectFirewall(exec),
      detectFail2ban(exec),
      detectSSHConfig(exec),
      detectMAC(exec),
      detectUsers(exec),
      detectCronJobs(exec),
    ]);

    return {
      name: 'security',
      success: true,
      data: {
        firewall: firewallData,
        fail2ban: fail2banData,
        sshConfig: sshConfigData,
        mac: macData,
        users: usersData,
        cronJobs: cronData,
      },
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      name: 'security',
      success: false,
      data: {
        firewall: { tool: 'none', rules: '' },
        fail2ban: { active: false, jails: [], recentBans: 0 },
        sshConfig: { port: 22, permitRoot: 'unknown', passwordAuth: 'unknown', keyAuth: 'unknown' },
        mac: { type: 'none', status: '' },
        users: [],
        cronJobs: [],
      },
      error: String(error),
      durationMs: Date.now() - start,
    };
  }
}

async function detectFirewall(exec: Executor): Promise<SecurityData['firewall']> {
  const ufw = await exec.run('ufw status 2>/dev/null');
  if (ufw.success && ufw.stdout.includes('Status:')) {
    return { tool: 'ufw', rules: ufw.stdout.slice(0, 1500) };
  }

  const nft = await exec.run('nft list ruleset 2>/dev/null | head -100');
  if (nft.success && nft.stdout.trim()) {
    return { tool: 'nftables', rules: nft.stdout.slice(0, 1500) };
  }

  const ipt = await exec.run('iptables -L -n 2>/dev/null | head -60');
  if (ipt.success && ipt.stdout.trim()) {
    return { tool: 'iptables', rules: ipt.stdout.slice(0, 1500) };
  }

  return { tool: 'none', rules: '' };
}

async function detectFail2ban(exec: Executor): Promise<SecurityData['fail2ban']> {
  const status = await exec.run('fail2ban-client status 2>/dev/null');
  if (!status.success || !status.stdout.includes('Jail list')) {
    return { active: false, jails: [], recentBans: 0 };
  }

  const jailMatch = status.stdout.match(/Jail list:\s*(.+)/);
  const jails = jailMatch ? jailMatch[1].split(',').map(j => j.trim()).filter(Boolean) : [];

  const bansResult = await exec.run(
    'fail2ban-client status sshd 2>/dev/null | grep "Currently banned"'
  );
  const recentBans = parseInt(bansResult.stdout.match(/(\d+)/)?.[1] ?? '0');

  return { active: true, jails, recentBans };
}

async function detectSSHConfig(exec: Executor): Promise<SecurityData['sshConfig']> {
  const result = await exec.run('cat /etc/ssh/sshd_config 2>/dev/null');
  if (!result.success) {
    return { port: 22, permitRoot: 'unknown', passwordAuth: 'unknown', keyAuth: 'unknown' };
  }

  const cfg = result.stdout;
  const port = parseInt(cfg.match(/^Port\s+(\d+)/m)?.[1] ?? '22');
  const permitRoot = cfg.match(/^PermitRootLogin\s+(\S+)/m)?.[1] ?? 'unknown';
  const passwordAuth = cfg.match(/^PasswordAuthentication\s+(\S+)/m)?.[1] ?? 'unknown';
  const keyAuth = cfg.match(/^PubkeyAuthentication\s+(\S+)/m)?.[1] ?? 'unknown';

  return { port, permitRoot, passwordAuth, keyAuth };
}

async function detectMAC(exec: Executor): Promise<SecurityData['mac']> {
  const selinux = await exec.run('getenforce 2>/dev/null');
  if (selinux.success && selinux.stdout.trim()) {
    return { type: 'selinux', status: selinux.stdout.trim() };
  }

  const apparmor = await exec.run('aa-status --enabled 2>/dev/null && echo enabled');
  if (apparmor.success && apparmor.stdout.includes('enabled')) {
    return { type: 'apparmor', status: 'enabled' };
  }

  return { type: 'none', status: '' };
}

async function detectUsers(exec: Executor): Promise<SecurityData['users']> {
  const passwdResult = await exec.run(
    "awk -F: '$7 ~ /(bash|zsh|sh|fish)$/ {print $1\":\"$7}' /etc/passwd"
  );
  const sudoResult = await exec.run(
    'getent group sudo wheel 2>/dev/null | cut -d: -f4'
  );
  const sudoUsers = sudoResult.stdout.split(/[,\n]/).map(s => s.trim()).filter(Boolean);

  return passwdResult.stdout.trim().split('\n').filter(Boolean).map(line => {
    const [name, shell] = line.split(':');
    return { name, shell, hasSudo: sudoUsers.includes(name) };
  });
}

async function detectCronJobs(exec: Executor): Promise<string[]> {
  const result = await exec.run(
    'cat /etc/crontab 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done | grep -v "^#" | grep -v "^$" | head -30'
  );
  return result.stdout.trim().split('\n').filter(Boolean);
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/probes/security.ts
git commit -m "feat(discovery): add security probe

Detects firewall (ufw/iptables/nftables), fail2ban, SSH config,
SELinux/AppArmor, users with shells, cron jobs."
```

---

### Task 6: System Probe

**Files:**
- Create: `src/discovery/probes/system.ts`

- [ ] **Step 1: Create system probe**

```typescript
// src/discovery/probes/system.ts
import type { Executor } from '../executor.js';
import type { ProbeResult, SystemData } from '../types.js';

export async function probeSystem(exec: Executor): Promise<ProbeResult<SystemData>> {
  const start = Date.now();
  try {
    const [osResult, kernelResult, cpuResult, memResult, diskResult, pkgResult, svcResult, uptimeResult, loadResult, authResult, syslogResult] = await Promise.all([
      exec.run('cat /etc/os-release 2>/dev/null'),
      exec.run('uname -r'),
      exec.run('lscpu 2>/dev/null | grep -E "^(CPU\\(s\\)|Model name)" | head -2'),
      exec.run('free -m | grep Mem'),
      exec.run("df -m --output=target,size,used,pcent 2>/dev/null | grep -v tmpfs | tail -n +2"),
      exec.run('dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l || apk list --installed 2>/dev/null | wc -l'),
      exec.run('systemctl list-units --type=service --state=active --no-pager --no-legend 2>/dev/null | head -40'),
      exec.run('uptime -p 2>/dev/null || uptime'),
      exec.run('cat /proc/loadavg'),
      exec.run('tail -50 /var/log/auth.log 2>/dev/null || journalctl -u sshd -n 50 --no-pager 2>/dev/null'),
      exec.run('tail -100 /var/log/syslog 2>/dev/null || journalctl -n 100 --no-pager 2>/dev/null'),
    ]);

    const os = parseOS(osResult.stdout);
    const kernel = kernelResult.stdout.trim();
    const cpu = parseCPU(cpuResult.stdout);
    const memoryMb = parseMemory(memResult.stdout);
    const disks = parseDisks(diskResult.stdout);
    const packages = [`${pkgResult.stdout.trim()} packages installed`];
    const services = parseServices(svcResult.stdout);
    const uptime = uptimeResult.stdout.trim();
    const load = loadResult.stdout.trim().split(/\s+/).slice(0, 3).map(Number);
    const recentAuthLogs = authResult.stdout.trim().split('\n').filter(Boolean).slice(-20);
    const recentSysLogs = syslogResult.stdout.trim().split('\n').filter(Boolean).slice(-30);

    return {
      name: 'system',
      success: true,
      data: { os, kernel, cpu, memoryMb, disks, packages, services, uptime, load, recentAuthLogs, recentSysLogs },
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      name: 'system',
      success: false,
      data: {
        os: { name: '', version: '', id: '' }, kernel: '', cpu: { cores: 0, model: '' },
        memoryMb: { total: 0, used: 0, available: 0 }, disks: [], packages: [],
        services: [], uptime: '', load: [], recentAuthLogs: [], recentSysLogs: [],
      },
      error: String(error),
      durationMs: Date.now() - start,
    };
  }
}

function parseOS(raw: string): SystemData['os'] {
  const name = raw.match(/^PRETTY_NAME="?([^"\n]+)"?/m)?.[1] ?? '';
  const version = raw.match(/^VERSION_ID="?([^"\n]+)"?/m)?.[1] ?? '';
  const id = raw.match(/^ID="?([^"\n]+)"?/m)?.[1] ?? '';
  return { name, version, id };
}

function parseCPU(raw: string): SystemData['cpu'] {
  const cores = parseInt(raw.match(/CPU\(s\):\s+(\d+)/)?.[1] ?? '1');
  const model = raw.match(/Model name:\s+(.+)/)?.[1]?.trim() ?? '';
  return { cores, model };
}

function parseMemory(raw: string): SystemData['memoryMb'] {
  const parts = raw.trim().split(/\s+/);
  return { total: parseInt(parts[1] || '0'), used: parseInt(parts[2] || '0'), available: parseInt(parts[6] || '0') };
}

function parseDisks(raw: string): SystemData['disks'] {
  return raw.trim().split('\n').filter(Boolean).map(line => {
    const parts = line.trim().split(/\s+/);
    return {
      mount: parts[0] || '/',
      sizeMb: parseInt(parts[1] || '0'),
      usedPercent: parseInt(parts[3]?.replace('%', '') || '0'),
    };
  });
}

function parseServices(raw: string): SystemData['services'] {
  return raw.trim().split('\n').filter(Boolean).map(line => {
    const name = line.trim().split(/\s+/)[0]?.replace('.service', '') ?? '';
    return { name, active: true };
  });
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/probes/system.ts
git commit -m "feat(discovery): add system probe

Detects OS, kernel, CPU/RAM/disk, installed packages count,
active systemd services, uptime, load, recent auth and syslog entries."
```

---

### Task 7: Probe Runner (index.ts)

**Files:**
- Create: `src/discovery/probes/index.ts`

- [ ] **Step 1: Create parallel probe runner**

```typescript
// src/discovery/probes/index.ts
import type { Executor } from '../executor.js';
import type { ServerSnapshot } from '../types.js';
import { probeNetwork } from './network.js';
import { probeProxy } from './proxy.js';
import { probeDocker } from './docker.js';
import { probeSecurity } from './security.js';
import { probeSystem } from './system.js';

const TOTAL_TIMEOUT_MS = 120_000;

export async function runAllProbes(
  exec: Executor,
  target: { host: string; port: number; user: string },
  transport: 'local' | 'ssh',
): Promise<ServerSnapshot> {
  const start = Date.now();

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error('Total scan timeout')), TOTAL_TIMEOUT_MS)
  );

  const probes = Promise.all([
    probeNetwork(exec),
    probeProxy(exec),
    probeDocker(exec),
    probeSecurity(exec),
    probeSystem(exec),
  ]);

  const results = await Promise.race([probes, timeout]);

  return {
    timestamp: new Date().toISOString(),
    scanDurationMs: Date.now() - start,
    transport,
    target,
    probes: {
      network: results[0],
      proxy: results[1],
      docker: results[2],
      security: results[3],
      system: results[4],
    },
  };
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/probes/index.ts
git commit -m "feat(discovery): add parallel probe runner

Runs all 5 probes in parallel with 120s total timeout.
Returns aggregated ServerSnapshot."
```

---

### Task 8: AI Analyzer

**Files:**
- Create: `src/discovery/analyzer.ts`
- Create: `src/discovery/templates.ts`

- [ ] **Step 1: Create templates.ts with heuristic fallback configs**

```typescript
// src/discovery/templates.ts
import type { DiscoveryResult, ServerSnapshot } from './types.js';

export function generateFallbackConfig(snapshot: ServerSnapshot): DiscoveryResult {
  const proxy = snapshot.probes.proxy.data;
  const docker = snapshot.probes.docker.data;
  const network = snapshot.probes.network.data;
  const security = snapshot.probes.security.data;
  const system = snapshot.probes.system.data;

  const architecture = detectArchitecture(proxy, docker);
  const sshPort = security.sshConfig.port || network.sshPort || 22;

  const env: Record<string, string> = {
    PORT: '3334',
    NODE_ENV: 'production',
    HOST_SSH_HOST: '127.0.0.1',
    HOST_SSH_PORT: String(sshPort),
    HOST_SSH_USER: 'root',
    AI_PROVIDER: 'auto',
    DATABASE_URL: 'postgres://guardian:guardian_secret@guardian-db:5432/guardian',
  };

  let dockerCompose: string | undefined;
  let systemdUnit: string | undefined;

  if (docker.installed) {
    dockerCompose = getDockerComposeTemplate(architecture, proxy);
  } else {
    systemdUnit = SYSTEMD_TEMPLATE;
  }

  const warnings: string[] = [];
  if (security.sshConfig.passwordAuth === 'yes') {
    warnings.push('PasswordAuthentication enabled — consider disabling for SSH key-only access');
  }
  if (security.sshConfig.permitRoot === 'yes') {
    warnings.push('PermitRootLogin enabled — consider restricting to prohibit-password or no');
  }
  if (security.firewall.tool === 'none') {
    warnings.push('No firewall detected — strongly recommend enabling ufw or iptables');
  }
  if (!security.fail2ban.active) {
    warnings.push('fail2ban not active — SSH brute-force protection missing');
  }

  const recommendations: string[] = [];
  if (!security.fail2ban.active) recommendations.push('Install and enable fail2ban for SSH protection');
  if (security.firewall.tool === 'none') recommendations.push('Enable ufw: ufw default deny incoming && ufw allow ssh && ufw enable');

  return {
    summary: `${system.os.name} with ${architecture} architecture. SSH on port ${sshPort}.`,
    architecture,
    confidence: 60,
    env,
    dockerCompose,
    systemdUnit,
    warnings,
    recommendations,
    monitoringProfile: {
      services: docker.containers.map(c => c.name).slice(0, 10),
      logPaths: ['/var/log/auth.log', '/var/log/syslog'],
      criticalPorts: network.listeningPorts.filter(p => p.port < 10000).map(p => p.port),
      customChecks: [],
    },
  };
}

function detectArchitecture(proxy: any, docker: any): DiscoveryResult['architecture'] {
  if (proxy.detected === 'traefik' && docker.installed) return 'traefik-docker';
  if (proxy.detected === 'nginx' && docker.installed) return 'nginx-docker';
  if (proxy.detected === 'nginx') return 'nginx-standalone';
  if (proxy.detected === 'caddy') return 'caddy';
  if (proxy.detected === 'haproxy') return 'haproxy';
  if (docker.installed) return 'traefik-docker';
  return 'bare-metal';
}

function getDockerComposeTemplate(arch: string, proxy: any): string {
  if (arch === 'traefik-docker') return TRAEFIK_COMPOSE;
  if (arch.includes('nginx')) return NGINX_COMPOSE;
  return BARE_COMPOSE;
}

const TRAEFIK_COMPOSE = `services:
  guardian:
    build: .
    container_name: guardian
    restart: unless-stopped
    env_file: .env
    depends_on:
      guardian-db:
        condition: service_healthy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - \${SSH_KEY_DIR:-~/.ssh}:/home/node/.ssh:ro
    networks:
      - guardian-internal
      - traefik-public
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=traefik-public"
      - "traefik.http.routers.guardian.rule=Host(\`\${GUARDIAN_DOMAIN:-guardian.localhost}\`)"
      - "traefik.http.routers.guardian.entrypoints=websecure"
      - "traefik.http.routers.guardian.tls.certresolver=letsencrypt"
      - "traefik.http.services.guardian.loadbalancer.server.port=3334"

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: \${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - guardian_pgdata:/var/lib/postgresql/data
    networks:
      - guardian-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian -d guardian"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  guardian_pgdata:

networks:
  guardian-internal:
    driver: bridge
  traefik-public:
    external: true
`;

const NGINX_COMPOSE = `services:
  guardian:
    build: .
    container_name: guardian
    restart: unless-stopped
    env_file: .env
    depends_on:
      guardian-db:
        condition: service_healthy
    ports:
      - "127.0.0.1:3334:3334"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - \${SSH_KEY_DIR:-~/.ssh}:/home/node/.ssh:ro
    networks:
      - guardian-internal

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: \${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - guardian_pgdata:/var/lib/postgresql/data
    networks:
      - guardian-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian -d guardian"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  guardian_pgdata:

networks:
  guardian-internal:
    driver: bridge
`;

const BARE_COMPOSE = `services:
  guardian:
    build: .
    container_name: guardian
    restart: unless-stopped
    env_file: .env
    depends_on:
      guardian-db:
        condition: service_healthy
    ports:
      - "3334:3334"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - \${SSH_KEY_DIR:-~/.ssh}:/home/node/.ssh:ro
    networks:
      - guardian-internal

  guardian-db:
    image: postgres:16-alpine
    container_name: guardian-db
    restart: unless-stopped
    environment:
      POSTGRES_DB: guardian
      POSTGRES_USER: guardian
      POSTGRES_PASSWORD: \${GUARDIAN_DB_PASSWORD:-guardian_secret}
    volumes:
      - guardian_pgdata:/var/lib/postgresql/data
    networks:
      - guardian-internal
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U guardian -d guardian"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  guardian_pgdata:

networks:
  guardian-internal:
    driver: bridge
`;

const SYSTEMD_TEMPLATE = `[Unit]
Description=Guardian Blue Team SIEM
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=guardian
WorkingDirectory=/opt/guardian
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
`;
```

- [ ] **Step 2: Create analyzer.ts**

```typescript
// src/discovery/analyzer.ts
import { AIProvider } from '../services/ai-provider.js';
import { logger } from '../utils/logger.js';
import { discoveryResultSchema, type DiscoveryResult, type ServerSnapshot } from './types.js';
import { generateFallbackConfig } from './templates.js';

const SYSTEM_PROMPT = `You are an expert DevOps engineer specializing in server security infrastructure.
Analyze the server snapshot and generate the optimal configuration for Guardian Blue Team SIEM.

Rules:
1. If Traefik detected → configure Guardian as service in same Docker network with Traefik labels
2. If Nginx detected → Guardian listens on 127.0.0.1:3334, generate upstream block
3. If SSH on non-standard port → set HOST_SSH_PORT accordingly
4. If fail2ban active → include its jails in monitoring profile
5. If Docker present → mount /var/run/docker.sock read-only
6. Adapt to available tools (Alpine uses wget, Ubuntu/Debian has curl)
7. Generate .env with all detected values filled (never include secrets/passwords)
8. Generate docker-compose.yml adapted to the found architecture
9. If no Docker on server → generate systemd unit file instead of docker-compose
10. Set monitoringProfile with detected services, log paths, and critical ports

IMPORTANT: Respond with valid JSON only. No markdown, no code fences, no explanation outside JSON.
Match this exact schema:
{
  "summary": "string describing server",
  "architecture": "traefik-docker" | "nginx-standalone" | "nginx-docker" | "caddy" | "haproxy" | "bare-metal" | "unknown",
  "confidence": 0-100,
  "env": { "KEY": "value", ... },
  "dockerCompose": "yaml string or omit",
  "systemdUnit": "unit file string or omit",
  "proxyConfig": "nginx/caddy block or omit",
  "warnings": ["string", ...],
  "recommendations": ["string", ...],
  "monitoringProfile": {
    "services": ["name", ...],
    "logPaths": ["/var/log/...", ...],
    "criticalPorts": [443, ...],
    "customChecks": ["command", ...]
  }
}`;

export async function analyzeSnapshot(snapshot: ServerSnapshot): Promise<DiscoveryResult> {
  const sanitized = sanitizeForAI(snapshot);
  const prompt = `Analyze this server snapshot and generate Guardian SIEM configuration:\n\n${JSON.stringify(sanitized, null, 2)}`;

  const response = await AIProvider.chat(prompt, SYSTEM_PROMPT);

  if (response?.text) {
    try {
      const cleaned = response.text.replace(/```json?\n?/g, '').replace(/```/g, '').trim();
      const parsed = JSON.parse(cleaned);
      const validated = discoveryResultSchema.parse(parsed);
      logger.info({ provider: response.provider, confidence: validated.confidence }, 'Discovery AI analysis complete');
      return validated;
    } catch (err) {
      logger.warn({ err }, 'Discovery AI response failed validation, using fallback');
    }
  }

  logger.info('Discovery using heuristic fallback');
  return generateFallbackConfig(snapshot);
}

function sanitizeForAI(snapshot: ServerSnapshot): object {
  const safe = JSON.parse(JSON.stringify(snapshot));
  // Remove sensitive auth log content, keep only patterns
  if (safe.probes?.system?.data?.recentAuthLogs) {
    safe.probes.system.data.recentAuthLogs = safe.probes.system.data.recentAuthLogs
      .map((l: string) => l.replace(/key fingerprint is \S+/g, 'key fingerprint is [REDACTED]'));
  }
  // Remove any firewall rules that might contain IPs we don't want to send
  if (safe.probes?.security?.data?.firewall?.rules) {
    safe.probes.security.data.firewall.rules = safe.probes.security.data.firewall.rules.slice(0, 800);
  }
  return safe;
}
```

- [ ] **Step 3: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add src/discovery/analyzer.ts src/discovery/templates.ts
git commit -m "feat(discovery): add AI analyzer with heuristic fallback

Sends sanitized snapshot to AI provider, validates response with Zod.
Falls back to template-based config if AI fails or response is invalid."
```

---

### Task 9: Config Generator

**Files:**
- Create: `src/discovery/config-generator.ts`

- [ ] **Step 1: Create config generator**

```typescript
// src/discovery/config-generator.ts
import type { DiscoveryResult } from './types.js';

export interface GeneratedConfig {
  envContent: string;
  composeContent: string | null;
  systemdContent: string | null;
  proxyContent: string | null;
}

export function generateConfig(
  result: DiscoveryResult,
  userInputs: { telegramToken?: string; telegramChatId?: string; geminiApiKey?: string; domain?: string },
): GeneratedConfig {
  const env = { ...result.env };

  if (userInputs.telegramToken) env.TELEGRAM_BOT_TOKEN = userInputs.telegramToken;
  if (userInputs.telegramChatId) env.TELEGRAM_CHAT_ID = userInputs.telegramChatId;
  if (userInputs.geminiApiKey) env.GEMINI_API_KEY = userInputs.geminiApiKey;
  if (userInputs.domain) env.GUARDIAN_DOMAIN = userInputs.domain;

  if (!env.GUARDIAN_DB_PASSWORD) {
    env.GUARDIAN_DB_PASSWORD = generatePassword();
  }
  if (!env.DASHBOARD_TOKEN) {
    env.DASHBOARD_TOKEN = generatePassword();
  }

  const envContent = formatEnvFile(env);
  const composeContent = result.dockerCompose ?? null;
  const systemdContent = result.systemdUnit ?? null;
  const proxyContent = result.proxyConfig ?? null;

  return { envContent, composeContent, systemdContent, proxyContent };
}

function formatEnvFile(env: Record<string, string>): string {
  const sections: Record<string, string[]> = {
    'Server': ['PORT', 'NODE_ENV'],
    'Dashboard': ['DASHBOARD_TOKEN'],
    'Database': ['DATABASE_URL'],
    'Telegram': ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID', 'TELEGRAM_WEBHOOK_SECRET'],
    'AI': ['GEMINI_API_KEY', 'GEMINI_MODEL', 'AI_PROVIDER', 'OLLAMA_URL', 'OLLAMA_MODEL'],
    'SSH': ['HOST_SSH_HOST', 'HOST_SSH_PORT', 'HOST_SSH_USER', 'HOST_SSH_KEY_PATH'],
    'Security': ['TRUSTED_IPS', 'TRUSTED_FINGERPRINTS', 'ABUSE_CONFIDENCE_THRESHOLD'],
    'Threat Intel': ['ABUSEIPDB_API_KEY'],
    'Docker Compose': ['GUARDIAN_DOMAIN', 'GUARDIAN_DB_PASSWORD', 'SSH_KEY_DIR'],
  };

  const lines: string[] = ['# Guardian Blue Team — Auto-generated by Discovery Engine', ''];
  const used = new Set<string>();

  for (const [section, keys] of Object.entries(sections)) {
    const sectionLines: string[] = [];
    for (const key of keys) {
      if (env[key] !== undefined) {
        sectionLines.push(`${key}=${env[key]}`);
        used.add(key);
      }
    }
    if (sectionLines.length > 0) {
      lines.push(`# ─── ${section} ${'─'.repeat(Math.max(0, 60 - section.length))}`);
      lines.push(...sectionLines);
      lines.push('');
    }
  }

  const remaining = Object.entries(env).filter(([k]) => !used.has(k));
  if (remaining.length > 0) {
    lines.push('# ─── Other ─────────────────────────────────────────────────────');
    for (const [k, v] of remaining) {
      lines.push(`${k}=${v}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function generatePassword(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  for (const byte of bytes) {
    result += chars[byte % chars.length];
  }
  return result;
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/config-generator.ts
git commit -m "feat(discovery): add config generator

Converts DiscoveryResult into .env file content and docker-compose.yml.
Merges user inputs (API keys, Telegram token, domain).
Auto-generates secure passwords for DB and dashboard."
```

---

### Task 10: Presenter (Terminal + Telegram)

**Files:**
- Create: `src/discovery/presenter.ts`

- [ ] **Step 1: Create presenter**

```typescript
// src/discovery/presenter.ts
import type { DiscoveryResult, ServerSnapshot } from './types.js';
import type { GeneratedConfig } from './config-generator.js';

export function formatTerminalPresentation(
  snapshot: ServerSnapshot,
  result: DiscoveryResult,
  config: GeneratedConfig,
): string {
  const os = snapshot.probes.system.data.os.name || 'Unknown OS';
  const containers = snapshot.probes.docker.data.containers.length;
  const sshPort = snapshot.probes.security.data.sshConfig.port || snapshot.probes.network.data.sshPort || 22;
  const proxy = snapshot.probes.proxy.data.detected;
  const proxyVersion = snapshot.probes.proxy.data.version;
  const envVars = Object.keys(result.env).length;

  const lines: string[] = [
    '',
    '╔══════════════════════════════════════════════════════════════════╗',
    '║  🔍 Guardian Auto-Discovery Complete                            ║',
    '╠══════════════════════════════════════════════════════════════════╣',
    '║                                                                  ║',
    `║  Server: ${pad(os, 52)}║`,
    `║  Architecture: ${pad(result.architecture, 46)}║`,
    `║  SSH Port: ${pad(String(sshPort), 50)}║`,
    `║  Reverse Proxy: ${pad(proxy !== 'none' ? `${proxy}${proxyVersion ? ` v${proxyVersion}` : ''}` : 'none detected', 44)}║`,
    `║  Containers: ${pad(String(containers) + ' running', 48)}║`,
    `║  Confidence: ${pad(result.confidence + '%', 48)}║`,
    '║                                                                  ║',
  ];

  if (result.warnings.length > 0) {
    lines.push('║  ⚠️  Warnings:                                                   ║');
    for (const w of result.warnings.slice(0, 4)) {
      lines.push(`║  • ${pad(w.slice(0, 56), 58)}║`);
    }
    lines.push('║                                                                  ║');
  }

  if (result.recommendations.length > 0) {
    lines.push('║  💡 Recommendations:                                             ║');
    for (const r of result.recommendations.slice(0, 3)) {
      lines.push(`║  • ${pad(r.slice(0, 56), 58)}║`);
    }
    lines.push('║                                                                  ║');
  }

  lines.push(`║  Generated: .env (${envVars} vars) + ${config.composeContent ? 'docker-compose.yml' : 'systemd unit'}${pad('', 20)}║`);
  lines.push('║                                                                  ║');
  lines.push('╚══════════════════════════════════════════════════════════════════╝');
  lines.push('');
  lines.push('[V] View full config    [A] Apply    [E] Edit .env    [Q] Quit');
  lines.push('');

  return lines.join('\n');
}

export function formatTelegramMessage(
  snapshot: ServerSnapshot,
  result: DiscoveryResult,
): string {
  const os = snapshot.probes.system.data.os.name || 'Unknown';
  const sshPort = snapshot.probes.security.data.sshConfig.port || 22;
  const containers = snapshot.probes.docker.data.containers.length;

  const lines: string[] = [
    `🔍 <b>Discovery completo</b> — ${snapshot.target.host}`,
    '',
    `<b>Resumo:</b>`,
    `• ${os} — ${result.architecture}`,
    `• SSH porta ${sshPort}`,
    `• ${containers} containers rodando`,
    `• Confiança: ${result.confidence}%`,
  ];

  if (result.warnings.length > 0) {
    lines.push('', '⚠️ <b>Avisos:</b>');
    for (const w of result.warnings.slice(0, 4)) {
      lines.push(`• ${w}`);
    }
  }

  if (result.monitoringProfile.services.length > 0) {
    lines.push('', '📋 <b>Monitoring Profile:</b>');
    lines.push(`• Serviços: ${result.monitoringProfile.services.slice(0, 5).join(', ')}`);
    lines.push(`• Logs: ${result.monitoringProfile.logPaths.slice(0, 3).join(', ')}`);
    lines.push(`• Portas: ${result.monitoringProfile.criticalPorts.slice(0, 6).join(', ')}`);
  }

  if (result.recommendations.length > 0) {
    lines.push('', '💡 <b>Recomendações:</b>');
    for (const r of result.recommendations.slice(0, 3)) {
      lines.push(`• ${r}`);
    }
  }

  return lines.join('\n');
}

function pad(text: string, width: number): string {
  return text + ' '.repeat(Math.max(0, width - text.length));
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/presenter.ts
git commit -m "feat(discovery): add presenter for terminal and Telegram

Terminal: box-formatted display with server info, warnings, recommendations.
Telegram: HTML-formatted message for inline display in chat."
```

---

### Task 11: CLI Entry Point (for install.sh)

**Files:**
- Create: `src/discovery/cli.ts`

- [ ] **Step 1: Create CLI entry point**

```typescript
// src/discovery/cli.ts
import { LocalExecutor } from './executor.js';
import { runAllProbes } from './probes/index.js';
import { analyzeSnapshot } from './analyzer.js';
import { generateConfig, type GeneratedConfig } from './config-generator.js';
import { formatTerminalPresentation } from './presenter.js';
import { writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';

async function main() {
  const args = process.argv.slice(2);
  const apiKey = getArg(args, '--api-key');
  const installDir = getArg(args, '--dir') || process.cwd();
  const telegramToken = getArg(args, '--telegram-token');
  const telegramChatId = getArg(args, '--telegram-chat-id');
  const domain = getArg(args, '--domain');

  if (apiKey) {
    process.env.GEMINI_API_KEY = apiKey;
  }

  console.log('\n🔍 Guardian Auto-Discovery starting...\n');
  console.log('  Scanning: network, proxy, docker, security, system');
  console.log('  This may take up to 60 seconds...\n');

  const exec = new LocalExecutor();
  const hostname = (await exec.run('hostname')).stdout.trim() || 'localhost';

  const snapshot = await runAllProbes(exec, { host: hostname, port: 22, user: 'root' }, 'local');

  const probeStatus = Object.entries(snapshot.probes)
    .map(([name, probe]) => `  ${probe.success ? '✅' : '❌'} ${name} (${probe.durationMs}ms)`)
    .join('\n');
  console.log(`Probes completed in ${snapshot.scanDurationMs}ms:\n${probeStatus}\n`);

  console.log('🤖 Analyzing with AI...\n');
  const result = await analyzeSnapshot(snapshot);

  const config = generateConfig(result, {
    geminiApiKey: apiKey,
    telegramToken,
    telegramChatId,
    domain,
  });

  console.log(formatTerminalPresentation(snapshot, result, config));

  const action = await prompt('Your choice [V/A/E/Q]: ');

  switch (action.toLowerCase()) {
    case 'v':
      console.log('\n─── .env ───────────────────────────────────────────────');
      console.log(config.envContent);
      if (config.composeContent) {
        console.log('\n─── docker-compose.yml ─────────────────────────────────');
        console.log(config.composeContent);
      }
      const action2 = await prompt('\n[A] Apply    [Q] Quit: ');
      if (action2.toLowerCase() === 'a') {
        applyConfig(installDir, config);
      }
      break;
    case 'a':
      applyConfig(installDir, config);
      break;
    case 'e':
      console.log('\n.env will be written. Edit it manually, then run: docker compose up -d');
      writeWithBackup(join(installDir, '.env'), config.envContent);
      console.log(`✅ Written to ${join(installDir, '.env')}`);
      break;
    case 'q':
    default:
      console.log('Aborted. No changes made.');
      break;
  }

  // Output result as JSON for install.sh to parse if needed
  const outputPath = join(installDir, '.guardian-discovery.json');
  writeFileSync(outputPath, JSON.stringify({ snapshot, result }, null, 2));
}

function applyConfig(dir: string, config: GeneratedConfig): void {
  writeWithBackup(join(dir, '.env'), config.envContent);
  console.log('✅ .env written');

  if (config.composeContent) {
    writeWithBackup(join(dir, 'docker-compose.yml'), config.composeContent);
    console.log('✅ docker-compose.yml written');
  }

  if (config.systemdContent) {
    writeFileSync(join(dir, 'guardian.service'), config.systemdContent);
    console.log('✅ guardian.service written');
  }

  if (config.proxyContent) {
    writeFileSync(join(dir, 'guardian-proxy.conf'), config.proxyContent);
    console.log('✅ guardian-proxy.conf written (add to your proxy config)');
  }

  console.log('\n🎉 Configuration applied! Run: docker compose up -d');
}

function writeWithBackup(path: string, content: string): void {
  if (existsSync(path)) {
    copyFileSync(path, path + '.bak');
  }
  writeFileSync(path, content);
}

function getArg(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

function prompt(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(question, answer => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

main().catch(err => {
  console.error('❌ Discovery failed:', err.message);
  process.exit(1);
});
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/cli.ts
git commit -m "feat(discovery): add CLI entry point for install.sh

Interactive terminal UI: scan → AI analysis → present → confirm → apply.
Writes .env and docker-compose.yml with backup of existing files."
```

---

### Task 12: Remote Entry Point (for /add-server)

**Files:**
- Create: `src/discovery/remote.ts`

- [ ] **Step 1: Create remote discovery module**

```typescript
// src/discovery/remote.ts
import { SSHExecutor } from './executor.js';
import { runAllProbes } from './probes/index.js';
import { analyzeSnapshot } from './analyzer.js';
import { formatTelegramMessage } from './presenter.js';
import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { logger } from '../utils/logger.js';
import type { DiscoveryResult, ServerSnapshot } from './types.js';

export interface RemoteDiscoveryResult {
  snapshot: ServerSnapshot;
  analysis: DiscoveryResult;
  telegramMessage: string;
}

export async function discoverRemoteServer(target: SSHTarget): Promise<RemoteDiscoveryResult | null> {
  const reachable = await SSHCollector.isReachable(target);
  if (!reachable) {
    logger.warn({ server: target.name }, 'Discovery: server not reachable');
    return null;
  }

  logger.info({ server: target.name }, 'Discovery: starting remote scan');
  const exec = new SSHExecutor(target);
  const snapshot = await runAllProbes(
    exec,
    { host: target.host, port: target.sshPort, user: target.sshUser },
    'ssh',
  );

  logger.info({ server: target.name, durationMs: snapshot.scanDurationMs }, 'Discovery: probes complete');
  const analysis = await analyzeSnapshot(snapshot);
  const telegramMessage = formatTelegramMessage(snapshot, analysis);

  return { snapshot, analysis, telegramMessage };
}

export function formatDiscoveryApprovalKeyboard(serverId: number): object {
  return {
    inline_keyboard: [[
      { text: '✅ Aprovar', callback_data: `discovery_approve_${serverId}` },
      { text: '❌ Cancelar', callback_data: `discovery_cancel_${serverId}` },
    ]],
  };
}
```

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/discovery/remote.ts
git commit -m "feat(discovery): add remote entry point for /add-server

Connects via SSH, runs all probes, analyzes with AI, returns
Telegram-formatted message with approval keyboard."
```

---

### Task 13: Integrate with /add-server Command

**Files:**
- Modify: `src/telegram/commands.ts` (addServer function around line 486-508)
- Modify: `src/telegram/callbacks.ts` (add discovery callbacks)

- [ ] **Step 1: Update addServer function in commands.ts**

Replace the `addServer` function (approximately lines 486-508) with a version that triggers discovery:

```typescript
// In src/telegram/commands.ts — replace the addServer function

import { discoverRemoteServer, formatDiscoveryApprovalKeyboard } from '../discovery/remote.js';

// Store pending discoveries for approval
const pendingDiscoveries = new Map<number, { analysis: import('../discovery/types.js').DiscoveryResult; serverName: string }>();

async function addServer(args: string[]): Promise<string> {
  if (args.length < 2) {
    return '❌ Uso: /add-server nome host [porta] [user] [key_path]\nEx: /add-server ovh-main 1.2.3.4 22 ubuntu /root/.ssh/id_ed25519';
  }

  const [name, host, portStr, user, keyPath] = args;
  const sshPort = portStr ? parseInt(portStr) : 22;

  if (!isValidServerName(name)) return '❌ Nome inválido (use a-z, 0-9, -, _, . — max 64 chars).';
  if (!isValidHostname(host) && !isValidIp(host)) return '❌ Hostname/IP inválido.';
  if (isNaN(sshPort) || sshPort < 1 || sshPort > 65535) return '❌ Porta SSH inválida.';
  if (user && !isValidSshUser(user)) return '❌ Usuário SSH inválido (a-z, 0-9, _, - — max 32 chars).';
  if (keyPath && !isValidKeyPath(keyPath)) return '❌ Caminho de chave SSH inválido (path absoluto, sem ..).';

  const existing = await ServerService.getByName(name);
  if (existing) return `❌ Servidor "${name}" já existe.`;

  const server = await ServerService.add({ name, host, sshPort, sshUser: user || 'ubuntu', sshKeyPath: keyPath });
  const target = ServerService.toSSHTarget(server);
  const reachable = await SSHCollector.isReachable(target);

  if (!reachable) {
    await ServerService.remove(name);
    return `❌ Não foi possível conectar a ${host}:${sshPort}. Servidor não adicionado.`;
  }

  // Trigger auto-discovery in background
  discoverRemoteServer(target).then(async discoveryResult => {
    if (!discoveryResult) return;

    pendingDiscoveries.set(server.id, { analysis: discoveryResult.analysis, serverName: name });

    const keyboard = formatDiscoveryApprovalKeyboard(server.id);
    await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: config.telegram.chatId,
        text: discoveryResult.telegramMessage,
        parse_mode: 'HTML',
        reply_markup: keyboard,
      }),
    }).catch(err => logger.warn({ err }, 'Failed to send discovery message'));

    // Auto-expire after 30 minutes
    setTimeout(() => pendingDiscoveries.delete(server.id), 30 * 60_000);
  }).catch(err => logger.warn({ err }, 'Background discovery failed'));

  return `✅ <b>${name}</b> adicionado (${user || 'ubuntu'}@${host}:${sshPort}) 🟢\n\n🔍 Auto-discovery em andamento...`;
}

export { pendingDiscoveries };
```

- [ ] **Step 2: Add discovery callback handler in callbacks.ts**

Add to the `handleTelegramCallback` function in `src/telegram/callbacks.ts`, before the "Unknown callback" line:

```typescript
// Add import at top of callbacks.ts
import { pendingDiscoveries } from './commands.js';

// Add inside handleTelegramCallback, before the logger.debug('Unknown callback') line:
  if (callbackQuery.data.startsWith('discovery_approve_')) {
    const serverId = parseInt(callbackQuery.data.replace('discovery_approve_', ''));
    const pending = pendingDiscoveries.get(serverId);
    if (!pending) {
      await answerCallback(callbackQuery.id, 'Discovery expirado');
      return;
    }
    pendingDiscoveries.delete(serverId);
    await answerCallback(callbackQuery.id, `✅ Discovery aprovado para ${pending.serverName}`);
    // Update message to show approval
    if (callbackQuery.message) {
      await editMessage(callbackQuery.message.chat.id, callbackQuery.message.message_id,
        `✅ Discovery aprovado — <b>${pending.serverName}</b> monitoramento configurado.`);
    }
    return;
  }

  if (callbackQuery.data.startsWith('discovery_cancel_')) {
    const serverId = parseInt(callbackQuery.data.replace('discovery_cancel_', ''));
    pendingDiscoveries.delete(serverId);
    await answerCallback(callbackQuery.id, '❌ Discovery cancelado');
    if (callbackQuery.message) {
      await editMessage(callbackQuery.message.chat.id, callbackQuery.message.message_id,
        '❌ Discovery cancelado.');
    }
    return;
  }
```

Also add these helper functions if not already present:

```typescript
async function answerCallback(callbackQueryId: string, text: string): Promise<void> {
  await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/answerCallbackQuery`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ callback_query_id: callbackQueryId, text }),
  }).catch(err => logger.warn({ err }, 'answerCallback failed'));
}

async function editMessage(chatId: number, messageId: number, text: string): Promise<void> {
  await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/editMessageText`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, message_id: messageId, text, parse_mode: 'HTML' }),
  }).catch(err => logger.warn({ err }, 'editMessage failed'));
}
```

- [ ] **Step 3: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -c error`
Expected: 0 (or only pre-existing errors unrelated to discovery)

- [ ] **Step 4: Commit**

```bash
git add src/telegram/commands.ts src/telegram/callbacks.ts
git commit -m "feat(discovery): integrate with /add-server and Telegram callbacks

When a server is added, discovery runs in background and sends results
to Telegram with approval buttons. Discovery approval/cancel via callbacks."
```

---

### Task 14: Integrate with install.sh

**Files:**
- Modify: `install.sh`

- [ ] **Step 1: Add discovery step to install.sh**

After the `npm install` / clone step in install.sh, add the discovery call. Locate the section after cloning and before `docker compose up` and add:

```bash
# ─── Auto-Discovery ────────────────────────────────────────────────
step "🔍 Running auto-discovery..."

# Ask for Gemini API key if not set
if [[ -z "${GEMINI_API_KEY:-}" ]]; then
  echo ""
  echo "  Guardian uses AI to auto-configure for your server."
  echo "  Get a free Gemini API key at: https://aistudio.google.com/"
  echo ""
  read -rp "  Gemini API Key (or press Enter to skip): " GEMINI_API_KEY
fi

DISCOVERY_ARGS="--dir ${INSTALL_DIR}"
[[ -n "${GEMINI_API_KEY:-}" ]] && DISCOVERY_ARGS="${DISCOVERY_ARGS} --api-key ${GEMINI_API_KEY}"
[[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && DISCOVERY_ARGS="${DISCOVERY_ARGS} --telegram-token ${TELEGRAM_BOT_TOKEN}"
[[ -n "${TELEGRAM_CHAT_ID:-}" ]] && DISCOVERY_ARGS="${DISCOVERY_ARGS} --telegram-chat-id ${TELEGRAM_CHAT_ID}"
[[ -n "${GUARDIAN_DOMAIN:-}" ]] && DISCOVERY_ARGS="${DISCOVERY_ARGS} --domain ${GUARDIAN_DOMAIN}"

if [[ -n "${GEMINI_API_KEY:-}" ]]; then
  cd "${INSTALL_DIR}"
  npx tsx src/discovery/cli.ts ${DISCOVERY_ARGS}
  DISCOVERY_EXIT=$?
  
  if [[ $DISCOVERY_EXIT -ne 0 ]]; then
    warn "Auto-discovery failed. Using default configuration."
    # Fall through to manual config or defaults
  fi
else
  warn "No API key provided. Using default configuration."
  warn "You can run discovery later: npx tsx src/discovery/cli.ts --local"
fi
```

- [ ] **Step 2: Verify install.sh is syntactically valid**

Run: `bash -n /Users/I776289/Documents/pessoal/guardian/install.sh`
Expected: No syntax errors

- [ ] **Step 3: Commit**

```bash
git add install.sh
git commit -m "feat(discovery): integrate auto-discovery into install.sh

Prompts for Gemini API key, runs discovery CLI to auto-detect
server architecture and generate optimal configuration."
```

---

### Task 15: Re-Discovery Worker (24h periodic)

**Files:**
- Create: `src/workers/discovery.worker.ts`

- [ ] **Step 1: Create discovery worker**

```typescript
// src/workers/discovery.worker.ts
import { ServerService } from '../services/server.service.js';
import { discoverRemoteServer } from '../discovery/remote.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';

export class DiscoveryWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static running = false;
  private static readonly INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

  static start(): void {
    // Initial run after 5 minutes (let other workers settle)
    setTimeout(() => this.runDiscovery(), 5 * 60_000);
    this.intervalId = setInterval(() => this.runDiscovery(), this.INTERVAL_MS);
    logger.info('DiscoveryWorker started (24h cycle)');
  }

  static stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('DiscoveryWorker stopped');
  }

  private static async runDiscovery(): Promise<void> {
    if (this.running) return;
    this.running = true;

    try {
      const servers = await ServerService.getEnabled();
      if (servers.length === 0) return;

      logger.info({ count: servers.length }, 'Re-discovery cycle starting');

      for (const server of servers) {
        const target = ServerService.toSSHTarget(server);
        const result = await discoverRemoteServer(target);

        if (!result) {
          logger.debug({ server: server.name }, 'Re-discovery: server unreachable, skipping');
          continue;
        }

        // Compare with stored snapshot (detect significant changes)
        const changes = detectChanges(server.name, result.analysis);
        if (changes.length > 0) {
          await notifyChanges(server.name, changes);
        }
      }

      logger.info({ count: servers.length }, 'Re-discovery cycle complete');
    } catch (err) {
      logger.error({ err }, 'Re-discovery cycle failed');
    } finally {
      this.running = false;
    }
  }
}

// Simple in-memory cache of last known state per server
const lastKnownState = new Map<string, { services: string[]; ports: number[]; architecture: string }>();

function detectChanges(serverName: string, analysis: import('../discovery/types.js').DiscoveryResult): string[] {
  const previous = lastKnownState.get(serverName);
  const current = {
    services: analysis.monitoringProfile.services,
    ports: analysis.monitoringProfile.criticalPorts,
    architecture: analysis.architecture,
  };

  lastKnownState.set(serverName, current);

  if (!previous) return []; // First scan, no comparison

  const changes: string[] = [];

  const newServices = current.services.filter(s => !previous.services.includes(s));
  const removedServices = previous.services.filter(s => !current.services.includes(s));
  const newPorts = current.ports.filter(p => !previous.ports.includes(p));
  const closedPorts = previous.ports.filter(p => !current.ports.includes(p));

  if (newServices.length > 0) changes.push(`New services: ${newServices.join(', ')}`);
  if (removedServices.length > 0) changes.push(`Stopped services: ${removedServices.join(', ')}`);
  if (newPorts.length > 0) changes.push(`New ports: ${newPorts.join(', ')}`);
  if (closedPorts.length > 0) changes.push(`Closed ports: ${closedPorts.join(', ')}`);
  if (current.architecture !== previous.architecture) {
    changes.push(`Architecture changed: ${previous.architecture} → ${current.architecture}`);
  }

  return changes;
}

async function notifyChanges(serverName: string, changes: string[]): Promise<void> {
  const text = [
    `🔄 <b>Re-Discovery: changes detected</b>`,
    `🖥️ Server: <b>${serverName}</b>`,
    '',
    ...changes.map(c => `• ${c}`),
    '',
    '⚠️ Review recommended. No auto-changes applied.',
  ].join('\n');

  await fetch(`https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: config.telegram.chatId, text, parse_mode: 'HTML' }),
  }).catch(err => logger.warn({ err }, 'Re-discovery notification failed'));
}
```

- [ ] **Step 2: Register worker in src/index.ts**

Add to the worker start section in `src/index.ts`:

```typescript
import { DiscoveryWorker } from './workers/discovery.worker.js';

// In the worker start block:
DiscoveryWorker.start();

// In the graceful shutdown block:
DiscoveryWorker.stop();
```

- [ ] **Step 3: Verify TypeScript compiles**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit 2>&1 | grep -i discovery`
Expected: No errors

- [ ] **Step 4: Commit**

```bash
git add src/workers/discovery.worker.ts src/index.ts
git commit -m "feat(discovery): add 24h re-discovery worker

Periodically re-scans all monitored servers. Detects changes in
services, ports, or architecture and notifies via Telegram.
Does not auto-apply changes — advisory only."
```

---

### Task 16: Final Verification

**Files:** None new — verification only

- [ ] **Step 1: Run full TypeScript check**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsc --noEmit`
Expected: Clean compile (or only pre-existing unrelated issues)

- [ ] **Step 2: Run existing tests**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npm test 2>&1 | tail -20`
Expected: Tests pass (no regressions)

- [ ] **Step 3: Verify the discovery module can be imported**

Run: `cd /Users/I776289/Documents/pessoal/guardian && npx tsx -e "import './src/discovery/types.js'; import './src/discovery/executor.js'; console.log('OK')"`
Expected: "OK"

- [ ] **Step 4: List created files to verify structure**

Run: `find src/discovery -type f | sort`
Expected:
```
src/discovery/analyzer.ts
src/discovery/cli.ts
src/discovery/config-generator.ts
src/discovery/executor.ts
src/discovery/presenter.ts
src/discovery/probes/docker.ts
src/discovery/probes/index.ts
src/discovery/probes/network.ts
src/discovery/probes/proxy.ts
src/discovery/probes/security.ts
src/discovery/probes/system.ts
src/discovery/remote.ts
src/discovery/templates.ts
src/discovery/types.ts
```

- [ ] **Step 5: Final commit with version bump**

```bash
# Update version in package.json from 1.3.0 to 1.4.0
sed -i '' 's/"version": "1.3.0"/"version": "1.4.0"/' package.json
git add package.json
git commit -m "chore: bump version to 1.4.0 for auto-discovery feature"
```
