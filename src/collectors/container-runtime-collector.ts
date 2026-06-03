import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';

export interface ContainerProcessInfo {
  container: string;
  pid: number;
  user: string;
  cpu: number;
  mem: number;
  command: string;
  args: string;
}

export interface ContainerConnection {
  container: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  state: string;
  process: string;
}

export interface ContainerSecurityConfig {
  container: string;
  readOnly: boolean;
  noNewPrivs: boolean;
  capDrop: string[];
  memoryLimit: number;
  cpuQuota: number;
  image: string;
}

export class ContainerRuntimeCollector {
  /**
   * Collects processes running INSIDE each container via docker top.
   * Lightweight: ~3MB I/O, 8-15s for 15 containers. Runs every 2 min.
   */
  static async collectContainerProcesses(target: SSHTarget): Promise<RawLogEntry[]> {
    const cmd = `docker ps -q 2>/dev/null | xargs -P4 -I{} sh -c '
      name=$(docker inspect --format "{{.Name}}" {} 2>/dev/null | tr -d /);
      echo "---CONTAINER:$name---";
      docker top {} -eo pid,user,%cpu,%mem,comm,args 2>/dev/null | tail -n +2
    ' 2>/dev/null || echo ''`;

    const result = await SSHCollector.run(target, cmd, 20_000);
    if (!result.success || !result.stdout.trim()) return [];

    const entries: RawLogEntry[] = [];
    let currentContainer = '';

    for (const line of result.stdout.trim().split('\n')) {
      const headerMatch = line.match(/^---CONTAINER:(.+)---$/);
      if (headerMatch) {
        currentContainer = headerMatch[1];
        continue;
      }

      if (!currentContainer || !line.trim()) continue;

      entries.push({
        serverId: target.id,
        serverName: target.name,
        source: 'container_process',
        timestamp: new Date(),
        line: `${currentContainer}|${line.trim()}`,
      });
    }

    return entries;
  }

  /**
   * Collects established network connections FROM each container via nsenter + ss.
   * Moderate: ~2MB I/O, 12-20s for 15 containers. Runs every 5 min.
   */
  static async collectContainerNetwork(target: SSHTarget): Promise<RawLogEntry[]> {
    const cmd = `for cid in $(docker ps -q 2>/dev/null); do
      name=$(docker inspect --format '{{.Name}}' $cid 2>/dev/null | tr -d /);
      pid=$(docker inspect --format '{{.State.Pid}}' $cid 2>/dev/null);
      [ -z "$pid" ] || [ "$pid" = "0" ] && continue;
      conns=$(nsenter -t $pid -n ss -tnp state established 2>/dev/null | tail -n +2);
      [ -n "$conns" ] && echo "---CONTAINER:$name---" && echo "$conns";
    done 2>/dev/null || echo ''`;

    const result = await SSHCollector.run(target, cmd, 25_000);
    if (!result.success || !result.stdout.trim()) return [];

    const entries: RawLogEntry[] = [];
    let currentContainer = '';

    for (const line of result.stdout.trim().split('\n')) {
      const headerMatch = line.match(/^---CONTAINER:(.+)---$/);
      if (headerMatch) {
        currentContainer = headerMatch[1];
        continue;
      }

      if (!currentContainer || !line.trim()) continue;

      entries.push({
        serverId: target.id,
        serverName: target.name,
        source: 'container_network',
        timestamp: new Date(),
        line: `${currentContainer}|${line.trim()}`,
      });
    }

    return entries;
  }

  /**
   * Collects filesystem changes in containers via docker diff.
   * Only reports files in suspicious paths (/tmp, /dev/shm, /bin, /usr/bin).
   * Heavier: up to 200MB I/O if many containers. Runs every 30 min.
   */
  static async collectContainerFilesystem(target: SSHTarget): Promise<RawLogEntry[]> {
    const cmd = `for cid in $(docker ps -q 2>/dev/null); do
      name=$(docker inspect --format '{{.Name}}' $cid 2>/dev/null | tr -d /);
      diff=$(docker diff $cid 2>/dev/null | grep -E '^[AC] .*(tmp|dev/shm|bin|usr/bin|usr/local/bin)' | grep -Ev 'node-compile-cache|qdrant.*(snapshots|tmp)|guardian-ssh-|/tmp/\\.mc|dotnet-diagnostic|clr-debug-pipe|jellyfin|/tmp/pg_|/tmp/pgsql_|/tmp/\\.s\\.PGSQL|/tmp/v8-compile-cache|/tmp/yarn--|/tmp/npm-');
      [ -n "$diff" ] && echo "---CONTAINER:$name---" && echo "$diff";
    done 2>/dev/null || echo ''`;

    const result = await SSHCollector.run(target, cmd, 30_000);
    if (!result.success || !result.stdout.trim()) return [];

    const entries: RawLogEntry[] = [];
    let currentContainer = '';

    for (const line of result.stdout.trim().split('\n')) {
      const headerMatch = line.match(/^---CONTAINER:(.+)---$/);
      if (headerMatch) {
        currentContainer = headerMatch[1];
        continue;
      }

      if (!currentContainer || !line.trim()) continue;

      entries.push({
        serverId: target.id,
        serverName: target.name,
        source: 'container_filesystem',
        timestamp: new Date(),
        line: `${currentContainer}|${line.trim()}`,
      });
    }

    return entries;
  }

  /**
   * Audits security configuration of running containers.
   * Very lightweight: <1MB I/O, 2-3s. Runs every 1h.
   */
  static async auditContainerConfig(target: SSHTarget): Promise<RawLogEntry[]> {
    const cmd = `docker ps -q 2>/dev/null | xargs -I{} docker inspect --format '{{.Name}}|IMAGE={{.Config.Image}}|RO={{.HostConfig.ReadonlyRootfs}}|PRIVILEGED={{.HostConfig.Privileged}}|SECOPT={{join .HostConfig.SecurityOpt ","}}|CAPDROP={{join .HostConfig.CapDrop ","}}|MEM={{.HostConfig.Memory}}|CPU={{.HostConfig.CpuQuota}}' {} 2>/dev/null || echo ''`;

    const result = await SSHCollector.run(target, cmd, 15_000);
    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(line => line.includes('|'))
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'container_config',
        timestamp: new Date(),
        line: line.replace(/^\//, ''),
      }));
  }

  /**
   * Parses raw process lines into structured data (for dashboard snapshots).
   */
  static parseProcessLine(line: string): ContainerProcessInfo | null {
    const [container, rest] = line.split('|', 2);
    if (!container || !rest) return null;

    const parts = rest.trim().split(/\s+/);
    if (parts.length < 5) return null;

    const [pid, user, cpu, mem, comm, ...argParts] = parts;
    return {
      container,
      pid: parseInt(pid ?? '0'),
      user: user ?? '',
      cpu: parseFloat(cpu ?? '0'),
      mem: parseFloat(mem ?? '0'),
      command: comm ?? '',
      args: argParts.join(' '),
    };
  }

  /**
   * Parses raw network lines into structured data.
   */
  static parseNetworkLine(line: string): ContainerConnection | null {
    const [container, rest] = line.split('|', 2);
    if (!container || !rest) return null;

    // ss output: ESTAB  0  0  local_addr:port  remote_addr:port  users:(("proc",pid=X,fd=Y))
    const parts = rest.trim().split(/\s+/);
    const localAddr = parts[3] || '';
    const remoteAddr = parts[4] || '';
    const processInfo = parts.slice(5).join(' ');

    const localPort = parseInt(localAddr.split(':').pop() ?? '0');
    const remoteParts = remoteAddr.split(':');
    const remotePort = parseInt(remoteParts.pop() ?? '0');
    const remoteIp = remoteParts.join(':');

    if (!remoteIp || remotePort === 0) return null;

    return {
      container,
      localPort,
      remoteIp,
      remotePort,
      state: 'ESTAB',
      process: processInfo,
    };
  }

  /**
   * Parses container security config line into structured data.
   */
  static parseConfigLine(line: string): ContainerSecurityConfig | null {
    const parts = line.split('|');
    if (parts.length < 6) return null;

    const container = parts[0].trim();
    const fields: Record<string, string> = {};
    for (const part of parts.slice(1)) {
      const [key, val] = part.split('=', 2);
      if (key && val !== undefined) fields[key] = val;
    }

    return {
      container,
      image: fields['IMAGE'] ?? '',
      readOnly: fields['RO'] === 'true',
      noNewPrivs: (fields['SECOPT'] ?? '').includes('no-new-privileges'),
      capDrop: (fields['CAPDROP'] ?? '').split(',').filter(Boolean),
      memoryLimit: parseInt(fields['MEM'] ?? '0'),
      cpuQuota: parseInt(fields['CPU'] ?? '0'),
    };
  }
}
