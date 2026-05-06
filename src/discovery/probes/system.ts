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
