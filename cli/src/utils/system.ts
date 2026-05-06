import { execa } from 'execa';

export interface SystemInfo {
  os: string;
  distro: string;
  arch: string;
  cores: number;
  memoryGB: number;
  diskFreeGB: number;
  dockerInstalled: boolean;
  dockerVersion: string | null;
  dockerComposeInstalled: boolean;
  traefikNetwork: string | null;
  sshPort: number;
}

export async function detectSystem(): Promise<SystemInfo> {
  const os = process.platform === 'linux' ? 'linux' : process.platform === 'darwin' ? 'macos' : 'unknown';

  let distro = 'unknown';
  if (os === 'linux') {
    try {
      const { stdout } = await execa('cat', ['/etc/os-release']);
      const match = stdout.match(/^PRETTY_NAME="(.+)"/m);
      if (match) distro = match[1];
    } catch { /* not available */ }
  } else if (os === 'macos') {
    try {
      const { stdout } = await execa('sw_vers', ['-productVersion']);
      distro = `macOS ${stdout.trim()}`;
    } catch { distro = 'macOS'; }
  }

  const arch = process.arch;

  let cores = 1;
  try {
    const { stdout } = await execa('nproc', [], { reject: false });
    cores = parseInt(stdout) || 1;
  } catch {
    const cpus = await import('os').then(o => o.cpus());
    cores = cpus.length;
  }

  let memoryGB = 0;
  try {
    const osMod = await import('os');
    memoryGB = Math.round(osMod.totalmem() / 1073741824);
  } catch { /* ignore */ }

  let diskFreeGB = 0;
  if (os === 'linux' || os === 'macos') {
    try {
      const { stdout } = await execa('df', ['-BG', '/']);
      const match = stdout.match(/(\d+)G\s+\d+%/);
      if (match) diskFreeGB = parseInt(match[1]);
    } catch { /* ignore */ }
  }

  let dockerInstalled = false;
  let dockerVersion: string | null = null;
  try {
    const { stdout } = await execa('docker', ['--version']);
    dockerInstalled = true;
    const match = stdout.match(/Docker version ([\d.]+)/);
    dockerVersion = match ? match[1] : stdout.trim();
  } catch { /* not installed */ }

  let dockerComposeInstalled = false;
  if (dockerInstalled) {
    try {
      await execa('docker', ['compose', 'version']);
      dockerComposeInstalled = true;
    } catch { /* not available */ }
  }

  let traefikNetwork: string | null = null;
  if (dockerInstalled) {
    try {
      const { stdout } = await execa('docker', ['network', 'ls', '--format', '{{.Name}}']);
      const networks = stdout.split('\n').filter(Boolean);
      const match = networks.find(n => /traefik|proxy/i.test(n));
      if (match) traefikNetwork = match.trim();
    } catch { /* ignore */ }
  }

  let sshPort = 22;
  if (os === 'linux') {
    try {
      const { stdout } = await execa('ss', ['-tlnp'], { reject: false });
      const match = stdout.match(/:(\d+)\s.*sshd/);
      if (match) sshPort = parseInt(match[1]);
    } catch { /* ignore */ }
  }

  return { os, distro, arch, cores, memoryGB, diskFreeGB, dockerInstalled, dockerVersion, dockerComposeInstalled, traefikNetwork, sshPort };
}
