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
      data: { firewall: firewallData, fail2ban: fail2banData, sshConfig: sshConfigData, mac: macData, users: usersData, cronJobs: cronData },
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
  const bansResult = await exec.run('fail2ban-client status sshd 2>/dev/null | grep "Currently banned"');
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
  const sudoResult = await exec.run('getent group sudo wheel 2>/dev/null | cut -d: -f4');
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
