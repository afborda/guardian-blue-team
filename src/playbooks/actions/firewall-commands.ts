import { canonicalIp } from '../../utils/ip-canonical.js';

/**
 * Insert at position 1. `ufw deny` appends, and on this host the first rules
 * are ACCEPT for 49222/80/443 — an appended DENY never matches those ports.
 */
export function ufwDenyCommand(ip: string, commentPrefix: 'guardian-block' | 'guardian-prop', now = Date.now()): string {
  const shown = canonicalIp(ip);
  return `sudo ufw insert 1 deny from ${shown} comment '${commentPrefix}-${now}'`;
}

/**
 * Append form already hashed into guardian-shells installed before insert-at-1.
 * Those hosts reject the insert command until the shell is updated.
 */
export function ufwDenyAppendCommand(ip: string, commentPrefix: 'guardian-block' | 'guardian-prop', now = Date.now()): string {
  const shown = canonicalIp(ip);
  return `sudo ufw deny from ${shown} comment '${commentPrefix}-${now}'`;
}

/**
 * Grep the form UFW prints (compressed IPv6), using the command those shells
 * already allow. `grep -F` is a different hash and would fail verification
 * on every old host.
 */
export function ufwVerifyCommand(ip: string): string {
  const shown = canonicalIp(ip);
  return `sudo ufw status | grep -q '${shown}'`;
}

/**
 * Alert the first time a block fails twice, then about once a week
 * (re-verify runs every 6h; 28 strikes ≈ 7 days). Stops the every-cycle Telegram spam.
 */
export function shouldNotifyBlockLost(failures: number): boolean {
  if (failures < 2) return false;
  if (failures === 2) return true;
  return failures % 28 === 0;
}

export function formatBlockLost(serverName: string, ip: string, failures: number, lastChecked: string): { title: string; body: string } {
  return {
    title: `Checagem de bloqueio falhou em ${serverName}`,
    body: [
      `IP: ${ip}`,
      `A checagem não encontrou a regra. Isso já aconteceu ${failures} vezes.`,
      lastChecked ? `Última checagem: ${lastChecked}.` : '',
      '',
      'O que isso quer dizer: o IP pode continuar barrado e só a consulta estar errada. É comum com IPv6, porque o firewall grava o endereço curto e o Guardian procurava o endereço longo.',
      '',
      'Quando se preocupar: se muitos IPs diferentes falharem no mesmo dia, alguém pode ter apagado o firewall. Um IP só, repetindo há dias, não é invasão.',
      '',
      'O Guardian vai tentar aplicar a regra de novo. Não precisa bloquear esse IP na mão.',
    ].filter((line) => line !== undefined).join('\n'),
  };
}
