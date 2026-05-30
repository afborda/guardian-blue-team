import { randomBytes, timingSafeEqual } from 'crypto';

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]{3,45}$/;
const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9])?$/;
const PACKAGE_RE = /^[a-zA-Z0-9][a-zA-Z0-9.+\-_:~]{0,127}$/;
const CONTAINER_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$/;
const PROCESS_RE = /^[a-zA-Z0-9._\-/]{1,128}$/;
const SSH_USER_RE = /^[a-z_][a-z0-9_\-]{0,31}$/;
const KEY_PATH_RE = /^\/[\w./-]+$/;
const SERVER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,63}$/;

export function isValidIp(ip: string): boolean {
  if (IPV4_RE.test(ip)) {
    return ip.split('.').every(oct => {
      const n = parseInt(oct);
      return n >= 0 && n <= 255;
    });
  }
  return IPV6_RE.test(ip);
}

export function isPrivateIp(ip: string): boolean {
  if (IPV4_RE.test(ip)) {
    const parts = ip.split('.').map(o => parseInt(o, 10));
    if (parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return false;
    const [a, b] = parts;
    if (a === 10) return true;                          // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return true;   // 172.16.0.0/12
    if (a === 192 && b === 168) return true;            // 192.168.0.0/16
    if (a === 127) return true;                         // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true;            // 169.254.0.0/16 link-local
    return false;
  }
  if (!IPV6_RE.test(ip)) return false;
  const lower = ip.toLowerCase();
  if (lower === '::1') return true;                      // loopback v6
  // fe80::/10 — first 10 bits 1111111010, so high byte 0xfe and second-byte
  // high nibble ∈ {8,9,a,b}. Plain startsWith('fe80:') misses fe9x/feax/febx.
  if (/^fe[89ab][0-9a-f]?:/.test(lower)) return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;        // fc00::/7 ULA
  return false;
}

export function isValidHostname(host: string): boolean {
  return HOSTNAME_RE.test(host) && host.length <= 255;
}

export function isValidPackageName(name: string): boolean {
  return PACKAGE_RE.test(name);
}

export function isValidContainerName(name: string): boolean {
  return CONTAINER_RE.test(name);
}

export function isValidProcessPattern(name: string): boolean {
  return PROCESS_RE.test(name);
}

export function isValidSshUser(user: string): boolean {
  return SSH_USER_RE.test(user);
}

export function isValidKeyPath(path: string): boolean {
  return KEY_PATH_RE.test(path) && !path.includes('..');
}

export function isValidServerName(name: string): boolean {
  return SERVER_NAME_RE.test(name);
}

export function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function secureId(): string {
  return randomBytes(16).toString('hex');
}
