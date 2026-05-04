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
