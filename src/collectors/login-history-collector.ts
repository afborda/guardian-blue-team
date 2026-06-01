import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import { logger } from '../utils/logger.js';
import type { RawLogEntry } from './log-collector.js';

export interface LoginSession {
  user: string;
  tty: string;
  fromIp: string | null;
  loginAt: Date;
  logoutAt: Date | null;
  duration: string | null;
  stillLoggedIn: boolean;
}

export interface FailedLogin {
  user: string;
  fromIp: string | null;
  timestamp: Date;
  reason: string;
}

export class LoginHistoryCollector {
  // Active sessions + recent login history via wtmp
  static async collectSessions(target: SSHTarget, maxEntries = 50): Promise<RawLogEntry[]> {
    const result = await SSHCollector.run(
      target,
      `last -F -n ${maxEntries} 2>/dev/null || last -n ${maxEntries} 2>/dev/null || echo ''`,
      10_000,
    );
    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 5 && !line.startsWith('wtmp') && !line.startsWith('btmp'))
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'login_history',
        timestamp: this.parseLastTimestamp(line),
        line,
      }));
  }

  // Failed logins via btmp (brute force, wrong password, bad user)
  static async collectFailedLogins(target: SSHTarget, maxEntries = 50): Promise<RawLogEntry[]> {
    const result = await SSHCollector.run(
      target,
      `sudo lastb -F -n ${maxEntries} 2>/dev/null || sudo lastb -n ${maxEntries} 2>/dev/null || echo ''`,
      10_000,
    );
    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 5 && !line.startsWith('btmp'))
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'login_failed',
        timestamp: this.parseLastTimestamp(line),
        line,
      }));
  }

  // Who is currently logged in (interactive sessions right now)
  static async collectCurrentSessions(target: SSHTarget): Promise<RawLogEntry[]> {
    const result = await SSHCollector.run(target, `w -h 2>/dev/null || who 2>/dev/null || echo ''`, 8_000);
    if (!result.success || !result.stdout.trim()) return [];

    return result.stdout.trim().split('\n')
      .filter(line => line.length > 5)
      .map(line => ({
        serverId: target.id,
        serverName: target.name,
        source: 'who',
        timestamp: new Date(),
        line,
      }));
  }

  private static parseLastTimestamp(line: string): Date {
    // last -F format: "user pts/0 1.2.3.4 Sun Jan 15 10:30:45 2024 - Sun Jan 15 10:45:00 2024"
    const fullMatch = line.match(/\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\d{4})/);
    if (fullMatch) {
      const dateStr = fullMatch[0];
      const parsed = new Date(dateStr);
      if (!isNaN(parsed.getTime())) return parsed;
    }
    // last (no -F) format: "user pts/0 1.2.3.4 Mon Jan 15 10:30"
    const shortMatch = line.match(/\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}/);
    if (shortMatch) {
      const year = new Date().getFullYear();
      const parsed = new Date(`${shortMatch[0]} ${year}`);
      if (!isNaN(parsed.getTime())) return parsed;
    }
    return new Date();
  }
}

export function parseLoginSession(line: string): LoginSession | null {
  // Format: "user   tty   from_ip   login_time - logout_time  (duration)"
  // or:     "user   tty   login_time   still logged in"
  const parts = line.trim().split(/\s{2,}/);
  if (parts.length < 2) return null;

  const user = parts[0].trim();
  const tty = parts[1]?.trim() ?? '';
  if (!user || user === 'reboot' || user === 'shutdown') return null;

  const fromIpMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  const fromIp = fromIpMatch ? fromIpMatch[1] : null;
  const stillLoggedIn = line.includes('still logged in');
  const duration = line.match(/\((\d+:\d{2})\)/)?.[1] ?? null;

  return { user, tty, fromIp, loginAt: new Date(), logoutAt: null, duration, stillLoggedIn };
}

export function parseFailedLogin(line: string): FailedLogin | null {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) return null;
  const user = parts[0];
  if (!user || user.startsWith('-')) return null;
  const fromIpMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  return {
    user,
    fromIp: fromIpMatch ? fromIpMatch[1] : null,
    timestamp: new Date(),
    reason: 'authentication failure',
  };
}

// Needed so normalizer can check for unusual hour without breaking existing auth events
export function isUnusualHour(date: Date): boolean {
  // BRT = UTC-3. Unusual = 00:00–06:00 BRT = 03:00–09:00 UTC
  const hourUtc = date.getUTCHours();
  return hourUtc >= 3 && hourUtc < 9;
}

export { logger as _logger };
