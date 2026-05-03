import { describe, it, expect, beforeEach } from 'vitest';
import { EventDetector } from '../src/pipeline/detector.js';
import type { NormalizedEvent } from '../src/pipeline/normalizer.js';

function makeEvent(overrides: Partial<NormalizedEvent> = {}): NormalizedEvent {
  return {
    serverId: 1,
    timestamp: new Date(),
    source: 'auth.log',
    category: 'authentication',
    severity: 'info',
    eventType: 'ssh_login_success',
    rawLog: '',
    ...overrides,
  };
}

describe('EventDetector', () => {
  beforeEach(() => {
    EventDetector.clearBuffer();
  });

  it('detects crypto mining processes', () => {
    const events: NormalizedEvent[] = [
      makeEvent({ source: 'process', rawLog: 'xmrig --donate-level 1 -o pool.example.com' }),
    ];
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'crypto_mining')).toBe(true);
    expect(detected[0].severity).toBe('critical');
  });

  it('detects suspicious binaries from /tmp', () => {
    const events: NormalizedEvent[] = [
      makeEvent({ source: 'process', rawLog: '/tmp/.hidden/payload --daemon' }),
    ];
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'suspicious_binary')).toBe(true);
  });

  it('detects suspicious binaries from /dev/shm', () => {
    const events: NormalizedEvent[] = [
      makeEvent({ source: 'process', rawLog: '/dev/shm/backdoor serve' }),
    ];
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'suspicious_binary')).toBe(true);
  });

  it('detects password login via rawLog', () => {
    // Use a trusted IP so unauthorized_login doesn't trigger first
    const events: NormalizedEvent[] = [
      makeEvent({
        eventType: 'ssh_login_success',
        sourceIp: '203.0.113.10',
        rawLog: 'Accepted password for ubuntu from 203.0.113.10 port 54321 ssh2',
      }),
    ];
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'password_login')).toBe(true);
  });

  it('does NOT flag key-based login as password login', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        eventType: 'ssh_login_success',
        sourceIp: '203.0.113.10',
        rawLog: 'Accepted publickey for ubuntu from 203.0.113.10 port 54321 ssh2',
      }),
    ];
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'password_login')).toBe(false);
  });

  it('does NOT flag trusted IPs as unauthorized', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        eventType: 'ssh_login_success',
        sourceIp: '203.0.113.10',
        rawLog: 'Accepted publickey for ubuntu from 203.0.113.10',
      }),
    ];
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'unauthorized_login')).toBe(false);
  });

  it('flags unknown IPs as unauthorized login', () => {
    const events: NormalizedEvent[] = [
      makeEvent({
        eventType: 'ssh_login_success',
        sourceIp: '45.33.32.156',
        rawLog: 'Accepted publickey for ubuntu from 45.33.32.156 port 12345 ssh2',
      }),
    ];
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'unauthorized_login')).toBe(true);
  });

  it('detects SSH brute force burst (20+ failures from same IP)', () => {
    const events: NormalizedEvent[] = Array.from({ length: 25 }, () =>
      makeEvent({
        eventType: 'ssh_failed_password',
        sourceIp: '192.168.100.50',
        source: 'auth.log',
        rawLog: 'Failed password for root from 192.168.100.50',
      })
    );
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'ssh_brute_force')).toBe(true);
  });

  it('does NOT trigger brute force for < 20 failures', () => {
    const events: NormalizedEvent[] = Array.from({ length: 10 }, () =>
      makeEvent({
        eventType: 'ssh_failed_password',
        sourceIp: '192.168.100.50',
        source: 'auth.log',
        rawLog: 'Failed password for root from 192.168.100.50',
      })
    );
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'ssh_brute_force')).toBe(false);
  });

  it('detects lateral movement (login after failed attempts)', () => {
    EventDetector.detect([
      makeEvent({ eventType: 'ssh_failed_password', sourceIp: '10.0.0.5', rawLog: 'Failed password' }),
    ]);
    const events = [
      makeEvent({
        eventType: 'ssh_login_success',
        sourceIp: '10.0.0.5',
        rawLog: 'Accepted publickey for ubuntu from 10.0.0.5',
      }),
    ];
    const detected = EventDetector.detect(events);
    expect(detected.some(e => e.eventType === 'lateral_movement')).toBe(true);
  });
});
