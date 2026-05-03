import { describe, it, expect } from 'vitest';
import { EventNormalizer } from '../src/pipeline/normalizer.js';
import type { RawLogEntry } from '../src/collectors/log-collector.js';

function makeEntry(line: string, source = 'auth.log'): RawLogEntry {
  return {
    serverId: 1,
    serverName: 'test-server',
    source,
    timestamp: new Date(),
    line,
  };
}

describe('EventNormalizer', () => {
  it('normalizes sshd failed password log', () => {
    const entry = makeEntry('Failed password for admin from 192.168.1.50 port 42222 ssh2');
    const event = EventNormalizer.normalize(entry);
    expect(event).not.toBeNull();
    expect(event!.eventType).toBe('ssh_failed_password');
    expect(event!.sourceIp).toBe('192.168.1.50');
    expect(event!.userName).toBe('admin');
  });

  it('normalizes sshd invalid user log', () => {
    const entry = makeEntry('Invalid user hacker from 10.0.0.1 port 55555');
    const event = EventNormalizer.normalize(entry);
    expect(event).not.toBeNull();
    expect(event!.eventType).toBe('ssh_invalid_user');
    expect(event!.sourceIp).toBe('10.0.0.1');
    expect(event!.userName).toBe('hacker');
  });

  it('normalizes sshd accepted publickey log', () => {
    const entry = makeEntry('Accepted publickey for ubuntu from 172.16.0.5 port 33333 ssh2');
    const event = EventNormalizer.normalize(entry);
    expect(event).not.toBeNull();
    expect(event!.eventType).toBe('ssh_login_success');
    expect(event!.sourceIp).toBe('172.16.0.5');
    expect(event!.userName).toBe('ubuntu');
  });

  it('normalizes UFW BLOCK log', () => {
    const entry = makeEntry('[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=192.168.1.1 DPT=8080 PROTO=TCP', 'ufw');
    const event = EventNormalizer.normalize(entry);
    expect(event).not.toBeNull();
    expect(event!.eventType).toBe('firewall_block');
    expect(event!.sourceIp).toBe('203.0.113.5');
    expect(event!.destinationPort).toBe(8080);
  });

  it('returns null for unrecognized auth logs', () => {
    const entry = makeEntry('some random log that does not match anything');
    const event = EventNormalizer.normalize(entry);
    expect(event).toBeNull();
  });

  it('returns null for unknown source', () => {
    const entry = makeEntry('some log', 'unknown-source');
    const event = EventNormalizer.normalize(entry);
    expect(event).toBeNull();
  });

  it('normalizeBatch filters nulls', () => {
    const entries = [
      makeEntry('Failed password for root from 1.1.1.1 port 22 ssh2'),
      makeEntry('some noise line'),
      makeEntry('Invalid user test from 2.2.2.2 port 22'),
    ];
    const events = EventNormalizer.normalizeBatch(entries);
    expect(events).toHaveLength(2);
    expect(events[0].sourceIp).toBe('1.1.1.1');
    expect(events[1].sourceIp).toBe('2.2.2.2');
  });
});
