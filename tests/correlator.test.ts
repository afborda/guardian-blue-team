import { describe, it, expect, beforeEach } from 'vitest';
import { EventCorrelator } from '../src/pipeline/correlator.js';
import type { NormalizedEvent } from '../src/pipeline/normalizer.js';

function makeEvent(overrides: Partial<NormalizedEvent> = {}): NormalizedEvent {
  return {
    serverId: 1,
    timestamp: new Date(),
    source: 'auth.log',
    category: 'authentication',
    severity: 'high',
    eventType: 'ssh_failed_password',
    sourceIp: '192.168.1.100',
    rawLog: '',
    ...overrides,
  };
}

describe('EventCorrelator', () => {
  beforeEach(() => {
    EventCorrelator.clearBuffer();
  });

  it('buffers events internally', async () => {
    const events = [makeEvent()];
    const results = await EventCorrelator.correlate(events);
    expect(results).toHaveLength(1);
    expect(results[0].event.sourceIp).toBe('192.168.1.100');
  });

  it('does not create incident below threshold', async () => {
    const events = Array.from({ length: 3 }, () => makeEvent());
    const results = await EventCorrelator.correlate(events);
    expect(results.every(r => r.incidentId === null)).toBe(true);
  });

  it('creates brute force incident at threshold', async () => {
    const events = Array.from({ length: 10 }, () => makeEvent());
    const results = await EventCorrelator.correlate(events);
    const withIncident = results.filter(r => r.incidentId !== null);
    expect(withIncident.length).toBeGreaterThan(0);
  });

  it('creates port scan incident for many blocked ports', async () => {
    const events = Array.from({ length: 15 }, (_, i) =>
      makeEvent({
        eventType: 'firewall_block',
        sourceIp: '10.0.0.1',
        destinationPort: 1000 + i,
      })
    );
    const results = await EventCorrelator.correlate(events);
    const withIncident = results.filter(r => r.incidentId !== null);
    expect(withIncident.length).toBeGreaterThan(0);
  });

  it('creates unauthorized access incident for critical events', async () => {
    const events = [makeEvent({ eventType: 'unauthorized_login', sourceIp: '5.5.5.5' })];
    const results = await EventCorrelator.correlate(events);
    const withIncident = results.filter(r => r.incidentId !== null);
    expect(withIncident.length).toBe(1);
  });
});
