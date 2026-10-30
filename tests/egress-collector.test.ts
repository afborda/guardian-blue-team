import { beforeEach, describe, expect, it } from 'vitest';
import {
  parseSockets,
  parseSynSent,
  summarizeContainer,
  summarizeEgress,
} from '../src/collectors/egress-collector.js';
import { EventDetector } from '../src/pipeline/detector.js';
import { EventNormalizer } from '../src/pipeline/normalizer.js';
import type { NormalizedEvent } from '../src/pipeline/normalizer.js';

const SS_OUTPUT = `State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
SYN-SENT 0 1 172.18.0.5:40000 1.2.3.4:80 users:(("next-server",pid=123,fd=20))
SYN-SENT 0 1 172.18.0.5:40001 5.6.7.8:443 users:(("next-server",pid=123,fd=21))
SYN-SENT 0 1 172.18.0.5:40002 10.0.0.9:5432 users:(("node",pid=999,fd=22))
ESTAB 0 0 172.18.0.5:50000 1.1.1.1:443 users:(("next-server",pid=123,fd=23))
ESTAB 0 0 172.18.0.5:50001 8.8.8.8:443 users:(("next-server",pid=123,fd=24))
ESTAB 0 0 172.18.0.5:80 9.9.9.9:55555 users:(("next-server",pid=123,fd=25))
`;

function egressEvent(metadata: Record<string, unknown>): NormalizedEvent {
  return {
    serverId: 1,
    timestamp: new Date(),
    source: 'container_egress',
    category: 'container',
    severity: 'info',
    eventType: 'container_egress_snapshot',
    sourceIp: '1.2.3.4',
    destinationPort: 80,
    userName: null,
    processName: 'synthfin-web',
    rawLog: 'synthfin-web|syn=60|dst=25|ports=10|web=22|rfc=0',
    metadata,
  };
}

describe('egress collector', () => {
  beforeEach(() => {
    EventDetector.clearBuffer();
  });

  it('parses SYN_SENT lines with pid, process and remote address', () => {
    const rows = parseSynSent(SS_OUTPUT);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatchObject({ pid: 123, process: 'next-server', remoteIp: '1.2.3.4', remotePort: 80 });
  });

  it('maps PIDs to containers and aggregates fan-out', () => {
    const pids = new Map<number, string>([[123, 'synthfin-web'], [999, 'worker']]);
    const summaries = summarizeEgress(parseSockets(SS_OUTPUT), pids);

    const web = summaries.find(summary => summary.container === 'synthfin-web');
    expect(web).toMatchObject({
      synSent: 2,
      distinctDst: 2,
      distinctPorts: 2,
      web: 2,
      rfc1918: 0,
      establishedWeb: 2,
      establishedDst: 2,
    });

    const worker = summaries.find(summary => summary.container === 'worker');
    expect(worker).toMatchObject({ synSent: 1, distinctDst: 1, distinctPorts: 1, web: 0, rfc1918: 1 });
  });

  it('summarizes a single container netns', () => {
    const summary = summarizeContainer('synthfin-web', parseSockets(SS_OUTPUT));
    expect(summary).toMatchObject({
      synSent: 3,
      distinctDst: 3,
      distinctPorts: 3,
      web: 2,
      rfc1918: 1,
      establishedWeb: 2,
      establishedDst: 2,
    });
  });

  it('ignores a container with only inbound established connections', () => {
    const inbound = 'ESTAB 0 0 172.18.0.5:80 9.9.9.9:55555 users:(("nginx",pid=321,fd=1))';
    expect(summarizeContainer('web', parseSockets(inbound))).toBeNull();
  });

  it('normalizes the aggregate line into a container_egress event', () => {
    const [event] = EventNormalizer.normalizeBatch([{
      serverId: 1,
      serverName: 'hetzner-prod',
      source: 'container_egress',
      timestamp: new Date(),
      line: 'synthfin-web|syn=60|dst=25|ports=10|web=22|rfc=0|est=3|estdst=3|sample=1.2.3.4:80,5.6.7.8:443',
    }]);

    expect(event?.source).toBe('container_egress');
    expect(event?.metadata).toMatchObject({
      containerName: 'synthfin-web',
      synSent: 60,
      distinctDst: 25,
      distinctPorts: 10,
      webDst: 22,
      rfc1918Dst: 0,
      establishedWeb: 3,
      establishedDst: 3,
    });
  });

  it('fires a critical egress incident on fan-out to web ports', () => {
    const detected = EventDetector.detect([egressEvent({
      containerName: 'synthfin-web',
      synSent: 60,
      distinctDst: 25,
      distinctPorts: 10,
      webDst: 22,
      rfc1918Dst: 0,
    })]);

    expect(detected.some(event => event.eventType === 'container_egress_scan')).toBe(true);
  });

  it('fires on internal (RFC1918) fan-out even with few destinations', () => {
    const detected = EventDetector.detect([egressEvent({
      containerName: 'synthfin-web',
      synSent: 8,
      distinctDst: 6,
      distinctPorts: 6,
      webDst: 0,
      rfc1918Dst: 6,
    })]);

    expect(detected.some(event => event.eventType === 'container_egress_scan')).toBe(true);
  });

  it('fires when established outbound fan-out to web ports is high', () => {
    const detected = EventDetector.detect([egressEvent({
      containerName: 'synthfin-web',
      synSent: 0,
      distinctDst: 0,
      distinctPorts: 0,
      webDst: 0,
      rfc1918Dst: 0,
      establishedDst: 25,
    })]);

    expect(detected.some(event => event.eventType === 'container_egress_scan')).toBe(true);
  });

  it('does not fire on many retries to a single destination', () => {
    const detected = EventDetector.detect([egressEvent({
      containerName: 'synthfin-web',
      synSent: 80,
      distinctDst: 1,
      distinctPorts: 1,
      webDst: 1,
      rfc1918Dst: 0,
    })]);

    expect(detected.some(event => event.eventType === 'container_egress_scan')).toBe(false);
  });

  it('stays quiet for a handful of legitimate connections', () => {
    const detected = EventDetector.detect([egressEvent({
      containerName: 'synthfin-web',
      synSent: 3,
      distinctDst: 2,
      distinctPorts: 2,
      webDst: 2,
      rfc1918Dst: 0,
    })]);

    expect(detected.some(event => event.eventType === 'container_egress_scan')).toBe(false);
  });
});
