import { beforeEach, describe, expect, it } from 'vitest';
import {
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
    const summaries = summarizeEgress(parseSynSent(SS_OUTPUT), pids);

    const web = summaries.find(summary => summary.container === 'synthfin-web');
    expect(web).toMatchObject({ synSent: 2, distinctDst: 2, distinctPorts: 2, web: 2, rfc1918: 0 });

    const worker = summaries.find(summary => summary.container === 'worker');
    expect(worker).toMatchObject({ synSent: 1, distinctDst: 1, distinctPorts: 1, web: 0, rfc1918: 1 });
  });

  it('summarizes a single container netns', () => {
    const summary = summarizeContainer('synthfin-web', parseSynSent(SS_OUTPUT));
    expect(summary).toMatchObject({ synSent: 3, distinctDst: 3, distinctPorts: 3, web: 2, rfc1918: 1 });
  });

  it('normalizes the aggregate line into a container_egress event', () => {
    const [event] = EventNormalizer.normalizeBatch([{
      serverId: 1,
      serverName: 'hetzner-prod',
      source: 'container_egress',
      timestamp: new Date(),
      line: 'synthfin-web|syn=60|dst=25|ports=10|web=22|rfc=0|sample=1.2.3.4:80,5.6.7.8:443',
    }]);

    expect(event?.source).toBe('container_egress');
    expect(event?.metadata).toMatchObject({
      containerName: 'synthfin-web',
      synSent: 60,
      distinctDst: 25,
      distinctPorts: 10,
      webDst: 22,
      rfc1918Dst: 0,
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
