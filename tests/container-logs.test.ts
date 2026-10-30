import { beforeEach, describe, expect, it } from 'vitest';
import {
  isSuspiciousContainerLine,
  parseDockerLogLine,
} from '../src/collectors/container-logs-collector.js';
import { EventDetector } from '../src/pipeline/detector.js';
import { EventNormalizer } from '../src/pipeline/normalizer.js';

const RAW = '2026-10-30T18:00:00.123456789Z ⨯ [Error: RCE_RES]';

describe('container stdout collector', () => {
  beforeEach(() => {
    EventDetector.clearBuffer();
  });

  it('strips the docker timestamp and detects RCE markers', () => {
    const parsed = parseDockerLogLine(RAW);
    expect(parsed.text).toContain('RCE_RES');
    expect(parsed.timestamp.toISOString()).toBe('2026-10-30T18:00:00.123Z');
    expect(isSuspiciousContainerLine(RAW)).toBe(true);
  });

  it('detects shell command-not-found from an exploit', () => {
    expect(isSuspiciousContainerLine('2026-10-30T18:00:00Z sh: 1: curl: not found')).toBe(true);
  });

  it('does not flag normal application noise', () => {
    expect(isSuspiciousContainerLine('2026-10-30T18:00:00Z GET /health 200')).toBe(false);
  });

  it('normalizes stdout into a container_stdout event', () => {
    const [event] = EventNormalizer.normalizeBatch([{
      serverId: 1,
      serverName: 'hetzner-prod',
      source: 'container_stdout',
      timestamp: new Date(),
      line: `synthfin-web|${RAW}`,
    }]);

    expect(event?.source).toBe('container_stdout');
    expect(event?.metadata).toMatchObject({ containerName: 'synthfin-web' });
    expect(event?.rawLog).toContain('RCE_RES');
  });

  it('fires a critical RCE incident', () => {
    const detected = EventDetector.detect([{
      serverId: 1,
      timestamp: new Date(),
      source: 'container_stdout',
      category: 'container',
      severity: 'info',
      eventType: 'container_stdout',
      sourceIp: null,
      destinationPort: null,
      userName: null,
      processName: 'synthfin-web',
      rawLog: RAW,
      metadata: { containerName: 'synthfin-web', logLine: RAW },
    }]);

    expect(detected.some(event => event.eventType === 'container_rce_marker')).toBe(true);
  });
});
