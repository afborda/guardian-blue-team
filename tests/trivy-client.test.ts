import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock SSHCollector and override config to drive Trivy state per-test.
const sshRunMock = vi.fn();

vi.mock('../src/collectors/ssh-collector.js', () => ({
  SSHCollector: { run: sshRunMock },
}));

const mockConfig: { trivy: { serverUrl: string | null; token: string | null } } = {
  trivy: { serverUrl: null, token: null },
};

vi.mock('../src/config/environment.js', () => ({
  config: mockConfig,
}));

const { TrivyClient } = await import('../src/vuln-scanner/trivy-client.js');

const target = { host: '10.0.0.1', port: 22, user: 'guardian' };

beforeEach(() => {
  sshRunMock.mockReset();
  mockConfig.trivy.serverUrl = null;
  mockConfig.trivy.token = null;
});

describe('TrivyClient.isConfigured', () => {
  it('false when serverUrl is null', () => {
    expect(TrivyClient.isConfigured()).toBe(false);
  });

  it('true when serverUrl is set', () => {
    mockConfig.trivy.serverUrl = 'http://trivy:4954';
    expect(TrivyClient.isConfigured()).toBe(true);
  });
});

describe('TrivyClient.scanImage — graceful degradation', () => {
  it('returns [] without invoking SSH when not configured', async () => {
    const findings = await TrivyClient.scanImage(target, 'nginx', '1.21');
    expect(findings).toEqual([]);
    expect(sshRunMock).not.toHaveBeenCalled();
  });

  it('returns [] when SSH command fails', async () => {
    mockConfig.trivy.serverUrl = 'http://trivy:4954';
    sshRunMock.mockResolvedValueOnce({ success: false, stdout: '', error: 'trivy: command not found', durationMs: 50 });

    const findings = await TrivyClient.scanImage(target, 'nginx', '1.21');
    expect(findings).toEqual([]);
  });

  it('returns [] when stdout is empty (Trivy server unreachable)', async () => {
    mockConfig.trivy.serverUrl = 'http://trivy:4954';
    sshRunMock.mockResolvedValueOnce({ success: true, stdout: '', durationMs: 50 });

    const findings = await TrivyClient.scanImage(target, 'nginx', '1.21');
    expect(findings).toEqual([]);
  });

  it('passes --token flag when configured, omits it when null', async () => {
    mockConfig.trivy.serverUrl = 'http://trivy:4954';
    mockConfig.trivy.token = 'secret-token';
    sshRunMock.mockResolvedValueOnce({ success: true, stdout: '{}', durationMs: 100 });

    await TrivyClient.scanImage(target, 'nginx', '1.21');
    const cmd = sshRunMock.mock.calls[0][1];
    expect(cmd).toContain("--token 'secret-token'");
    expect(cmd).toContain("--server 'http://trivy:4954'");
    expect(cmd).toContain("'nginx:1.21'");
  });

  it('shell-escapes single quotes in image refs (defense-in-depth)', async () => {
    mockConfig.trivy.serverUrl = 'http://trivy:4954';
    sshRunMock.mockResolvedValueOnce({ success: true, stdout: '{}', durationMs: 100 });

    await TrivyClient.scanImage(target, "ev'il", 'tag');
    const cmd = sshRunMock.mock.calls[0][1];
    // The single quote must be broken out of the surrounding quotes.
    expect(cmd).toContain("'ev'\\''il:tag'");
  });
});

describe('TrivyClient.parseReport', () => {
  it('extracts findings from a typical Trivy JSON report', () => {
    const report = JSON.stringify({
      Results: [
        {
          Target: 'nginx:1.21 (debian 11.2)',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2022-1234',
              PkgName: 'libssl',
              InstalledVersion: '1.1.1k-1',
              FixedVersion: '1.1.1n-0',
              Severity: 'CRITICAL',
              Title: 'OpenSSL infinite loop',
            },
            {
              VulnerabilityID: 'CVE-2022-5678',
              PkgName: 'zlib',
              InstalledVersion: '1.2.11',
              Severity: 'HIGH',
            },
          ],
        },
      ],
    });

    const findings = TrivyClient.parseReport(report, 'nginx', '1.21');
    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({
      image: 'nginx',
      tag: '1.21',
      cveId: 'CVE-2022-1234',
      severity: 'critical',
      packageName: 'libssl',
      installedVersion: '1.1.1k-1',
      fixedVersion: '1.1.1n-0',
      title: 'OpenSSL infinite loop',
    });
    expect(findings[1].severity).toBe('high');
    expect(findings[1].fixedVersion).toBeNull(); // missing FixedVersion → null, not undefined
  });

  it('returns [] for malformed JSON (no crash)', () => {
    expect(TrivyClient.parseReport('not json', 'a', 'b')).toEqual([]);
  });

  it('returns [] when Results is empty (clean image)', () => {
    expect(TrivyClient.parseReport(JSON.stringify({ Results: [] }), 'a', 'b')).toEqual([]);
  });

  it('returns [] when Results is missing entirely', () => {
    expect(TrivyClient.parseReport('{}', 'a', 'b')).toEqual([]);
  });

  it('normalizes unknown severity to "unknown" sentinel', () => {
    const report = JSON.stringify({
      Results: [{ Vulnerabilities: [{ VulnerabilityID: 'CVE-X', PkgName: 'p', InstalledVersion: '1', Severity: 'INFO' }] }],
    });
    expect(TrivyClient.parseReport(report, 'a', 'b')[0].severity).toBe('unknown');
  });

  it('truncates findings at 50 per image to bound noisy reports', () => {
    const vulns = Array.from({ length: 80 }, (_, i) => ({
      VulnerabilityID: `CVE-2024-${i}`,
      PkgName: 'noisy',
      InstalledVersion: '1.0',
      Severity: 'HIGH',
    }));
    const report = JSON.stringify({ Results: [{ Vulnerabilities: vulns }] });
    expect(TrivyClient.parseReport(report, 'a', 'b')).toHaveLength(50);
  });

  it('truncates overly long titles to keep alert payloads bounded', () => {
    const longTitle = 'x'.repeat(500);
    const report = JSON.stringify({
      Results: [{ Vulnerabilities: [{ VulnerabilityID: 'CVE-X', PkgName: 'p', InstalledVersion: '1', Severity: 'HIGH', Title: longTitle }] }],
    });
    expect(TrivyClient.parseReport(report, 'a', 'b')[0].title.length).toBeLessThanOrEqual(200);
  });

  it('falls back to Description when Title is missing', () => {
    const report = JSON.stringify({
      Results: [{ Vulnerabilities: [{ VulnerabilityID: 'CVE-X', PkgName: 'p', InstalledVersion: '1', Severity: 'HIGH', Description: 'desc text' }] }],
    });
    expect(TrivyClient.parseReport(report, 'a', 'b')[0].title).toBe('desc text');
  });
});
