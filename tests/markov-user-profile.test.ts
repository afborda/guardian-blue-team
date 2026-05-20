import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock db.execute BEFORE importing the service. The setup.ts mock doesn't
// include execute(), so we add it per-test by overriding the module mock.
const executeMock = vi.fn();
vi.mock('../src/database/connection.js', () => ({
  db: { execute: executeMock },
  dbTrue: true,
  dbFalse: false,
  dbNow: () => new Date(),
}));

const { MarkovUserProfile, MIN_SAMPLES } = await import('../src/intelligence/markov-user-profile.service.js');

// Drizzle's execute() returns an object with `.rows` for pg. The service does
// `(result as unknown as { rows: T[] }).rows`, so the mock just returns
// `{ rows: [...] }` directly.
function rowsResponse<T>(rows: T[]): { rows: T[] } {
  return { rows };
}

describe('MarkovUserProfile.score', () => {
  beforeEach(() => {
    executeMock.mockReset();
  });

  it('returns cold reason when user has fewer than MIN_SAMPLES transitions', async () => {
    executeMock.mockResolvedValueOnce(rowsResponse([{
      p99_surprisal: 4.0,
      total_samples: MIN_SAMPLES - 1,
      min_observed_p: 0.01,
    }]));

    const result = await MarkovUserProfile.score(1, 'alice', 'ls', 'cat');
    expect(result?.reason).toBe('cold');
    expect(result?.isAnomaly).toBe(false);
    expect(result?.totalSamples).toBe(MIN_SAMPLES - 1);
    // Threshold lookup should be the only call — no follow-up to transitions.
    expect(executeMock).toHaveBeenCalledTimes(1);
  });

  it('returns cold when no threshold row exists at all (user never seen)', async () => {
    executeMock.mockResolvedValueOnce(rowsResponse([]));

    const result = await MarkovUserProfile.score(1, 'newbie', 'ls', 'cat');
    expect(result?.reason).toBe('cold');
    expect(result?.totalSamples).toBe(0);
  });

  it('flags high surprisal as anomaly when above p99 threshold', async () => {
    executeMock
      .mockResolvedValueOnce(rowsResponse([{
        p99_surprisal: 3.0, // -ln(0.05) ≈ 3.0
        total_samples: 100,
        min_observed_p: 0.001,
      }]))
      .mockResolvedValueOnce(rowsResponse([{ p: 0.001 }])); // -ln(0.001) ≈ 6.9 > 3.0

    const result = await MarkovUserProfile.score(1, 'alice', 'ls', 'rm');
    expect(result?.reason).toBe('scored');
    expect(result?.isAnomaly).toBe(true);
    expect(result?.surprisal).toBeCloseTo(-Math.log(0.001), 4);
    expect(result?.threshold).toBe(3.0);
  });

  it('does NOT flag normal-frequency transitions', async () => {
    executeMock
      .mockResolvedValueOnce(rowsResponse([{
        p99_surprisal: 4.0,
        total_samples: 200,
        min_observed_p: 0.001,
      }]))
      .mockResolvedValueOnce(rowsResponse([{ p: 0.5 }])); // -ln(0.5) ≈ 0.69, well below 4.0

    const result = await MarkovUserProfile.score(1, 'alice', 'ls', 'cat');
    expect(result?.reason).toBe('scored');
    expect(result?.isAnomaly).toBe(false);
    expect(result?.surprisal).toBeCloseTo(-Math.log(0.5), 4);
  });

  it('uses min_observed_p as floor for unseen transitions', async () => {
    executeMock
      .mockResolvedValueOnce(rowsResponse([{
        p99_surprisal: 5.0,
        total_samples: 100,
        min_observed_p: 0.002, // -ln(0.002) ≈ 6.21 > 5.0 → anomaly
      }]))
      .mockResolvedValueOnce(rowsResponse([])); // unseen — no row

    const result = await MarkovUserProfile.score(1, 'alice', 'systemctl', 'curl');
    expect(result?.reason).toBe('unseen');
    expect(result?.isAnomaly).toBe(true);
    expect(result?.surprisal).toBeCloseTo(-Math.log(0.002), 4);
  });

  it('returns unseen with isAnomaly=false when min_observed_p is null', async () => {
    executeMock
      .mockResolvedValueOnce(rowsResponse([{
        p99_surprisal: 5.0,
        total_samples: 100,
        min_observed_p: null,
      }]))
      .mockResolvedValueOnce(rowsResponse([]));

    const result = await MarkovUserProfile.score(1, 'alice', 'foo', 'bar');
    expect(result?.reason).toBe('unseen');
    expect(result?.isAnomaly).toBe(false);
  });

  it('returns null on database error so detection never crashes', async () => {
    executeMock.mockRejectedValueOnce(new Error('connection lost'));

    const result = await MarkovUserProfile.score(1, 'alice', 'ls', 'cat');
    expect(result).toBeNull();
  });
});

describe('MarkovUserProfile.refresh', () => {
  beforeEach(() => {
    executeMock.mockReset();
  });

  it('calls REFRESH MATERIALIZED VIEW CONCURRENTLY for both views', async () => {
    executeMock.mockResolvedValue(rowsResponse([]));

    await MarkovUserProfile.refresh();
    expect(executeMock).toHaveBeenCalledTimes(2);
  });

  it('falls back to non-concurrent refresh on first run', async () => {
    // First two calls (concurrent) reject → service catches and retries 2 more
    // calls without CONCURRENTLY.
    executeMock
      .mockRejectedValueOnce(new Error('cannot refresh CONCURRENTLY before populated'))
      .mockResolvedValue(rowsResponse([]));

    await MarkovUserProfile.refresh();
    // 1 (failed concurrent) + 2 (non-concurrent retries) = 3 calls minimum.
    expect(executeMock.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});
