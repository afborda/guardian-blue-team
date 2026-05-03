import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ScoreCalculator } from '../src/pipeline/score-calculator.js';

vi.mock('../src/database/connection.js', () => ({
  db: {
    select: vi.fn(() => ({
      from: vi.fn(() => ({
        where: vi.fn(() => Promise.resolve([])),
      })),
    })),
    insert: vi.fn(() => ({ values: vi.fn(() => Promise.resolve()) })),
  },
  dbDate: (d: Date) => d,
  dbNow: () => new Date(),
}));

vi.mock('../src/database/schema.js', () => ({
  serverMetrics: {},
  serverScores: {},
  securityEvents: {},
  socIncidents: {},
  cveAlerts: {},
  vulnerabilities: {},
}));

vi.mock('drizzle-orm', () => ({
  eq: vi.fn(),
  gte: vi.fn(),
  lte: vi.fn(),
  and: vi.fn(),
  sql: vi.fn(),
  count: vi.fn(),
}));

describe('ScoreCalculator', () => {
  beforeEach(() => vi.clearAllMocks());

  it('returns neutral scores when no metrics exist', async () => {
    const result = await ScoreCalculator.computeForServer(1, new Date(), new Date());
    expect(result.healthScore).toBe(50);
    expect(result.qualityScore).toBe(50);
    expect(result.wasteScore).toBe(80);
    expect(result.availabilityScore).toBe(30);
    expect(result.overallScore).toBeGreaterThan(0);
  });

  it('computes correct overall weighted score', async () => {
    const result = await ScoreCalculator.computeForServer(1, new Date(), new Date());
    const expected = Math.round(
      result.healthScore * 0.20 +
      result.securityScore * 0.25 +
      result.qualityScore * 0.15 +
      result.wasteScore * 0.10 +
      result.vulnerabilityScore * 0.20 +
      result.availabilityScore * 0.10
    );
    expect(result.overallScore).toBe(expected);
  });

  it('all scores are between 0 and 100', async () => {
    const result = await ScoreCalculator.computeForServer(1, new Date(), new Date());
    const scores = [
      result.healthScore,
      result.securityScore,
      result.qualityScore,
      result.wasteScore,
      result.vulnerabilityScore,
      result.availabilityScore,
      result.overallScore,
    ];
    for (const s of scores) {
      expect(s).toBeGreaterThanOrEqual(0);
      expect(s).toBeLessThanOrEqual(100);
    }
  });
});
