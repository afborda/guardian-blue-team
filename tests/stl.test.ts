import { describe, it, expect } from 'vitest';
import {
  stlDecompose,
  scoreCurrentAgainstSTL,
  residualZ,
  median,
  mad,
  estimatePeriod,
} from '../src/intelligence/stl.js';

describe('stl', () => {
  describe('median', () => {
    it('handles odd length', () => {
      expect(median([3, 1, 2])).toBe(2);
    });
    it('handles even length', () => {
      expect(median([1, 2, 3, 4])).toBe(2.5);
    });
    it('returns 0 for empty', () => {
      expect(median([])).toBe(0);
    });
  });

  describe('mad', () => {
    it('is zero for constant series', () => {
      expect(mad([5, 5, 5, 5, 5])).toBe(0);
    });
    it('matches expected for symmetric series', () => {
      // values: 1,2,3,4,5 → median 3 → deviations 2,1,0,1,2 → MAD = median(0,1,1,2,2) = 1
      expect(mad([1, 2, 3, 4, 5])).toBe(1);
    });
    it('is robust to outliers', () => {
      // single huge outlier should not move MAD much
      const clean = [10, 11, 10, 12, 11, 9, 10];
      const contaminated = [10, 11, 10, 12, 11, 9, 1000];
      const cleanMad = mad(clean);
      const dirtyMad = mad(contaminated);
      // MAD changes only modestly (median absorbs the outlier)
      expect(Math.abs(dirtyMad - cleanMad)).toBeLessThan(2);
    });
  });

  describe('stlDecompose', () => {
    it('rejects series shorter than 2 periods', () => {
      expect(() => stlDecompose([1, 2, 3], 4)).toThrow();
    });

    it('rejects period < 2', () => {
      expect(() => stlDecompose(Array(20).fill(1), 1)).toThrow();
    });

    it('extracts a pure sinusoid as seasonal with near-zero residual in the interior', () => {
      const period = 24;
      const n = period * 5;
      const values = Array.from({ length: n }, (_, i) => Math.sin((2 * Math.PI * i) / period));

      const { trend, seasonal, residual } = stlDecompose(values, period);

      // Trend in the *interior* (away from edges) should be near zero — edges
      // are expected to drift due to centered-MA window shrinkage.
      const interiorTrend = trend.slice(period, n - period);
      const interiorTrendMag = Math.max(...interiorTrend.map(Math.abs));
      expect(interiorTrendMag).toBeLessThan(0.05);

      // Seasonal should track the sine within tight tolerance throughout.
      for (let i = 0; i < n; i++) {
        expect(Math.abs(seasonal[i] - values[i])).toBeLessThan(0.05);
      }

      // Interior residual should be tiny.
      const interiorResidual = residual.slice(period, n - period);
      const residualMag = Math.max(...interiorResidual.map(Math.abs));
      expect(residualMag).toBeLessThan(0.05);
    });

    it('separates linear trend from seasonal', () => {
      const period = 24;
      const n = period * 5;
      // y = i/10 (trend) + sin(2πi/period) (seasonal)
      const values = Array.from({ length: n }, (_, i) =>
        i / 10 + Math.sin((2 * Math.PI * i) / period)
      );

      const { trend, seasonal, residual } = stlDecompose(values, period);

      // Trend should be roughly linear and increasing.
      expect(trend[n - 1]).toBeGreaterThan(trend[0] + 5);

      // Seasonal should still capture the sinusoid (range close to 2.0)
      const seasonalRange = Math.max(...seasonal) - Math.min(...seasonal);
      expect(seasonalRange).toBeGreaterThan(1.5);
      expect(seasonalRange).toBeLessThan(2.5);

      // Residual mean should be near zero.
      const residualMean = residual.reduce((a, b) => a + b, 0) / n;
      expect(Math.abs(residualMean)).toBeLessThan(0.1);
    });

    it('seasonal component sums to zero (centered)', () => {
      const period = 24;
      const values = Array.from({ length: period * 4 }, (_, i) =>
        i + Math.sin((2 * Math.PI * i) / period) * 5
      );
      const { seasonal } = stlDecompose(values, period);
      // Sum over one full period should be near zero.
      const onePeriodSum = seasonal.slice(0, period).reduce((a, b) => a + b, 0);
      expect(Math.abs(onePeriodSum)).toBeLessThan(0.1);
    });
  });

  describe('residualZ', () => {
    it('returns 0 when MAD is 0 (constant residual)', () => {
      expect(residualZ([3, 3, 3, 3, 3], 99)).toBe(0);
    });

    it('flags large deviations from residual median', () => {
      // residuals around 0, current value far away
      const noise = [0.1, -0.2, 0.05, -0.1, 0.2, -0.05, 0.15, -0.15];
      const z = residualZ(noise, 5);
      expect(z).toBeGreaterThan(10);
    });

    it('does not flag values within the residual bulk', () => {
      const noise = [0.1, -0.2, 0.05, -0.1, 0.2, -0.05, 0.15, -0.15];
      const z = residualZ(noise, 0.1);
      expect(z).toBeLessThan(2);
    });

    it('is unaffected by a single contaminating outlier in the residual', () => {
      // MAD should ignore the outlier and still flag a *new* spike correctly.
      const cleanResiduals = [0, 0.1, -0.1, 0.05, -0.05, 0.2, -0.2];
      const contaminated = [...cleanResiduals, 100]; // one prior outlier
      const cleanZ = residualZ(cleanResiduals, 1);
      const dirtyZ = residualZ(contaminated, 1);
      // Should still be within an order of magnitude — σ-based would crash.
      expect(Math.abs(dirtyZ - cleanZ) / Math.max(cleanZ, 1)).toBeLessThan(1);
    });
  });

  describe('scoreCurrentAgainstSTL', () => {
    const period = 24;

    function buildSeasonalSeries(n: number, trend = 0, noiseAmplitude = 0): number[] {
      // Daily sinusoid + optional linear trend + small noise (deterministic, no randomness).
      return Array.from({ length: n }, (_, i) => {
        const seasonal = Math.sin((2 * Math.PI * i) / period) * 10;
        const t = (trend * i) / n;
        const noise = noiseAmplitude * Math.sin(i * 7.13); // pseudo-noise via incommensurate frequency
        return seasonal + t + noise;
      });
    }

    it('does not flag an in-pattern next value as anomalous', () => {
      const n = period * 6;
      const history = buildSeasonalSeries(n, 0, 0.3);
      const decomposition = stlDecompose(history, period);

      // The "next" value sitting at phase n (which equals phase 0) and on-pattern.
      const onPattern = Math.sin((2 * Math.PI * n) / period) * 10;
      const result = scoreCurrentAgainstSTL(decomposition, period, onPattern);

      expect(result.z).toBeLessThan(3);
    });

    it('flags an off-pattern spike as anomalous', () => {
      const n = period * 6;
      const history = buildSeasonalSeries(n, 0, 0.3);
      const decomposition = stlDecompose(history, period);

      // Inject a spike that is way off the seasonal pattern at phase n.
      const expectedSeasonal = Math.sin((2 * Math.PI * n) / period) * 10;
      const spike = expectedSeasonal + 50;
      const result = scoreCurrentAgainstSTL(decomposition, period, spike);

      expect(result.z).toBeGreaterThan(5);
    });

    it('captures gradual upward trend without false-flagging continuation', () => {
      const n = period * 6;
      // Strong linear trend on top of seasonal.
      const history = buildSeasonalSeries(n, 60, 0.3);
      const decomposition = stlDecompose(history, period);

      // The next sample, continuing the trend, should not alarm.
      const trendNext = (60 * n) / n; // trend value at i=n
      const seasonalNext = Math.sin((2 * Math.PI * n) / period) * 10;
      const onPattern = trendNext + seasonalNext;

      const result = scoreCurrentAgainstSTL(decomposition, period, onPattern);
      // Allow some slack since interior trend baseline lags the most recent values.
      expect(result.z).toBeLessThan(8);
    });
  });

  describe('estimatePeriod', () => {
    it('returns null for fewer than 10 samples', () => {
      const ts = Array.from({ length: 5 }, (_, i) => new Date(i * 60_000));
      expect(estimatePeriod(ts)).toBeNull();
    });

    it('infers samplesPerDay for 2-minute spacing', () => {
      const ts = Array.from({ length: 50 }, (_, i) => new Date(i * 120_000));
      const est = estimatePeriod(ts);
      expect(est).not.toBeNull();
      expect(est!.medianIntervalSec).toBe(120);
      expect(est!.samplesPerDay).toBe(720);
      expect(est!.hasLargeGap).toBe(false);
    });

    it('detects large gaps', () => {
      // mostly 60s spacing, one 10-minute gap
      const ts: Date[] = [];
      for (let i = 0; i < 30; i++) ts.push(new Date(i * 60_000));
      ts.push(new Date(30 * 60_000 + 600_000)); // 10-minute jump
      for (let i = 31; i < 40; i++) ts.push(new Date(ts[ts.length - 1].getTime() + 60_000));

      const est = estimatePeriod(ts);
      expect(est).not.toBeNull();
      expect(est!.hasLargeGap).toBe(true);
    });
  });
});
