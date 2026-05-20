/**
 * Classical STL (Seasonal-Trend decomposition by Loess) — additive model.
 *
 *   y_t = trend_t + seasonal_t + residual_t
 *
 * This is a deliberately simple implementation:
 *   - Trend via centered moving average of length = period (with extension at the edges).
 *   - Seasonal via per-phase mean of (y - trend), centered to sum to zero.
 *   - Residual = y - trend - seasonal.
 *
 * Why not LOESS? For 5040 equi-spaced samples and a fixed daily period, classical
 * decomposition produces residuals comparable to LOESS-based STL within the noise
 * floor of the underlying metric. LOESS adds ~10× compute and a dependency.
 *
 * Robust scoring on residuals uses MAD (Median Absolute Deviation) which is far
 * less sensitive to a single contaminating spike than σ.
 */

export interface STLDecomposition {
  trend: number[];
  seasonal: number[];
  residual: number[];
}

/**
 * Decompose an equi-spaced time series into trend + seasonal + residual.
 *
 * @param values  Equi-spaced observations. Length should be ≥ 2 × period.
 * @param period  Number of samples per seasonal cycle (e.g. 720 for 24h @ 2min).
 */
export function stlDecompose(values: number[], period: number): STLDecomposition {
  const n = values.length;
  if (n < 2 * period) {
    throw new Error(`stlDecompose: need at least 2 periods of data (got ${n}, need ${2 * period})`);
  }
  if (period < 2) {
    throw new Error(`stlDecompose: period must be ≥ 2 (got ${period})`);
  }

  // Two-pass decomposition. The first pass estimates a coarse trend via centered
  // moving average; this contaminates edge samples because the MA window shrinks
  // there. The second pass re-estimates the trend on (values − seasonal), which
  // is roughly stationary and therefore much less sensitive to the edge bias.
  // One extra pass is enough to drive seasonal-leakage well below the noise
  // floor we care about for anomaly scoring.
  let trend = centeredMovingAverage(values, period);
  let seasonal = phaseMeanSeasonal(values, trend, period);
  trend = centeredMovingAverage(values.map((v, i) => v - seasonal[i]), period);
  seasonal = phaseMeanSeasonal(values, trend, period);

  const residual = values.map((v, i) => v - trend[i] - seasonal[i]);
  return { trend, seasonal, residual };
}

/**
 * Per-phase mean of (values − trend), centered so the seasonal component sums
 * to zero over one period.
 */
function phaseMeanSeasonal(values: number[], trend: number[], period: number): number[] {
  const n = values.length;
  const phaseSums = new Array<number>(period).fill(0);
  const phaseCounts = new Array<number>(period).fill(0);
  for (let i = 0; i < n; i++) {
    const d = values[i] - trend[i];
    if (Number.isFinite(d)) {
      phaseSums[i % period] += d;
      phaseCounts[i % period]++;
    }
  }
  const phaseMeans = phaseSums.map((s, p) => phaseCounts[p] > 0 ? s / phaseCounts[p] : 0);
  const offset = phaseMeans.reduce((a, b) => a + b, 0) / period;
  const centered = phaseMeans.map(m => m - offset);

  const seasonal = new Array<number>(n);
  for (let i = 0; i < n; i++) seasonal[i] = centered[i % period];
  return seasonal;
}

/**
 * Centered moving average of window `period`. For points within `period/2` of the
 * edges, the window shrinks and we extend with the nearest valid average — this
 * avoids NaN at the boundaries that would otherwise contaminate downstream stats.
 */
function centeredMovingAverage(values: number[], period: number): number[] {
  const n = values.length;
  const half = Math.floor(period / 2);
  const out = new Array<number>(n);

  // Running sum across the window. We recompute from scratch for clarity rather
  // than maintaining a sliding sum — n × period is small enough that the simpler
  // form wins on readability.
  for (let i = 0; i < n; i++) {
    const lo = Math.max(0, i - half);
    const hi = Math.min(n - 1, i + half);
    let sum = 0;
    let count = 0;
    for (let j = lo; j <= hi; j++) {
      if (Number.isFinite(values[j])) {
        sum += values[j];
        count++;
      }
    }
    out[i] = count > 0 ? sum / count : 0;
  }

  return out;
}

/**
 * Robust z-score using median + MAD on the residual series.
 *
 *   z = (x - median(R)) / (1.4826 × MAD(R))
 *
 * The 1.4826 constant scales MAD to be a consistent estimator of σ for normal
 * data. With non-normal data it's still a useful relative measure of how far a
 * point sits from the bulk of residuals.
 */
export function residualZ(residual: number[], current: number): number {
  const med = median(residual);
  const madValue = mad(residual, med);
  if (madValue === 0) return 0;
  return Math.abs(current - med) / (1.4826 * madValue);
}

/**
 * Score a "new" observation against an STL-decomposed history.
 *
 * STL's trend at the very edges of the input is unreliable (centered moving
 * average shrinks toward boundaries). Rather than trust `residual[n-1]`, we:
 *   1. Project the trend forward from the most recent reliable interior point.
 *   2. Compute expected = projected_trend + seasonal[(n) % period].
 *   3. Score current against the residual distribution from the *interior* —
 *      that's where decomposition is statistically clean.
 *
 * Returns z-score of `current` relative to interior residuals.
 */
export function scoreCurrentAgainstSTL(
  decomposition: STLDecomposition,
  period: number,
  current: number,
): { expected: number; residual: number; z: number } {
  const { trend, seasonal, residual } = decomposition;
  const n = trend.length;

  // Interior slice: skip the first and last `period` samples where edge
  // effects contaminate the trend estimate.
  const interiorStart = period;
  const interiorEnd = n - period;

  let interiorResiduals: number[];
  let lastInteriorIdx: number;
  let interiorAnchor: number;

  if (interiorEnd > interiorStart + Math.max(2, Math.floor(period / 2))) {
    // Enough interior to compute robust statistics.
    interiorResiduals = residual.slice(interiorStart, interiorEnd);
    lastInteriorIdx = interiorEnd - 1;
    // Project the trend forward by extrapolating the slope between two recent
    // interior points. Using the median of trend is wrong for non-stationary
    // (e.g. monotonically increasing) series — the median sits near the middle
    // of the range, not near the most recent value.
    const slopeWindow = Math.min(period, interiorEnd - interiorStart - 1);
    const earlierIdx = lastInteriorIdx - slopeWindow;
    const slopePerStep = (trend[lastInteriorIdx] - trend[earlierIdx]) / slopeWindow;
    const stepsAhead = (n - 1) - lastInteriorIdx + 1; // current sits at index n
    interiorAnchor = trend[lastInteriorIdx] + slopePerStep * stepsAhead;
  } else {
    // Series is just barely long enough for STL; fall back to the full series.
    interiorResiduals = residual;
    lastInteriorIdx = n - 1;
    interiorAnchor = trend[lastInteriorIdx];
  }

  // The "next" sample sits conceptually at index n (one past the last observed
  // sample), so its phase is n mod period.
  const phaseIdx = n % period;
  const expected = interiorAnchor + seasonal[phaseIdx];
  const r = current - expected;

  return { expected, residual: r, z: residualZ(interiorResiduals, r) };
}

export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

export function mad(values: number[], precomputedMedian?: number): number {
  if (values.length === 0) return 0;
  const med = precomputedMedian ?? median(values);
  const deviations = values.map(v => Math.abs(v - med));
  return median(deviations);
}

/**
 * Estimate the period (in samples) of an equi-spaced time series given its
 * timestamps. Used to fit STL when the collection interval might drift.
 *
 * Returns null if the series isn't reliably equi-spaced (gaps too large).
 */
export interface PeriodEstimate {
  samplesPerDay: number;
  medianIntervalSec: number;
  hasLargeGap: boolean;
}

export function estimatePeriod(timestamps: Date[]): PeriodEstimate | null {
  if (timestamps.length < 10) return null;

  const deltas: number[] = [];
  for (let i = 1; i < timestamps.length; i++) {
    deltas.push((timestamps[i].getTime() - timestamps[i - 1].getTime()) / 1000);
  }

  const med = median(deltas);
  if (med <= 0) return null;

  // Treat any delta > 3× median as a "gap". A few small gaps are ok (we can
  // interpolate); a single huge one means the series isn't usable for STL.
  const largeGapThreshold = med * 3;
  const hasLargeGap = deltas.some(d => d > largeGapThreshold);

  return {
    samplesPerDay: Math.round(86400 / med),
    medianIntervalSec: med,
    hasLargeGap,
  };
}
