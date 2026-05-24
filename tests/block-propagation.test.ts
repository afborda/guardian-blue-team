import { describe, expect, it } from 'vitest';
import { BACKOFF_MINUTES, backoffDelayMs } from '../src/workers/block-propagation.worker.js';

describe('BlockPropagationWorker backoff', () => {
  it('uses the documented 1m / 5m / 15m / 1h / 6h ladder', () => {
    expect(BACKOFF_MINUTES).toEqual([1, 5, 15, 60, 360]);
  });

  it('first failure → 1 minute', () => {
    expect(backoffDelayMs(1)).toBe(60_000);
  });

  it('second failure → 5 minutes', () => {
    expect(backoffDelayMs(2)).toBe(5 * 60_000);
  });

  it('fifth failure → 6 hours (last rung)', () => {
    expect(backoffDelayMs(5)).toBe(360 * 60_000);
  });

  it('clamps beyond the last rung to 6 hours', () => {
    expect(backoffDelayMs(99)).toBe(360 * 60_000);
  });

  it('handles attempts < 1 by returning the first rung (defensive)', () => {
    expect(backoffDelayMs(0)).toBe(60_000);
  });

  it('total wait until gave_up is the sum of all rungs', () => {
    const totalMin = BACKOFF_MINUTES.reduce((a, b) => a + b, 0);
    // 1 + 5 + 15 + 60 + 360 = 441 minutes ≈ 7h21m of patience before alerting
    expect(totalMin).toBe(441);
  });
});
