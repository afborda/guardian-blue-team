import { describe, it, expect } from 'vitest';
import { extractFeatures, featuresToVector, FEATURE_ORDER } from '../src/intelligence/dga-features.js';
import { DgaClassifier } from '../src/intelligence/dga-classifier.js';

// A reference bigram table — uniform log-prob across 27×27 cells. Real
// training builds this from English domains, but for unit tests we just
// need *something* of the right shape so feature extraction doesn't crash.
const uniformBigram = (() => {
  const table = new Float32Array(27 * 27);
  const p = Math.log(1 / 27);
  table.fill(p);
  return table;
})();

describe('dga-features', () => {
  describe('extractFeatures', () => {
    it('matches FEATURE_ORDER vector length', () => {
      const f = extractFeatures('example.com', uniformBigram);
      const vec = featuresToVector(f);
      expect(vec.length).toBe(FEATURE_ORDER.length);
    });

    it('counts vowels correctly', () => {
      // "google" has 4 vowels (oo, e... wait: g-o-o-g-l-e → 3 vowels). "com" has 1.
      // stripped = "googlecom" (9 chars), vowels = o,o,e,o = 4
      const f = extractFeatures('google.com', uniformBigram);
      expect(f.vowelRatio).toBeCloseTo(4 / 9, 4);
    });

    it('detects long consonant runs', () => {
      // "rhythm.com" stripped = "rhythmcom". Consonant runs: r,h (2), then
      // 'y' (vowel by our definition) breaks, then t,h,m,c (4) — counting
      // 'c' from the next label since dots are stripped before scanning.
      const f = extractFeatures('rhythm.com', uniformBigram);
      expect(f.maxConsonantRun).toBe(4);
    });

    it('counts digits and digit runs', () => {
      const f = extractFeatures('host123abc456.example.com', uniformBigram);
      expect(f.digitRatio).toBeGreaterThan(0);
      expect(f.maxDigitRun).toBe(3); // 123 or 456
    });

    it('picks the longest non-TLD label as SLD', () => {
      // Labels: "a", "longerlabel", "com" → pick "longerlabel" (TLD excluded)
      const f = extractFeatures('a.longerlabel.com', uniformBigram);
      expect(f.sldLength).toBe(11);
    });

    it('handles single-label input', () => {
      const f = extractFeatures('localhost', uniformBigram);
      expect(f.labelCount).toBe(1);
      expect(f.sldLength).toBe('localhost'.length);
    });

    it('lowercases input', () => {
      const upper = extractFeatures('GOOGLE.COM', uniformBigram);
      const lower = extractFeatures('google.com', uniformBigram);
      expect(upper.entropy).toBeCloseTo(lower.entropy, 6);
      expect(upper.vowelRatio).toBeCloseTo(lower.vowelRatio, 6);
    });

    it('strips trailing dots', () => {
      const a = extractFeatures('example.com.', uniformBigram);
      const b = extractFeatures('example.com', uniformBigram);
      expect(a.length).toBe(b.length);
      expect(a.labelCount).toBe(b.labelCount);
    });

    it('produces higher entropy for random-looking strings', () => {
      const random = extractFeatures('xkjqpvwzbnmlhgfd.com', uniformBigram);
      const normal = extractFeatures('aaaaaaaaaaaaaaaa.com', uniformBigram);
      expect(random.entropy).toBeGreaterThan(normal.entropy);
    });

    it('produces vector in canonical order', () => {
      const f = extractFeatures('example.com', uniformBigram);
      const vec = featuresToVector(f);
      // Sanity: first feature is length, last is sldLength
      expect(vec[0]).toBe(f.length);
      expect(vec[vec.length - 1]).toBe(f.sldLength);
    });
  });

  describe('charClasses', () => {
    it('counts only present classes', () => {
      const onlyAlpha = extractFeatures('example.com', uniformBigram);
      expect(onlyAlpha.charClasses).toBe(1);

      const alphaDigit = extractFeatures('host123.com', uniformBigram);
      expect(alphaDigit.charClasses).toBe(2);

      const alphaDigitHyphen = extractFeatures('my-host-1.com', uniformBigram);
      expect(alphaDigitHyphen.charClasses).toBe(3);
    });
  });
});

describe('DgaClassifier', () => {
  describe('fallback (no ONNX model loaded)', () => {
    it('does not flag short normal domains', async () => {
      const r = await DgaClassifier.classify('google.com');
      expect(r.isDga).toBe(false);
      expect(r.source).toBe('fallback');
    });

    it('does not flag short randomish-looking domains under length threshold', async () => {
      // Length filter (20) keeps fallback conservative — only flag long+random.
      const r = await DgaClassifier.classify('xkjqp.com');
      expect(r.isDga).toBe(false);
    });

    it('flags long high-entropy domains', async () => {
      // 26-char random-looking SLD; entropy > 3.5 expected.
      const r = await DgaClassifier.classify('xkjqpvwzbnmlhgfdrtystpqyz.com');
      expect(r.isDga).toBe(true);
      expect(r.score).toBeGreaterThan(0.5);
    });

    it('returns score in [0,1]', async () => {
      const r = await DgaClassifier.classify('asdfghjklqwertyuiopzx.net');
      expect(r.score).toBeGreaterThanOrEqual(0);
      expect(r.score).toBeLessThanOrEqual(1);
    });

    it('reports source=fallback when model is unavailable', async () => {
      const r = await DgaClassifier.classify('example.com');
      expect(r.source).toBe('fallback');
    });
  });
});
