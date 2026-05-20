/**
 * DGA (Domain Generation Algorithm) classifier — ONNX inference wrapper.
 *
 * Lifecycle:
 *   1. `init()` called once at worker startup. Loads ONNX model + bigram table.
 *   2. `classify(domain)` returns a probability score and boolean verdict.
 *   3. If init fails (model missing, runtime not installed), classify() falls
 *      back to a pure-entropy heuristic so detection never breaks.
 *
 * The model file path is resolved from env DGA_MODEL_PATH (default
 * `models/dga.onnx`). The bigram table comes from `models/dga.meta.json`.
 *
 * Training: run `python scripts/train_dga.py` — see that script for the
 * dataset and hyperparameters. The TS feature extractor in dga-features.ts
 * MUST match the Python feature extraction byte-for-byte; if you change one,
 * change the other and retrain.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { extractFeatures, featuresToVector } from './dga-features.js';
import { logger } from '../utils/logger.js';

interface ModelMeta {
  bigramTable: number[];          // flat 27×27 log-probability table
  threshold: number;              // probability above which we flag DGA
  featureOrder: string[];         // for cross-checking with TS feature names
  trainedAt: string;              // ISO timestamp of training run
  positiveLabel: number;          // which output index in `probabilities` corresponds to "DGA"
}

// Optional onnxruntime-node module shape — kept narrow so the dynamic import
// path doesn't depend on the package being installed at type-check time.
interface OnnxRuntimeModule {
  InferenceSession: { create(path: string): Promise<OnnxSession> };
  Tensor: new (type: string, data: Float32Array, dims: number[]) => unknown;
}

interface OnnxSession {
  // Minimal shape we need from onnxruntime-node — full type lives in
  // `onnxruntime-common` which we'd rather not import unconditionally.
  run(feeds: Record<string, unknown>): Promise<Record<string, { data: Float32Array | BigInt64Array }>>;
  inputNames: string[];
  outputNames: string[];
}

export interface DgaResult {
  isDga: boolean;
  score: number;
  // 'model' = ONNX classified the domain. 'fallback' = heuristic (model
  // unavailable). The detector log includes this so we know which signal
  // triggered.
  source: 'model' | 'fallback';
}

export class DgaClassifier {
  private static session: OnnxSession | null = null;
  private static bigramTable: Float32Array = new Float32Array(0);
  private static threshold = 0.5;
  private static positiveLabel = 1;
  private static ortModule: OnnxRuntimeModule | null = null;
  // Track init via a single shared promise so concurrent first-call classify()
  // requests await the same load instead of all racing past the in-progress
  // init and falling back to entropy.
  private static initPromise: Promise<void> | null = null;
  private static initOk = false;

  static init(): Promise<void> {
    if (this.initPromise) return this.initPromise;
    this.initPromise = this.doInit();
    return this.initPromise;
  }

  private static async doInit(): Promise<void> {
    const modelPath = resolve(process.env.DGA_MODEL_PATH ?? 'models/dga.onnx');
    const metaPath = modelPath.replace(/\.onnx$/, '.meta.json');

    try {
      const metaRaw = await readFile(metaPath, 'utf8');
      const meta = JSON.parse(metaRaw) as ModelMeta;
      this.bigramTable = new Float32Array(meta.bigramTable);
      this.threshold = meta.threshold;
      this.positiveLabel = meta.positiveLabel ?? 1;

      // Dynamic import keeps onnxruntime-node optional. If the package isn't
      // installed, we fall back to entropy without crashing the worker.
      // @ts-ignore — onnxruntime-node is an optional peer dep
      const ort = await import('onnxruntime-node').catch(() => null) as OnnxRuntimeModule | null;
      if (!ort) {
        logger.warn('onnxruntime-node not installed — DGA detection falls back to entropy');
        return;
      }

      this.ortModule = ort;
      this.session = await ort.InferenceSession.create(modelPath);
      this.initOk = true;
      logger.info({ modelPath, threshold: this.threshold, positiveLabel: this.positiveLabel, features: meta.featureOrder.length },
        'DGA classifier loaded');
    } catch (err) {
      logger.warn({ err: (err as Error).message, modelPath },
        'DGA model unavailable — falling back to entropy-based detection');
    }
  }

  static async classify(domain: string): Promise<DgaResult> {
    await this.init();

    if (!this.initOk || !this.session || !this.ortModule) {
      return this.fallback(domain);
    }

    try {
      const features = extractFeatures(domain, this.bigramTable);
      const vec = featuresToVector(features);

      const inputName = this.session.inputNames[0];
      const tensor = new this.ortModule.Tensor('float32', vec, [1, vec.length]);
      const out = await this.session.run({ [inputName]: tensor });

      // sklearn's LogisticRegression with skl2onnx outputs two heads:
      // `label` (predicted class) and `probabilities` (per-class probs).
      // We want the probability of the positive class — index from meta.
      const probsKey = this.session.outputNames.find(n => n.toLowerCase().includes('prob'))
        ?? this.session.outputNames[1];
      const probs = out[probsKey]?.data;
      if (!probs || !(probs instanceof Float32Array)) {
        return this.fallback(domain);
      }
      const idx = this.positiveLabel < probs.length ? this.positiveLabel : probs.length - 1;
      const score = probs[idx];
      return { isDga: score >= this.threshold, score, source: 'model' };
    } catch (err) {
      logger.debug({ err: (err as Error).message, domain }, 'DGA inference failed, falling back');
      return this.fallback(domain);
    }
  }

  /**
   * Pure-entropy fallback. Same logic as the original detector rule: high
   * Shannon entropy + minimum length = suspicious. Less accurate than the
   * model, but always available.
   */
  private static fallback(domain: string): DgaResult {
    const stripped = domain.toLowerCase().replace(/\.+$/, '').replace(/\./g, '');
    if (stripped.length < 20) return { isDga: false, score: 0, source: 'fallback' };

    const freq = new Map<string, number>();
    for (const ch of stripped) freq.set(ch, (freq.get(ch) ?? 0) + 1);
    let entropy = 0;
    for (const c of freq.values()) {
      const p = c / stripped.length;
      entropy -= p * Math.log2(p);
    }
    // Map entropy to a [0,1] score so the API shape matches model output.
    // 3.5 was the old threshold; map 3.5 → 0.5, 4.5 → 0.9.
    const score = Math.max(0, Math.min(1, (entropy - 2.5) / 2));
    return { isDga: entropy > 3.5, score, source: 'fallback' };
  }
}
