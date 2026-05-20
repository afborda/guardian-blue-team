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
  positiveLabel: number;          // which output index corresponds to "DGA"
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
  private static initAttempted = false;
  private static initOk = false;

  static async init(): Promise<void> {
    if (this.initAttempted) return;
    this.initAttempted = true;

    const modelPath = resolve(process.env.DGA_MODEL_PATH ?? 'models/dga.onnx');
    const metaPath = modelPath.replace(/\.onnx$/, '.meta.json');

    try {
      const metaRaw = await readFile(metaPath, 'utf8');
      const meta = JSON.parse(metaRaw) as ModelMeta;
      this.bigramTable = new Float32Array(meta.bigramTable);
      this.threshold = meta.threshold;

      // Dynamic import keeps onnxruntime-node optional. If the package isn't
      // installed, we fall back to entropy without crashing the worker.
      // @ts-ignore — onnxruntime-node is an optional peer dep
      const ort = await import('onnxruntime-node').catch(() => null);
      if (!ort) {
        logger.warn('onnxruntime-node not installed — DGA detection falls back to entropy');
        return;
      }

      // The runtime exposes `InferenceSession.create(path)` which returns a
      // session compatible with our `OnnxSession` shape.
      const session = await (ort as any).InferenceSession.create(modelPath);
      this.session = session as OnnxSession;
      this.initOk = true;
      logger.info({ modelPath, threshold: this.threshold, features: meta.featureOrder.length },
        'DGA classifier loaded');
    } catch (err) {
      logger.warn({ err: (err as Error).message, modelPath },
        'DGA model unavailable — falling back to entropy-based detection');
    }
  }

  static async classify(domain: string): Promise<DgaResult> {
    if (!this.initAttempted) await this.init();

    if (!this.initOk || !this.session) {
      return this.fallback(domain);
    }

    try {
      const features = extractFeatures(domain, this.bigramTable);
      const vec = featuresToVector(features);

      // skl2onnx exports a 2D input tensor (batch × features). Build a 1×N
      // tensor for a single domain. We use the runtime's Tensor constructor
      // via the loaded module — keep this isolated so a runtime-shape change
      // is easy to fix.
      // @ts-ignore — onnxruntime-node is an optional peer dep
      const ort = await import('onnxruntime-node');
      const inputName = this.session.inputNames[0];
      const tensor = new (ort as any).Tensor('float32', vec, [1, vec.length]);
      const out = await this.session.run({ [inputName]: tensor });

      // sklearn's LogisticRegression with skl2onnx outputs two heads:
      // `label` (predicted class) and `probabilities` (per-class probs).
      // We want the probability of the positive class.
      const probsKey = this.session.outputNames.find(n => n.toLowerCase().includes('prob'))
        ?? this.session.outputNames[1];
      const probs = out[probsKey]?.data;
      if (!probs || !(probs instanceof Float32Array)) {
        return this.fallback(domain);
      }
      // Two-class output: [P(legit), P(dga)] — positive label index is
      // typically 1, but the meta file is authoritative.
      const score = probs.length >= 2 ? probs[1] : probs[0];
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
