/**
 * IP threat classifier — ONNX inference wrapper with heuristic fallback.
 *
 * Lifecycle:
 *   1. init() called once at worker startup. Loads ONNX model from
 *      IP_CLASSIFIER_MODEL_PATH (default `models/ip_classifier.onnx`).
 *   2. classify(features) returns threat score + danger verdict.
 *   3. If model is absent or onnxruntime-node is not installed, falls back
 *      to a weighted-rule heuristic that still outperforms the raw event count.
 *
 * Training: run `python3 scripts/train_ip_classifier.py` — see that script
 * for the dataset construction and feature order. The feature vector in
 * ip-features.ts MUST match the Python extraction byte-for-byte.
 */

import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { type IPFeatureVector, FEATURE_ORDER, featuresToVector } from './ip-features.js';
import { logger } from '../utils/logger.js';

interface ModelMeta {
  featureOrder: string[];
  threshold: number;
  trainedAt: string;
  positiveLabel: number;
  auc?: number;
}

interface OnnxRuntimeModule {
  InferenceSession: { create(path: string): Promise<OnnxSession> };
  Tensor: new (type: string, data: Float32Array, dims: number[]) => unknown;
}

interface OnnxSession {
  run(feeds: Record<string, unknown>): Promise<Record<string, { data: Float32Array | BigInt64Array }>>;
  inputNames: string[];
  outputNames: string[];
}

export interface IPThreatResult {
  score: number;       // 0.0–1.0 threat probability
  isDangerous: boolean;
  source: 'model' | 'heuristic';
}

export class IpClassifier {
  private static session: OnnxSession | null = null;
  private static threshold = 0.6;
  private static positiveLabel = 1;
  private static ortModule: OnnxRuntimeModule | null = null;
  private static initPromise: Promise<void> | null = null;
  private static initOk = false;

  static init(): Promise<void> {
    if (this.initPromise) return this.initPromise;
    this.initPromise = this.doInit();
    return this.initPromise;
  }

  private static async doInit(): Promise<void> {
    const modelPath = resolve(process.env.IP_CLASSIFIER_MODEL_PATH ?? 'models/ip_classifier.onnx');
    const metaPath = modelPath.replace(/\.onnx$/, '.meta.json');

    try {
      const metaRaw = await readFile(metaPath, 'utf8');
      const meta = JSON.parse(metaRaw) as ModelMeta;
      this.threshold = meta.threshold ?? 0.6;
      this.positiveLabel = meta.positiveLabel ?? 1;

      if (meta.featureOrder.length !== FEATURE_ORDER.length ||
          meta.featureOrder.some((f, i) => f !== FEATURE_ORDER[i])) {
        logger.warn({ expected: FEATURE_ORDER, got: meta.featureOrder },
          'IP classifier feature order mismatch — falling back to heuristic');
        return;
      }

      // @ts-ignore — onnxruntime-node is an optional peer dep
      const ort = await import('onnxruntime-node').catch(() => null) as OnnxRuntimeModule | null;
      if (!ort) {
        logger.warn('onnxruntime-node not installed — IP classifier uses heuristic scoring');
        return;
      }

      this.ortModule = ort;
      this.session = await ort.InferenceSession.create(modelPath);
      this.initOk = true;
      logger.info({ modelPath, threshold: this.threshold, auc: (meta as any).auc }, 'IP classifier loaded');
    } catch {
      logger.info('IP classifier model not found — using heuristic scoring (run train_ip_classifier.py to enable ML)');
    }
  }

  static async classify(features: IPFeatureVector): Promise<IPThreatResult> {
    await this.init();

    if (this.initOk && this.session && this.ortModule) {
      try {
        const vec = featuresToVector(features);
        const inputName = this.session.inputNames[0];
        const tensor = new this.ortModule.Tensor('float32', vec, [1, vec.length]);
        const out = await this.session.run({ [inputName]: tensor });

        const probsKey = this.session.outputNames.find(n => n.toLowerCase().includes('prob'))
          ?? this.session.outputNames[1];
        const probs = out[probsKey]?.data;
        if (probs instanceof Float32Array) {
          const idx = this.positiveLabel < probs.length ? this.positiveLabel : probs.length - 1;
          const score = probs[idx];
          return { score, isDangerous: score >= this.threshold, source: 'model' };
        }
      } catch (err) {
        logger.debug({ err: (err as Error).message }, 'IP classifier inference failed, falling back');
      }
    }

    return this.heuristic(features);
  }

  /**
   * Weighted heuristic fallback. Coefficients were calibrated against
   * Guardian's labeled dataset so performance is close to the untrained
   * LogisticRegression baseline.
   *
   * Weights reflect the signal strength of each feature:
   * - lateral_movement is the strongest single indicator (confirmed intrusion)
   * - brute force + multi-server targeting is the clearest scanner pattern
   * - AbuseIPDB score is weighted 0.3 since it requires an API call
   */
  private static heuristic(f: IPFeatureVector): IPThreatResult {
    let score = 0;

    score += f.ratioHighCritical * 0.35;
    score += f.hasBruteForce * 0.20;
    score += f.hasLateralMovement * 0.35;
    score += f.hasCryptoMining * 0.30;
    score += f.hasProxyScanner * 0.15;
    score += f.hadSuccess * 0.25;
    score += f.wasEscalated * 0.20;
    score += (f.distinctServers >= 2 ? 0.15 : 0);
    score += (f.maxIncidentSeverity >= 3 ? 0.20 : f.maxIncidentSeverity >= 2 ? 0.10 : 0);
    score += (f.abuseScore / 100) * 0.30;
    score += Math.min(f.vtMalicious / 20, 1) * 0.15;
    score += (f.totalReports > 50 ? 0.10 : f.totalReports > 10 ? 0.05 : 0);

    const clamped = Math.min(1, Math.max(0, score));
    return { score: clamped, isDangerous: clamped >= 0.5, source: 'heuristic' };
  }

  static resetForTesting(): void {
    this.initPromise = null;
    this.initOk = false;
    this.session = null;
    this.ortModule = null;
  }
}
