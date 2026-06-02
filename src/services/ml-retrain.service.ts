import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { logger } from '../utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = resolve(__dirname, '../../scripts');
const PYTHON = process.env.ML_PYTHON ?? 'python3';

export type RetrainTarget = 'dga' | 'ip';

export interface RetrainJob {
  target: RetrainTarget;
  status: 'idle' | 'running' | 'success' | 'error';
  startedAt: Date | null;
  finishedAt: Date | null;
  durationMs: number | null;
  log: string[];
  error: string | null;
}

const jobs: Record<RetrainTarget, RetrainJob> = {
  dga: { target: 'dga', status: 'idle', startedAt: null, finishedAt: null, durationMs: null, log: [], error: null },
  ip:  { target: 'ip',  status: 'idle', startedAt: null, finishedAt: null, durationMs: null, log: [], error: null },
};

const SCRIPT: Record<RetrainTarget, string> = {
  dga: 'train_dga.py',
  ip:  'train_ip_classifier.py',
};

export class MLRetrainService {
  static getJob(target: RetrainTarget): RetrainJob {
    return jobs[target];
  }

  static getAllJobs(): Record<RetrainTarget, RetrainJob> {
    return jobs;
  }

  static start(target: RetrainTarget): { ok: boolean; reason?: string } {
    const job = jobs[target];
    if (job.status === 'running') return { ok: false, reason: 'already_running' };

    const scriptPath = resolve(SCRIPTS_DIR, SCRIPT[target]);
    if (!existsSync(scriptPath)) {
      return { ok: false, reason: `script_not_found: ${scriptPath}` };
    }

    job.status = 'running';
    job.startedAt = new Date();
    job.finishedAt = null;
    job.durationMs = null;
    job.log = [];
    job.error = null;

    const env = { ...process.env, PYTHONUNBUFFERED: '1' };
    const child = spawn(PYTHON, [scriptPath], { cwd: resolve(__dirname, '../..'), env });

    const append = (line: string) => {
      job.log.push(line);
      // Keep last 200 lines to avoid unbounded memory
      if (job.log.length > 200) job.log.shift();
    };

    child.stdout.on('data', (d: Buffer) =>
      String(d).split('\n').filter(Boolean).forEach(append),
    );
    child.stderr.on('data', (d: Buffer) =>
      String(d).split('\n').filter(Boolean).forEach(l => append(`[stderr] ${l}`)),
    );

    child.on('close', (code) => {
      job.finishedAt = new Date();
      job.durationMs = job.finishedAt.getTime() - job.startedAt!.getTime();
      if (code === 0) {
        job.status = 'success';
        logger.info({ target, durationMs: job.durationMs }, 'ML retrain completed');
      } else {
        job.status = 'error';
        job.error = `exit code ${code}`;
        logger.warn({ target, code }, 'ML retrain failed');
      }
    });

    child.on('error', (err) => {
      job.status = 'error';
      job.error = err.message;
      job.finishedAt = new Date();
      job.durationMs = job.finishedAt.getTime() - job.startedAt!.getTime();
      logger.error({ target, err }, 'ML retrain spawn error');
    });

    logger.info({ target, script: scriptPath, python: PYTHON }, 'ML retrain started');
    return { ok: true };
  }
}
