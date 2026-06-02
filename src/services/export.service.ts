import { spawn } from 'node:child_process';
import { existsSync, unlinkSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { logger } from '../utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIR = resolve(__dirname, '../../scripts');
const PYTHON = process.env.ML_PYTHON ?? 'python3';
const EXPORT_SCRIPT = resolve(SCRIPTS_DIR, 'export_table.py');

export type ExportTable = 'events' | 'incidents' | 'blocked_ips' | 'server_metrics';
export type ExportFormat = 'csv' | 'parquet';

export interface ExportOptions {
  table: ExportTable;
  format: ExportFormat;
  days?: number;
  date?: string; // YYYY-MM-DD
}

export interface ExportResult {
  path: string;
  rows: number;
  sizeKb: number;
  durationMs: number;
}

const TABLE_LABELS: Record<ExportTable, string> = {
  events: 'events',
  incidents: 'incidents',
  blocked_ips: 'blocked_ips',
  server_metrics: 'server_metrics',
};

export class ExportService {
  static async generate(opts: ExportOptions): Promise<ExportResult> {
    if (!existsSync(EXPORT_SCRIPT)) {
      throw new Error(`Export script not found: ${EXPORT_SCRIPT}`);
    }

    const ts = Date.now();
    const ext = opts.format === 'parquet' ? 'parquet' : 'csv';
    const outPath = resolve(tmpdir(), `guardian-export-${TABLE_LABELS[opts.table]}-${ts}.${ext}`);

    const args = [EXPORT_SCRIPT, opts.table, opts.format, outPath];
    if (opts.days) args.push('--days', String(opts.days));
    if (opts.date) args.push('--date', opts.date);

    const dbUrl = process.env.DATABASE_URL ?? '';
    const env = { ...process.env, DATABASE_URL: dbUrl };

    logger.info({ table: opts.table, format: opts.format, outPath }, 'Export started');

    const startMs = Date.now();
    const logLines: string[] = [];

    await new Promise<void>((resolve, reject) => {
      const child = spawn(PYTHON, args, { env });

      child.stderr.on('data', (d: Buffer) =>
        String(d).split('\n').filter(Boolean).forEach(l => logLines.push(l)),
      );

      child.on('close', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`Export script exited with code ${code}\n${logLines.join('\n')}`));
      });

      child.on('error', reject);
    });

    const durationMs = Date.now() - startMs;

    if (!existsSync(outPath)) {
      throw new Error('Export script ran but output file not found');
    }

    const { statSync } = await import('node:fs');
    const stat = statSync(outPath);
    const sizeKb = stat.size / 1024;

    // Parse row count from last stderr line: "[export] 1234 rows fetched"
    const rowLine = logLines.find(l => l.includes('rows fetched'));
    const rows = rowLine ? parseInt(rowLine.match(/(\d+) rows/)?.[1] ?? '0') : 0;

    logger.info({ table: opts.table, format: opts.format, rows, sizeKb, durationMs }, 'Export complete');

    return { path: outPath, rows, sizeKb, durationMs };
  }

  static cleanup(path: string): void {
    try {
      if (existsSync(path)) unlinkSync(path);
    } catch {
      // best-effort
    }
  }
}
