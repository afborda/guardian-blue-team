import { logger } from '../utils/logger.js';
import { CONSTANTS } from '../config/constants.js';
import { db, dbNow } from '../database/connection.js';
import { sql } from 'drizzle-orm';
import { createHash } from 'crypto';
import { ServerService } from '../services/server.service.js';
import { FIMCollector } from '../collectors/fim-collector.js';
import { CronCollector, type CronEntry } from '../collectors/cron-collector.js';
import { SSHKeysCollector } from '../collectors/ssh-keys-collector.js';
import { EventNormalizer } from '../pipeline/normalizer.js';
import { EventDetector } from '../pipeline/detector.js';
import { EventCorrelator } from '../pipeline/correlator.js';
import { EventIngestor } from '../pipeline/ingestor.js';
import type { RawLogEntry } from '../collectors/log-collector.js';
import type { SSHTarget } from '../collectors/ssh-collector.js';

export class FIMWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static running = false;

  static start(): void {
    if (this.intervalId) return;

    setTimeout(() => {
      this.work().catch(e => logger.error({ err: e }, 'FIM worker error'));
    }, 30_000);

    this.intervalId = setInterval(() => {
      this.work().catch(e => logger.error({ err: e }, 'FIM worker error'));
    }, CONSTANTS.fim.intervalMs);

    logger.info('FIM/Baseline worker started (interval: 4h)');
  }

  static stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  private static async work(): Promise<void> {
    if (this.running) return;
    this.running = true;

    try {
      const servers = await ServerService.getEnabled();
      if (servers.length === 0) {
        logger.debug('No servers registered, skipping FIM check');
        return;
      }

      for (const server of servers) {
        try {
          const target = ServerService.toSSHTarget(server);
          await this.checkFileIntegrity(target);
          await this.checkCronJobs(target);
          await this.checkSSHKeys(target);
        } catch (err) {
          logger.error({ err, server: server.name }, 'FIM check failed for server');
        }
      }
    } finally {
      this.running = false;
    }
  }

  // ─── File Integrity ──────────────────────────────────────────────────────────

  private static async checkFileIntegrity(target: SSHTarget): Promise<void> {
    const current = await FIMCollector.collect(target);
    if (current.length === 0) return;

    const existing = await db.execute<{
      file_path: string;
      sha256: string;
      permissions: string | null;
      owner: string | null;
    }>(sql`SELECT file_path, sha256, permissions, owner FROM file_baselines WHERE server_id = ${target.id}`);

    const baselineMap = new Map<string, { sha256: string; permissions: string | null; owner: string | null }>();
    for (const row of existing.rows) {
      baselineMap.set(row.file_path, { sha256: row.sha256, permissions: row.permissions, owner: row.owner });
    }

    const isFirstRun = baselineMap.size === 0;

    // Upsert all current entries into the baseline
    for (const file of current) {
      await db.execute(sql`
        INSERT INTO file_baselines (server_id, file_path, sha256, permissions, owner, last_seen_at)
        VALUES (${target.id}, ${file.path}, ${file.sha256}, ${file.permissions}, ${file.owner}, ${dbNow()})
        ON CONFLICT (server_id, file_path)
        DO UPDATE SET sha256 = ${file.sha256}, permissions = ${file.permissions}, owner = ${file.owner}, last_seen_at = ${dbNow()}
      `);
    }

    if (isFirstRun) {
      logger.info({ server: target.name, files: current.length }, 'FIM baseline initialized');
      return;
    }

    // Detect changes
    const rawEvents: RawLogEntry[] = [];
    const currentPaths = new Set(current.map(f => f.path));

    for (const file of current) {
      const baseline = baselineMap.get(file.path);

      if (!baseline) {
        // New file appeared
        rawEvents.push({
          serverId: target.id,
          serverName: target.name,
          source: 'fim',
          timestamp: new Date(),
          line: `FILE_CREATED path=${file.path} sha256=${file.sha256} permissions=${file.permissions} owner=${file.owner}`,
        });
      } else {
        if (baseline.sha256 !== file.sha256) {
          rawEvents.push({
            serverId: target.id,
            serverName: target.name,
            source: 'fim',
            timestamp: new Date(),
            line: `FILE_MODIFIED path=${file.path} old_sha256=${baseline.sha256} new_sha256=${file.sha256}`,
          });
        }
        if (baseline.permissions !== file.permissions) {
          rawEvents.push({
            serverId: target.id,
            serverName: target.name,
            source: 'fim',
            timestamp: new Date(),
            line: `FILE_PERMISSIONS_CHANGED path=${file.path} old_permissions=${baseline.permissions} new_permissions=${file.permissions}`,
          });
        }
        if (baseline.owner !== file.owner) {
          rawEvents.push({
            serverId: target.id,
            serverName: target.name,
            source: 'fim',
            timestamp: new Date(),
            line: `FILE_MODIFIED path=${file.path} old_owner=${baseline.owner} new_owner=${file.owner}`,
          });
        }
      }
    }

    // Check for deleted files
    for (const [path] of baselineMap) {
      if (!currentPaths.has(path)) {
        rawEvents.push({
          serverId: target.id,
          serverName: target.name,
          source: 'fim',
          timestamp: new Date(),
          line: `FILE_DELETED path=${path}`,
        });
      }
    }

    if (rawEvents.length > 0) {
      await this.emitEvents(rawEvents);
      logger.info({ server: target.name, changes: rawEvents.length }, 'FIM changes detected');
    }
  }

  // ─── Cron Jobs ───────────────────────────────────────────────────────────────

  private static cronEntryHash(entry: CronEntry): string {
    return createHash('sha256').update(`${entry.schedule}${entry.command}`).digest('hex');
  }

  private static async checkCronJobs(target: SSHTarget): Promise<void> {
    const current = await CronCollector.collect(target);

    const existing = await db.execute<{
      username: string;
      schedule: string | null;
      command: string;
      source: string;
      sha256: string;
    }>(sql`SELECT username, schedule, command, source, sha256 FROM cron_baselines WHERE server_id = ${target.id}`);

    const baselineSet = new Set<string>();
    for (const row of existing.rows) {
      baselineSet.add(row.sha256);
    }

    const isFirstRun = baselineSet.size === 0;

    // Upsert current entries
    for (const entry of current) {
      const hash = this.cronEntryHash(entry);
      await db.execute(sql`
        INSERT INTO cron_baselines (server_id, username, schedule, command, source, sha256, first_seen_at, last_seen_at)
        VALUES (${target.id}, ${entry.user}, ${entry.schedule}, ${entry.command}, ${entry.source}, ${hash}, ${dbNow()}, ${dbNow()})
        ON CONFLICT (server_id, username, sha256)
        DO UPDATE SET last_seen_at = ${dbNow()}, schedule = ${entry.schedule}, command = ${entry.command}, source = ${entry.source}
      `);
    }

    if (isFirstRun) {
      logger.info({ server: target.name, crons: current.length }, 'Cron baseline initialized');
      return;
    }

    // Detect changes
    const rawEvents: RawLogEntry[] = [];
    const currentHashes = new Set(current.map(e => this.cronEntryHash(e)));

    // New cron entries
    for (const entry of current) {
      const hash = this.cronEntryHash(entry);
      if (!baselineSet.has(hash)) {
        rawEvents.push({
          serverId: target.id,
          serverName: target.name,
          source: 'cron',
          timestamp: new Date(),
          line: `CRON_ADDED user=${entry.user} schedule="${entry.schedule}" command="${entry.command}" source=${entry.source}`,
        });
      }
    }

    // Removed cron entries
    for (const row of existing.rows) {
      if (!currentHashes.has(row.sha256)) {
        rawEvents.push({
          serverId: target.id,
          serverName: target.name,
          source: 'cron',
          timestamp: new Date(),
          line: `CRON_REMOVED user=${row.username} schedule="${row.schedule}" command="${row.command}" source=${row.source}`,
        });
      }
    }

    if (rawEvents.length > 0) {
      await this.emitEvents(rawEvents);
      logger.info({ server: target.name, changes: rawEvents.length }, 'Cron changes detected');
    }
  }

  // ─── SSH Keys ────────────────────────────────────────────────────────────────

  private static async checkSSHKeys(target: SSHTarget): Promise<void> {
    const current = await SSHKeysCollector.collect(target);

    const existing = await db.execute<{
      username: string;
      key_type: string;
      fingerprint: string;
      comment: string | null;
    }>(sql`SELECT username, key_type, fingerprint, comment FROM ssh_key_baselines WHERE server_id = ${target.id}`);

    const baselineSet = new Set<string>();
    for (const row of existing.rows) {
      baselineSet.add(`${row.username}:${row.fingerprint}`);
    }

    const isFirstRun = baselineSet.size === 0;

    // Upsert current entries
    for (const key of current) {
      await db.execute(sql`
        INSERT INTO ssh_key_baselines (server_id, username, key_type, fingerprint, comment, first_seen_at, last_seen_at)
        VALUES (${target.id}, ${key.user}, ${key.keyType}, ${key.fingerprint}, ${key.comment}, ${dbNow()}, ${dbNow()})
        ON CONFLICT (server_id, username, fingerprint)
        DO UPDATE SET key_type = ${key.keyType}, comment = ${key.comment}, last_seen_at = ${dbNow()}
      `);
    }

    if (isFirstRun) {
      logger.info({ server: target.name, keys: current.length }, 'SSH key baseline initialized');
      return;
    }

    // Detect changes
    const rawEvents: RawLogEntry[] = [];
    const currentKeys = new Set(current.map(k => `${k.user}:${k.fingerprint}`));

    // New SSH keys
    for (const key of current) {
      const identifier = `${key.user}:${key.fingerprint}`;
      if (!baselineSet.has(identifier)) {
        rawEvents.push({
          serverId: target.id,
          serverName: target.name,
          source: 'ssh-keys',
          timestamp: new Date(),
          line: `SSH_KEY_ADDED user=${key.user} type=${key.keyType} fingerprint=${key.fingerprint} comment="${key.comment}"`,
        });
      }
    }

    // Removed SSH keys
    for (const row of existing.rows) {
      const identifier = `${row.username}:${row.fingerprint}`;
      if (!currentKeys.has(identifier)) {
        rawEvents.push({
          serverId: target.id,
          serverName: target.name,
          source: 'ssh-keys',
          timestamp: new Date(),
          line: `SSH_KEY_REMOVED user=${row.username} type=${row.key_type} fingerprint=${row.fingerprint} comment="${row.comment}"`,
        });
      }
    }

    if (rawEvents.length > 0) {
      await this.emitEvents(rawEvents);
      logger.info({ server: target.name, changes: rawEvents.length }, 'SSH key changes detected');
    }
  }

  // ─── Event Pipeline ──────────────────────────────────────────────────────────

  private static async emitEvents(rawEvents: RawLogEntry[]): Promise<void> {
    const normalized = EventNormalizer.normalizeBatch(rawEvents);
    if (normalized.length === 0) return;

    const detected = EventDetector.detect(normalized);
    const allEvents = detected.length > 0 ? [...normalized, ...detected] : normalized;

    const correlated = await EventCorrelator.correlate(allEvents);
    await EventIngestor.persist(correlated);
  }
}
