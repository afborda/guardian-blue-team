import { SSHCollector, type SSHTarget } from './ssh-collector.js';
import type { RawLogEntry } from './log-collector.js';
import { CONSTANTS } from '../config/constants.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';
import { createHash } from 'node:crypto';

const DOCKER_TS = /^(\d{4}-\d{2}-\d{2}T[^\s]+)\s(.*)$/;
const MAX_MATCHES_PER_CONTAINER = 50;

export interface ContainerLogLine {
  timestamp: Date;
  text: string;
}

/** Remove o prefixo RFC3339 que `docker logs --timestamps` adiciona. */
export function parseDockerLogLine(line: string): ContainerLogLine {
  const match = line.match(DOCKER_TS);
  if (!match) return { timestamp: new Date(), text: line };
  const parsed = new Date(match[1]!);
  return {
    timestamp: Number.isNaN(parsed.getTime()) ? new Date() : parsed,
    text: match[2] ?? '',
  };
}

/** Marcadores de execução de comando/erro de exploit no stdout do app. */
export function isSuspiciousContainerLine(line: string): boolean {
  const { text } = parseDockerLogLine(line);
  return CONSTANTS.container.stdoutPatterns.test(text);
}

export class ContainerLogsCollector {
  private static seen = new Map<string, number>();
  private static readonly SEEN_TTL_MS = 10 * 60 * 1000;

  private static alreadyEmitted(serverId: number, container: string, line: string): boolean {
    const key = `${serverId}:${container}:${createHash('sha1').update(line).digest('hex')}`;
    const last = this.seen.get(key) ?? 0;
    if (Date.now() - last < this.SEEN_TTL_MS) return true;
    this.seen.set(key, Date.now());

    if (this.seen.size > 5_000) {
      const cutoff = Date.now() - this.SEEN_TTL_MS;
      for (const [seenKey, seenAt] of this.seen) {
        if (seenAt < cutoff) this.seen.delete(seenKey);
      }
    }
    return false;
  }

  static async collect(target: SSHTarget): Promise<RawLogEntry[]> {
    const wanted = new Set(config.collection?.logContainers ?? []);
    if (wanted.size === 0) return [];

    const list = await SSHCollector.run(
      target,
      "docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null | head -40",
      10_000,
    );
    if (!list.success || !list.stdout.trim()) return [];

    const containers = list.stdout.trim().split('\n').map(line => {
      const [id, ...nameParts] = line.trim().split(/\s+/);
      return { id: id ?? '', name: nameParts.join(' ') };
    }).filter(item => item.id.length >= 12 && wanted.has(item.name));

    const entries: RawLogEntry[] = [];
    for (const container of containers) {
      const logs = await SSHCollector.run(
        target,
        `docker logs --since 3m --timestamps --tail 200 ${container.id} 2>&1`,
        15_000,
      );
      if (!logs.success || !logs.stdout.trim()) continue;

      let matched = 0;
      for (const raw of logs.stdout.split('\n')) {
        if (!raw.trim() || !isSuspiciousContainerLine(raw)) continue;
        if (this.alreadyEmitted(target.id, container.name, raw)) continue;
        const parsed = parseDockerLogLine(raw);
        entries.push({
          serverId: target.id,
          serverName: target.name,
          source: 'container_stdout',
          timestamp: parsed.timestamp,
          line: `${container.name}|${raw}`,
        });
        matched++;
        if (matched >= MAX_MATCHES_PER_CONTAINER) break;
      }

      if (matched > 0) {
        logger.info({ server: target.name, container: container.name, matched }, 'Container logs: linhas suspeitas');
      }
    }

    logger.debug({ server: target.name, wanted: wanted.size, matched: entries.length }, 'Container logs cycle');
    return entries;
  }
}
