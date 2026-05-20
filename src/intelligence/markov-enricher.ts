/**
 * Pre-attach Markov surprisal scores to sudo_command events before the
 * synchronous detector pipeline runs. Mirrors the DGA enricher pattern:
 * detector rules can't `await`, so we do the lookup ahead of time and the rule
 * just reads `metadata.markovIsAnomaly`.
 *
 * For each sudo_command event we look up the user's PREVIOUS sudo_command on
 * the same server (within a 24h window) to form the (prev_cmd, curr_cmd)
 * transition. Events without a prior command are skipped — there's nothing to
 * score.
 */

import { sql } from 'drizzle-orm';
import type { NormalizedEvent } from '../pipeline/normalizer.js';
import { db } from '../database/connection.js';
import { MarkovUserProfile } from './markov-user-profile.service.js';
import { logger } from '../utils/logger.js';

interface PrevRow {
  command: string;
  [key: string]: unknown;
}

export async function enrichWithMarkovScore(
  events: NormalizedEvent[],
): Promise<NormalizedEvent[]> {
  const sudoEvents = events.filter(
    e => e.eventType === 'sudo_command'
      && e.userName
      && typeof e.metadata?.command === 'string',
  );
  if (sudoEvents.length === 0) return events;

  await Promise.all(sudoEvents.map(async event => {
    try {
      // Find the most recent prior sudo_command for this user on this server.
      // 24h window keeps the chain meaningful — older commands are likely a
      // different session/intent.
      const prevRows = await db.execute<PrevRow>(sql`
        SELECT metadata->>'command' AS command
        FROM security_events
        WHERE server_id = ${event.serverId}
          AND user_name = ${event.userName}
          AND event_type = 'sudo_command'
          AND timestamp < ${event.timestamp}
          AND timestamp > ${new Date(event.timestamp.getTime() - 24 * 60 * 60 * 1000)}
          AND metadata ? 'command'
        ORDER BY timestamp DESC
        LIMIT 1
      `);
      const prev = (prevRows as unknown as { rows: PrevRow[] }).rows?.[0];
      if (!prev?.command) return;

      const currCmd = event.metadata!.command as string;
      const score = await MarkovUserProfile.score(
        event.serverId,
        event.userName!,
        prev.command,
        currCmd,
      );
      if (!score) return;

      event.metadata = {
        ...event.metadata,
        markovPrevCmd: prev.command,
        markovSurprisal: score.surprisal,
        markovThreshold: score.threshold,
        markovIsAnomaly: score.isAnomaly,
        markovReason: score.reason,
        markovTotalSamples: score.totalSamples,
      };
    } catch (err) {
      logger.debug({ err, server: event.serverId }, 'Markov enrichment failed for event');
    }
  }));

  return events;
}
