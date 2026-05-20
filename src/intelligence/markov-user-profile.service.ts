/**
 * Markov user behavioral profiling — pure-SQL surprisal scoring.
 *
 * Lookup-only service: every transition probability and threshold is
 * pre-computed in the materialized views `user_command_transitions` and
 * `user_command_thresholds` (see migrations/007_user_command_transitions.sql).
 * This file just queries them and applies the cold-start guard.
 *
 * Cold-start: users with fewer than `MIN_SAMPLES` historical transitions on the
 * server are skipped — their distribution isn't yet stable enough to call
 * anything anomalous without flooding alerts. 50 was chosen so that a typical
 * admin who runs ~5 sudo commands/day reaches the threshold inside two weeks,
 * while service accounts and rare users stay silent.
 *
 * Refresh: intelligence.worker triggers `REFRESH MATERIALIZED VIEW CONCURRENTLY`
 * on both views once a day. Until the first refresh runs, scoring returns
 * `notEnoughData` for everyone.
 */

import { sql } from 'drizzle-orm';
import { db } from '../database/connection.js';
import { logger } from '../utils/logger.js';

export const MIN_SAMPLES = 50;

export interface MarkovScore {
  // -ln(P(curr | prev, user)). Higher = more surprising.
  surprisal: number;
  // P at which the transition fires for THIS user.
  threshold: number;
  isAnomaly: boolean;
  // 'scored' = had enough data and a probability lookup; 'unseen' = transition
  // never observed before but user has data; 'cold' = under MIN_SAMPLES.
  reason: 'scored' | 'unseen' | 'cold';
  totalSamples: number;
}

interface TransitionRow {
  p: number;
  [key: string]: unknown;
}
interface ThresholdRow {
  p99_surprisal: number | null;
  total_samples: number;
  min_observed_p: number | null;
  [key: string]: unknown;
}

export class MarkovUserProfile {
  /**
   * Score a single transition for a (server, user, prev_cmd, curr_cmd) tuple.
   * Returns null if the database lookup fails (logged at debug — failing here
   * must not break detection).
   */
  static async score(
    serverId: number,
    userName: string,
    prevCmd: string,
    currCmd: string,
  ): Promise<MarkovScore | null> {
    try {
      const thresholdRows = await db.execute<ThresholdRow>(sql`
        SELECT p99_surprisal, total_samples, min_observed_p
        FROM user_command_thresholds
        WHERE server_id = ${serverId} AND user_name = ${userName}
        LIMIT 1
      `);
      const threshold = (thresholdRows as unknown as { rows: ThresholdRow[] }).rows?.[0];
      if (!threshold || threshold.total_samples < MIN_SAMPLES) {
        return {
          surprisal: 0,
          threshold: 0,
          isAnomaly: false,
          reason: 'cold',
          totalSamples: threshold?.total_samples ?? 0,
        };
      }

      const transitionRows = await db.execute<TransitionRow>(sql`
        SELECT p
        FROM user_command_transitions
        WHERE server_id = ${serverId}
          AND user_name = ${userName}
          AND prev_cmd = ${prevCmd}
          AND curr_cmd = ${currCmd}
        LIMIT 1
      `);
      const transition = (transitionRows as unknown as { rows: TransitionRow[] }).rows?.[0];

      // Unseen transition — score it against the smallest probability the user
      // has ever produced. This caps surprisal so a single novel command
      // doesn't single-handedly trigger an alert; it still tends to be high
      // and will fire when paired with the user's own threshold.
      const p = transition?.p ?? threshold.min_observed_p ?? null;
      if (p === null || p <= 0) {
        return {
          surprisal: 0,
          threshold: threshold.p99_surprisal ?? 0,
          isAnomaly: false,
          reason: 'unseen',
          totalSamples: threshold.total_samples,
        };
      }

      const surprisal = -Math.log(p);
      const p99 = threshold.p99_surprisal ?? Infinity;
      return {
        surprisal,
        threshold: p99,
        isAnomaly: surprisal > p99,
        reason: transition ? 'scored' : 'unseen',
        totalSamples: threshold.total_samples,
      };
    } catch (err) {
      logger.debug({ err, serverId, userName }, 'Markov score lookup failed');
      return null;
    }
  }

  /**
   * Refresh both materialized views concurrently. Cheap if no rows have changed
   * since the last refresh (Postgres still scans, but doesn't block readers).
   * Called by intelligence.worker once a day.
   */
  static async refresh(): Promise<void> {
    try {
      await db.execute(sql`REFRESH MATERIALIZED VIEW CONCURRENTLY user_command_transitions`);
      await db.execute(sql`REFRESH MATERIALIZED VIEW CONCURRENTLY user_command_thresholds`);
      logger.info('Markov user profile views refreshed');
    } catch (err) {
      // First refresh after migration must be non-concurrent (Postgres rejects
      // CONCURRENTLY on a never-populated matview). Retry without it.
      try {
        await db.execute(sql`REFRESH MATERIALIZED VIEW user_command_transitions`);
        await db.execute(sql`REFRESH MATERIALIZED VIEW user_command_thresholds`);
        logger.info('Markov user profile views refreshed (initial, non-concurrent)');
      } catch (err2) {
        logger.warn({ err: (err2 as Error).message }, 'Markov refresh failed');
      }
    }
  }
}
