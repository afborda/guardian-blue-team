-- Markov user behavioral profiling — pure SQL.
--
-- Materialized view computes per-user (server_id, user_name) command-to-command
-- transition probabilities from the last 90 days of sudo_command events. A new
-- transition is scored by `-log(p)` (surprisal); we flag it as anomalous when it
-- exceeds the user's own p99 threshold AND the user has enough samples for the
-- distribution to be meaningful.
--
-- Refresh: `REFRESH MATERIALIZED VIEW CONCURRENTLY user_command_transitions`
-- runs daily from intelligence.worker — concurrent refresh requires the unique
-- index defined below.
--
-- Cold-start: scoring code (markov-user-profile.service.ts) skips users whose
-- `total_samples` is below MIN_SAMPLES (50) — they fall through with no signal.

CREATE MATERIALIZED VIEW IF NOT EXISTS user_command_transitions AS
WITH paired AS (
  SELECT
    e.server_id,
    e.user_name,
    -- Command extracted from JSONB metadata; fall back to NULL so missing
    -- metadata doesn't poison the chain.
    (e.metadata->>'command')                                  AS curr_cmd,
    LAG(e.metadata->>'command') OVER (
      PARTITION BY e.server_id, e.user_name
      ORDER BY e.timestamp
    )                                                         AS prev_cmd
  FROM security_events e
  WHERE e.event_type = 'sudo_command'
    AND e.user_name IS NOT NULL
    AND e.metadata ? 'command'
    AND e.timestamp > NOW() - INTERVAL '90 days'
),
counted AS (
  SELECT
    server_id,
    user_name,
    prev_cmd,
    curr_cmd,
    COUNT(*) AS n
  FROM paired
  WHERE prev_cmd IS NOT NULL
    AND curr_cmd IS NOT NULL
  GROUP BY server_id, user_name, prev_cmd, curr_cmd
)
SELECT
  server_id,
  user_name,
  prev_cmd,
  curr_cmd,
  n,
  -- Per-user, per-prev_cmd normalization: P(curr | prev, user, server).
  n::float / SUM(n) OVER (PARTITION BY server_id, user_name, prev_cmd) AS p,
  -- Total samples for the user — used for cold-start cutoff.
  SUM(n) OVER (PARTITION BY server_id, user_name) AS total_samples
FROM counted;

-- Required for REFRESH MATERIALIZED VIEW CONCURRENTLY.
CREATE UNIQUE INDEX IF NOT EXISTS user_command_transitions_pk
  ON user_command_transitions (server_id, user_name, prev_cmd, curr_cmd);

CREATE INDEX IF NOT EXISTS user_command_transitions_lookup_idx
  ON user_command_transitions (server_id, user_name, prev_cmd);

-- Per-user p99 surprisal threshold. We compute -log(p) on every observed
-- transition the user has made, then take the 99th percentile of *that*
-- distribution. A new transition's surprisal is anomalous when it exceeds this
-- value. A separate view keeps the threshold logic out of the hot scoring path.
CREATE MATERIALIZED VIEW IF NOT EXISTS user_command_thresholds AS
SELECT
  server_id,
  user_name,
  total_samples,
  -- p99 of -log(p) across this user's known transitions.
  PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY -LN(p)) AS p99_surprisal,
  -- Smallest p in the user's training set, used as a floor for unseen
  -- transitions (they'd otherwise score +Infinity and overwhelm the alert).
  MIN(p) AS min_observed_p
FROM user_command_transitions
GROUP BY server_id, user_name, total_samples;

CREATE UNIQUE INDEX IF NOT EXISTS user_command_thresholds_pk
  ON user_command_thresholds (server_id, user_name);
