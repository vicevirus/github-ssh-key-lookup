ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS fallback_attempts INTEGER NOT NULL DEFAULT 0;

ALTER TABLE account_queue
DROP CONSTRAINT IF EXISTS account_queue_status_check;

ALTER TABLE account_queue
ADD CONSTRAINT account_queue_status_check
CHECK (status IN (
  'pending', 'running', 'retry', 'rest_fallback', 'rest_fallback_running'
)) NOT VALID;

-- Versions before this migration incremented attempts on 99 claimed accounts
-- while querying only one of them. Some of those unqueried accounts were then
-- falsely quarantined as permanent failures. Put every affected account back
-- into the normal full-batch GraphQL lane and undo the false settlement count.
WITH repaired AS (
  SELECT run_id, COUNT(*) AS accounts
  FROM scan_anomalies
  WHERE last_error = 'isolating repeatedly failing GraphQL account'
    AND run_id IS NOT NULL
  GROUP BY run_id
)
UPDATE crawl_runs AS run
SET processed_users = GREATEST(0, run.processed_users - repaired.accounts),
    error_users = GREATEST(0, run.error_users - repaired.accounts)
FROM repaired
WHERE run.id = repaired.run_id;

UPDATE account_queue
SET status = 'pending', attempts = 0, fallback_attempts = 0,
    claimed_at = NULL, claim_token = NULL, lease_expires_at = NULL,
    next_attempt_at = now(), last_error = NULL, last_error_at = NULL
WHERE last_error = 'isolating repeatedly failing GraphQL account';

UPDATE account_queue AS queue
SET run_id = COALESCE(queue.run_id, anomaly.run_id),
    coverage_generation_id = COALESCE(
      queue.coverage_generation_id, anomaly.generation_id
    ),
    coverage_partition_id = COALESCE(
      queue.coverage_partition_id, anomaly.partition_id
    ),
    status = 'pending', attempts = 0, fallback_attempts = 0,
    claimed_at = NULL, claim_token = NULL, lease_expires_at = NULL,
    next_attempt_at = now(), last_error = NULL, last_error_at = NULL
FROM scan_anomalies AS anomaly
WHERE queue.github_id = anomaly.github_id
  AND anomaly.last_error = 'isolating repeatedly failing GraphQL account';

INSERT INTO account_queue (
  run_id, source, github_id, node_id, login,
  status, attempts, fallback_attempts, next_attempt_at,
  coverage_generation_id, coverage_partition_id
)
SELECT anomaly.run_id, 'anomaly', anomaly.github_id,
       anomaly.node_id, anomaly.login, 'pending', 0, 0, now(),
       anomaly.generation_id, anomaly.partition_id
FROM scan_anomalies AS anomaly
WHERE anomaly.last_error = 'isolating repeatedly failing GraphQL account'
  AND NOT EXISTS (
    SELECT 1 FROM account_queue AS queue
    WHERE queue.github_id = anomaly.github_id
  )
ON CONFLICT DO NOTHING;

UPDATE scan_anomalies
SET attempts = 0, next_attempt_at = now(), last_seen_at = now(),
    last_error = 'requeued after repairing false GraphQL batch isolation'
WHERE last_error = 'isolating repeatedly failing GraphQL account';
