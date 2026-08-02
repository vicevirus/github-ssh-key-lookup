ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS first_attempt_counted_at TIMESTAMPTZ;

-- Migration 009 already added these observations to crawl_runs. Mark them as
-- counted so the restart-safe two-phase counter cannot add them twice.
UPDATE account_queue
SET first_attempt_counted_at = first_attempted_at
WHERE first_attempted_at IS NOT NULL
  AND first_attempt_counted_at IS NULL;
