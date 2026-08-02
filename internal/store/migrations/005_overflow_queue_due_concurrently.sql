CREATE INDEX CONCURRENTLY IF NOT EXISTS overflow_queue_due_idx
ON overflow_queue (next_attempt_at, id)
WHERE status IN ('pending', 'retry');

