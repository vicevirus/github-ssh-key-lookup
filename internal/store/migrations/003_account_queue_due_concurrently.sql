CREATE INDEX CONCURRENTLY IF NOT EXISTS account_queue_due_source_idx
ON account_queue (source, next_attempt_at, id)
WHERE status IN ('pending', 'retry');

