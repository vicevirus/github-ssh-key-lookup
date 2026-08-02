CREATE INDEX CONCURRENTLY IF NOT EXISTS account_queue_claim_due_idx
ON account_queue (status, source, next_attempt_at, id)
WHERE status IN ('pending', 'retry');
