CREATE INDEX CONCURRENTLY IF NOT EXISTS account_queue_rest_fallback_due_idx
ON account_queue (next_attempt_at, id)
WHERE status = 'rest_fallback';
