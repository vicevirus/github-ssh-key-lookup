CREATE INDEX CONCURRENTLY IF NOT EXISTS coverage_partitions_work_idx
ON coverage_partitions (generation_id, status, next_attempt_at, start_at);

