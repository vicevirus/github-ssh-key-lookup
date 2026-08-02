CREATE INDEX CONCURRENTLY IF NOT EXISTS scan_anomalies_due_idx
ON scan_anomalies (next_attempt_at, github_id);
