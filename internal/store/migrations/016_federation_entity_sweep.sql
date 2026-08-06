ALTER TABLE account_queue DROP CONSTRAINT IF EXISTS account_queue_source_check;
ALTER TABLE account_queue ADD CONSTRAINT account_queue_source_check
CHECK (source IN (
  'global', 'tail', 'priority', 'onboarding', 'reconcile', 'anomaly',
  'federation'
)) NOT VALID;

ALTER TABLE overflow_queue DROP CONSTRAINT IF EXISTS overflow_queue_source_check;
ALTER TABLE overflow_queue ADD CONSTRAINT overflow_queue_source_check
CHECK (source IN (
  'global', 'tail', 'priority', 'onboarding', 'reconcile', 'anomaly',
  'federation'
)) NOT VALID;

CREATE TABLE IF NOT EXISTS entity_sweep_runs (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('initial', 'tail', 'reconcile')),
    lower_id BIGINT NOT NULL CHECK (lower_id > 0),
    upper_id BIGINT NOT NULL CHECK (upper_id >= lower_id),
    status TEXT NOT NULL DEFAULT 'running'
      CHECK (status IN ('running', 'completed')),
    batch_size INTEGER NOT NULL CHECK (batch_size BETWEEN 25 AND 250),
    requests BIGINT NOT NULL DEFAULT 0,
    resolved_users BIGINT NOT NULL DEFAULT 0,
    key_owners BIGINT NOT NULL DEFAULT 0,
    keys_observed BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_progress_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    CHECK (completed_at IS NULL OR status = 'completed')
);

CREATE UNIQUE INDEX IF NOT EXISTS entity_sweep_one_active
ON entity_sweep_runs ((status)) WHERE status = 'running';

CREATE TABLE IF NOT EXISTS entity_sweep_shards (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES entity_sweep_runs(id) ON DELETE CASCADE,
    lower_id BIGINT NOT NULL,
    upper_id BIGINT NOT NULL,
    next_id BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'running', 'retry', 'completed')),
    batch_size INTEGER NOT NULL CHECK (batch_size BETWEEN 25 AND 250),
    attempts INTEGER NOT NULL DEFAULT 0,
    requests BIGINT NOT NULL DEFAULT 0,
    resolved_users BIGINT NOT NULL DEFAULT 0,
    key_owners BIGINT NOT NULL DEFAULT 0,
    keys_observed BIGINT NOT NULL DEFAULT 0,
    claim_token UUID,
    claimed_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    UNIQUE (run_id, lower_id, upper_id),
    CHECK (lower_id <= next_id AND next_id <= upper_id + 1),
    CHECK (lower_id <= upper_id)
);

CREATE INDEX IF NOT EXISTS entity_sweep_shards_claim_idx
ON entity_sweep_shards (run_id, status, next_id)
WHERE status IN ('pending', 'retry');
