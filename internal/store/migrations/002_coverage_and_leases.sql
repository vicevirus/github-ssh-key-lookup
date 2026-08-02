ALTER TABLE crawl_runs
ADD COLUMN IF NOT EXISTS coverage_version SMALLINT NOT NULL DEFAULT 0;

ALTER TABLE crawl_runs
ADD COLUMN IF NOT EXISTS settled_cutoff TIMESTAMPTZ;

ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity';

ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS claim_token UUID;

ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS coverage_generation_id BIGINT;

ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS coverage_partition_id BIGINT;

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT '-infinity';

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS claim_token UUID;

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS account_created_at TIMESTAMPTZ;

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS coverage_generation_id BIGINT;

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS coverage_partition_id BIGINT;

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS expected_key_count INTEGER;

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS observed_key_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS verification_pass SMALLINT NOT NULL DEFAULT 1;

DO $$
BEGIN
    ALTER TABLE account_queue DROP CONSTRAINT IF EXISTS account_queue_source_check;
    ALTER TABLE account_queue ADD CONSTRAINT account_queue_source_check
      CHECK (source IN (
        'global', 'tail', 'priority', 'onboarding', 'reconcile', 'anomaly'
      )) NOT VALID;

    ALTER TABLE overflow_queue DROP CONSTRAINT IF EXISTS overflow_queue_source_check;
    ALTER TABLE overflow_queue ADD CONSTRAINT overflow_queue_source_check
      CHECK (source IN (
        'global', 'tail', 'priority', 'onboarding', 'reconcile', 'anomaly'
      )) NOT VALID;
END
$$;

CREATE TABLE IF NOT EXISTS coverage_generations (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL UNIQUE REFERENCES crawl_runs(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'building'
      CHECK (status IN (
        'building', 'auditing', 'repairing', 'count_reconciled', 'unresolved'
      )),
    cutoff_user_id BIGINT NOT NULL,
    settled_cutoff TIMESTAMPTZ NOT NULL,
    discovered_accounts BIGINT NOT NULL DEFAULT 0,
    successful_accounts BIGINT NOT NULL DEFAULT 0,
    inaccessible_accounts BIGINT NOT NULL DEFAULT 0,
    unresolved_accounts BIGINT NOT NULL DEFAULT 0,
    partitions_consistent BIGINT NOT NULL DEFAULT 0,
    partitions_repairing BIGINT NOT NULL DEFAULT 0,
    partitions_unresolved BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

ALTER TABLE crawl_runs
ADD COLUMN IF NOT EXISTS coverage_generation_id BIGINT
  REFERENCES coverage_generations(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS coverage_bitmap_chunks (
    generation_id BIGINT NOT NULL REFERENCES coverage_generations(id) ON DELETE CASCADE,
    chunk_no BIGINT NOT NULL,
    discovered_bits BIT(8192) NOT NULL DEFAULT repeat('0', 8192)::bit(8192),
    successful_bits BIT(8192) NOT NULL DEFAULT repeat('0', 8192)::bit(8192),
    inaccessible_bits BIT(8192) NOT NULL DEFAULT repeat('0', 8192)::bit(8192),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (generation_id, chunk_no)
);

CREATE TABLE IF NOT EXISTS coverage_day_counts (
    generation_id BIGINT NOT NULL REFERENCES coverage_generations(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    successful_accounts BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (generation_id, day)
);

CREATE TABLE IF NOT EXISTS coverage_partitions (
    id BIGSERIAL PRIMARY KEY,
    generation_id BIGINT NOT NULL REFERENCES coverage_generations(id) ON DELETE CASCADE,
    start_at TIMESTAMPTZ NOT NULL,
    end_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN (
        'pending', 'count_consistent', 'splitting', 'enumerating',
        'repairing', 'resolved', 'unresolved'
      )),
    sample BOOLEAN NOT NULL DEFAULT false,
    remote_count BIGINT,
    local_count BIGINT,
    pre_count BIGINT,
    post_count BIGINT,
    incomplete_results BOOLEAN NOT NULL DEFAULT false,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    UNIQUE (generation_id, start_at, end_at)
);

CREATE TABLE IF NOT EXISTS coverage_partition_ids (
    partition_id BIGINT NOT NULL REFERENCES coverage_partitions(id) ON DELETE CASCADE,
    github_id BIGINT NOT NULL,
    node_id TEXT NOT NULL,
    login TEXT NOT NULL,
    queued BOOLEAN NOT NULL DEFAULT false,
    resolved BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (partition_id, github_id)
);

ALTER TABLE account_queue
ADD CONSTRAINT account_queue_coverage_generation_fk
FOREIGN KEY (coverage_generation_id)
REFERENCES coverage_generations(id) ON DELETE SET NULL NOT VALID;

ALTER TABLE account_queue
ADD CONSTRAINT account_queue_coverage_partition_fk
FOREIGN KEY (coverage_partition_id)
REFERENCES coverage_partitions(id) ON DELETE SET NULL NOT VALID;

CREATE TABLE IF NOT EXISTS scan_anomalies (
    github_id BIGINT PRIMARY KEY,
    node_id TEXT NOT NULL,
    login TEXT NOT NULL,
    run_id BIGINT REFERENCES crawl_runs(id) ON DELETE SET NULL,
    generation_id BIGINT REFERENCES coverage_generations(id) ON DELETE SET NULL,
    partition_id BIGINT REFERENCES coverage_partitions(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS key_scan_attempts (
    scan_id UUID PRIMARY KEY,
    github_id BIGINT NOT NULL,
    run_id BIGINT REFERENCES crawl_runs(id) ON DELETE SET NULL,
    generation_id BIGINT REFERENCES coverage_generations(id) ON DELETE SET NULL,
    pass SMALLINT NOT NULL DEFAULT 1 CHECK (pass IN (1, 2)),
    expected_count INTEGER NOT NULL,
    next_cursor TEXT,
    page_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'collecting'
      CHECK (status IN ('collecting', 'verifying', 'complete', 'partial')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS key_scan_staging (
    scan_id UUID NOT NULL REFERENCES key_scan_attempts(scan_id) ON DELETE CASCADE,
    pass SMALLINT NOT NULL CHECK (pass IN (1, 2)),
    fingerprint_sha256 BYTEA NOT NULL,
    fingerprint_text TEXT NOT NULL,
    key_type TEXT NOT NULL,
    public_key TEXT NOT NULL,
    PRIMARY KEY (scan_id, pass, fingerprint_sha256)
);

CREATE TABLE IF NOT EXISTS crawler_rate_samples (
    sampled_at TIMESTAMPTZ NOT NULL,
    processed_users BIGINT NOT NULL,
    enumerated_users BIGINT NOT NULL,
    PRIMARY KEY (sampled_at)
);

CREATE TABLE IF NOT EXISTS service_snapshots (
    name TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
