CREATE TABLE IF NOT EXISTS runtime_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS crawler_workers (
    name TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    state TEXT NOT NULL
      CHECK (state IN ('starting', 'running', 'waiting', 'error', 'stopped')),
    activity TEXT NOT NULL,
    processed_users BIGINT NOT NULL DEFAULT 0,
    processed_keys BIGINT NOT NULL DEFAULT 0,
    requests BIGINT NOT NULL DEFAULT 0,
    rate_remaining INTEGER,
    rate_limit INTEGER,
    rate_reset_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS crawl_runs (
    id BIGSERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('initial', 'global')),
    status TEXT NOT NULL DEFAULT 'running'
      CHECK (status IN ('running', 'completed', 'failed')),
    cutoff_user_id BIGINT,
    next_since_id BIGINT NOT NULL DEFAULT 0,
    next_url TEXT NOT NULL,
    enumeration_complete BOOLEAN NOT NULL DEFAULT false,
    enumerated_users BIGINT NOT NULL DEFAULT 0,
    processed_users BIGINT NOT NULL DEFAULT 0,
    zero_key_users BIGINT NOT NULL DEFAULT 0,
    key_owner_users BIGINT NOT NULL DEFAULT 0,
    inaccessible_users BIGINT NOT NULL DEFAULT 0,
    error_users BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS crawl_runs_one_active_main
ON crawl_runs ((status))
WHERE status = 'running';

CREATE TABLE IF NOT EXISTS account_queue (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES crawl_runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('global', 'tail', 'priority')),
    github_id BIGINT NOT NULL,
    node_id TEXT NOT NULL,
    login TEXT NOT NULL,
    scan_id UUID NOT NULL DEFAULT gen_random_uuid(),
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'running', 'retry')),
    attempts INTEGER NOT NULL DEFAULT 0,
    claimed_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ;

CREATE UNIQUE INDEX IF NOT EXISTS account_queue_global_unique
ON account_queue (run_id, github_id)
WHERE source = 'global';

CREATE UNIQUE INDEX IF NOT EXISTS account_queue_non_global_unique
ON account_queue (source, github_id)
WHERE source <> 'global';

CREATE INDEX IF NOT EXISTS account_queue_claim_idx
ON account_queue (status, source, id);

CREATE TABLE IF NOT EXISTS github_owners (
    github_id BIGINT PRIMARY KEY,
    node_id TEXT NOT NULL UNIQUE,
    login TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_verified_at TIMESTAMPTZ,
    next_priority_scan_at TIMESTAMPTZ,
    inaccessible BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS github_owners_login_idx
ON github_owners (lower(login));

CREATE INDEX IF NOT EXISTS github_owners_priority_idx
ON github_owners (next_priority_scan_at, github_id);

CREATE TABLE IF NOT EXISTS github_owner_logins (
    github_id BIGINT NOT NULL REFERENCES github_owners(github_id) ON DELETE CASCADE,
    login TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    currently_present BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (github_id, login)
);

CREATE TABLE IF NOT EXISTS ssh_keys (
    fingerprint_sha256 BYTEA PRIMARY KEY,
    fingerprint_text TEXT NOT NULL UNIQUE,
    key_type TEXT NOT NULL,
    public_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS github_owner_keys (
    github_id BIGINT NOT NULL REFERENCES github_owners(github_id) ON DELETE CASCADE,
    fingerprint_sha256 BYTEA NOT NULL REFERENCES ssh_keys(fingerprint_sha256),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_verified_at TIMESTAMPTZ,
    currently_present BOOLEAN NOT NULL DEFAULT true,
    removed_at TIMESTAMPTZ,
    last_observation_scan UUID NOT NULL,
    PRIMARY KEY (github_id, fingerprint_sha256)
);

CREATE INDEX IF NOT EXISTS github_owner_keys_reverse_idx
ON github_owner_keys (fingerprint_sha256, currently_present, github_id);

CREATE TABLE IF NOT EXISTS overflow_queue (
    id BIGSERIAL PRIMARY KEY,
    run_id BIGINT REFERENCES crawl_runs(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (source IN ('global', 'tail', 'priority')),
    github_id BIGINT NOT NULL REFERENCES github_owners(github_id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    login TEXT NOT NULL,
    scan_id UUID NOT NULL,
    cursor TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
      CHECK (status IN ('pending', 'running', 'retry')),
    attempts INTEGER NOT NULL DEFAULT 0,
    claimed_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (source, github_id, scan_id)
);

ALTER TABLE overflow_queue
ADD COLUMN IF NOT EXISTS last_error_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS overflow_queue_claim_idx
ON overflow_queue (status, id);
