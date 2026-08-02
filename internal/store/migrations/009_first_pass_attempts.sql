ALTER TABLE crawl_runs
ADD COLUMN IF NOT EXISTS attempted_users BIGINT NOT NULL DEFAULT 0;

ALTER TABLE account_queue
ADD COLUMN IF NOT EXISTS first_attempted_at TIMESTAMPTZ;

ALTER TABLE crawler_rate_samples
ADD COLUMN IF NOT EXISTS attempted_users BIGINT NOT NULL DEFAULT 0;

-- Completed rows are known observations. Existing retry/running rows are not:
-- their old attempt may have failed before GitHub returned a usable response,
-- so leave them unmarked and let the crawler account for them conservatively.
UPDATE crawl_runs
SET attempted_users = processed_users;

UPDATE crawler_rate_samples
SET attempted_users = processed_users
WHERE attempted_users = 0;
