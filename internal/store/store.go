package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/local/github-ssh-index/internal/model"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	Pool *pgxpool.Pool
}

type Run struct {
	ID                  int64      `json:"id"`
	Kind                string     `json:"kind"`
	Status              string     `json:"status"`
	CutoffUserID        *int64     `json:"cutoff_user_id"`
	NextSinceID         int64      `json:"next_since_id"`
	NextURL             string     `json:"next_url"`
	EnumerationComplete bool       `json:"enumeration_complete"`
	EnumeratedUsers     int64      `json:"enumerated_users"`
	ProcessedUsers      int64      `json:"processed_users"`
	ZeroKeyUsers        int64      `json:"zero_key_users"`
	KeyOwnerUsers       int64      `json:"key_owner_users"`
	InaccessibleUsers   int64      `json:"inaccessible_users"`
	ErrorUsers          int64      `json:"error_users"`
	StartedAt           time.Time  `json:"started_at"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
}

type EnumerationShard struct {
	ID              int64
	RunID           int64
	LowerID         int64
	UpperID         int64
	NextSinceID     int64
	NextURL         string
	Attempts        int
	EnumeratedUsers int64
}

type Alias struct {
	Login            string    `json:"login"`
	FirstSeenAt      time.Time `json:"first_seen_at"`
	LastSeenAt       time.Time `json:"last_seen_at"`
	CurrentlyPresent bool      `json:"currently_present"`
}

type Match struct {
	GitHubID         int64      `json:"github_id"`
	Login            string     `json:"login"`
	ProfileURL       string     `json:"profile_url"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	LastVerifiedAt   *time.Time `json:"last_verified_at,omitempty"`
	CurrentlyPresent bool       `json:"currently_present"`
	RemovedAt        *time.Time `json:"removed_at,omitempty"`
	Aliases          []Alias    `json:"aliases"`
}

type IndexedKey struct {
	Fingerprint      string     `json:"fingerprint"`
	Type             string     `json:"type"`
	PublicKey        string     `json:"public_key"`
	FirstSeenAt      time.Time  `json:"first_seen_at"`
	LastSeenAt       time.Time  `json:"last_seen_at"`
	LastVerifiedAt   *time.Time `json:"last_verified_at,omitempty"`
	CurrentlyPresent bool       `json:"currently_present"`
	RemovedAt        *time.Time `json:"removed_at,omitempty"`
}

type IndexedUser struct {
	GitHubID       int64        `json:"github_id"`
	Login          string       `json:"login"`
	ProfileURL     string       `json:"profile_url"`
	FirstSeenAt    time.Time    `json:"first_seen_at"`
	LastSeenAt     time.Time    `json:"last_seen_at"`
	LastVerifiedAt *time.Time   `json:"last_verified_at,omitempty"`
	Inaccessible   bool         `json:"inaccessible"`
	Keys           []IndexedKey `json:"keys"`
}

type WorkerUpdate struct {
	Name           string
	Role           string
	State          string
	Activity       string
	ProcessedUsers int
	ProcessedKeys  int
	Request        bool
	RateRemaining  *int
	RateLimit      *int
	RateResetAt    *time.Time
	Success        bool
	Error          error
}

type WorkerStatus struct {
	Name           string     `json:"name"`
	Role           string     `json:"role"`
	State          string     `json:"state"`
	Activity       string     `json:"activity"`
	ProcessedUsers int64      `json:"processed_users"`
	ProcessedKeys  int64      `json:"processed_keys"`
	Requests       int64      `json:"requests"`
	RateRemaining  *int       `json:"rate_remaining,omitempty"`
	RateLimit      *int       `json:"rate_limit,omitempty"`
	RateResetAt    *time.Time `json:"rate_reset_at,omitempty"`
	LastSuccessAt  *time.Time `json:"last_success_at,omitempty"`
	LastError      *string    `json:"last_error,omitempty"`
	LastErrorAt    *time.Time `json:"last_error_at,omitempty"`
	StartedAt      time.Time  `json:"started_at"`
	HeartbeatAt    time.Time  `json:"heartbeat_at"`
}

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	config.MaxConns = 12
	config.MinConns = 1
	config.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect PostgreSQL: %w", err)
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() {
	s.Pool.Close()
}

func (s *Store) Migrate(ctx context.Context) error {
	const version = "001_init_20260802"
	applied, err := s.migrationApplied(ctx, version)
	if err != nil || applied {
		return err
	}

	connection, err := s.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer connection.Release()

	const migrationLockKey int64 = 742910238550
	if _, err := connection.Exec(
		ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey,
	); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		unlockContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = connection.Exec(
			unlockContext, `SELECT pg_advisory_unlock($1)`, migrationLockKey,
		)
	}()

	// Another process may have completed the migration while this process was
	// waiting for the advisory lock.
	applied, err = migrationAppliedOn(ctx, connection, version)
	if err != nil || applied {
		return err
	}

	ready, err := currentSchemaReady(ctx, connection)
	if err != nil {
		return err
	}
	if !ready {
		sql, err := migrations.ReadFile("migrations/001_init.sql")
		if err != nil {
			return err
		}
		if _, err := connection.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("apply database migration: %w", err)
		}
	}
	if _, err := connection.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
		  version TEXT PRIMARY KEY,
		  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	if _, err := connection.Exec(ctx, `
		INSERT INTO schema_migrations (version) VALUES ($1)
		ON CONFLICT (version) DO NOTHING
	`, version); err != nil {
		return fmt.Errorf("record database migration: %w", err)
	}
	return nil
}

type migrationQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) migrationApplied(ctx context.Context, version string) (bool, error) {
	return migrationAppliedOn(ctx, s.Pool, version)
}

func migrationAppliedOn(ctx context.Context, database migrationQuerier, version string) (bool, error) {
	var tableExists bool
	if err := database.QueryRow(ctx, `
		SELECT to_regclass('public.schema_migrations') IS NOT NULL
	`).Scan(&tableExists); err != nil || !tableExists {
		return false, err
	}
	var applied bool
	err := database.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)
	`, version).Scan(&applied)
	return applied, err
}

func currentSchemaReady(ctx context.Context, database migrationQuerier) (bool, error) {
	var ready bool
	err := database.QueryRow(ctx, `
		SELECT
		  to_regclass('public.runtime_state') IS NOT NULL AND
		  to_regclass('public.crawler_workers') IS NOT NULL AND
		  to_regclass('public.crawl_runs') IS NOT NULL AND
		  to_regclass('public.enumeration_shards') IS NOT NULL AND
		  to_regclass('public.account_queue') IS NOT NULL AND
		  to_regclass('public.github_owners') IS NOT NULL AND
		  to_regclass('public.github_owner_logins') IS NOT NULL AND
		  to_regclass('public.ssh_keys') IS NOT NULL AND
		  to_regclass('public.github_owner_keys') IS NOT NULL AND
		  to_regclass('public.zero_key_rechecks') IS NOT NULL AND
		  to_regclass('public.overflow_queue') IS NOT NULL AND
		  to_regclass('public.account_queue_ready_source_idx') IS NOT NULL AND
		  EXISTS (
		    SELECT 1 FROM information_schema.columns
		    WHERE table_schema = 'public' AND table_name = 'github_owner_keys'
		      AND column_name = 'state_changed_scan'
		  ) AND
		  EXISTS (
		    SELECT 1 FROM information_schema.columns
		    WHERE table_schema = 'public' AND table_name = 'account_queue'
		      AND column_name = 'last_error_at'
		  ) AND
		  EXISTS (
		    SELECT 1 FROM information_schema.columns
		    WHERE table_schema = 'public' AND table_name = 'github_owners'
		      AND column_name = 'refresh_stage'
		  )
	`).Scan(&ready)
	return ready, err
}

func (s *Store) Recover(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE account_queue
		SET status = 'retry', claimed_at = NULL,
		    last_error = COALESCE(last_error, 'recovered after restart'),
		    last_error_at = now()
		WHERE status = 'running';
		UPDATE overflow_queue
		SET status = 'retry', claimed_at = NULL,
		    last_error = COALESCE(last_error, 'recovered after restart'),
		    last_error_at = now()
		WHERE status = 'running';
		DELETE FROM crawler_workers;
		UPDATE enumeration_shards
		SET status = 'retry', claimed_at = NULL,
		    last_error = COALESCE(last_error, 'recovered after restart'),
		    last_error_at = now()
		WHERE status = 'running';
	`)
	return err
}

func (s *Store) UpdateWorker(ctx context.Context, update WorkerUpdate) error {
	if update.Name == "" || update.Role == "" {
		return errors.New("worker name and role are required")
	}
	if update.State == "" {
		update.State = "running"
	}
	if update.Activity == "" {
		update.Activity = "working"
	}
	var message *string
	if update.Error != nil {
		text := update.Error.Error()
		if len(text) > 2_000 {
			text = text[:2_000]
		}
		message = &text
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO crawler_workers (
		  name, role, state, activity, processed_users, processed_keys,
		  requests, rate_remaining, rate_limit, rate_reset_at,
		  last_success_at, last_error, last_error_at
		) VALUES (
		  $1, $2, $3, $4, $5, $6, CASE WHEN $7 THEN 1 ELSE 0 END,
		  $8, $9, $10,
		  CASE WHEN $11 THEN now() ELSE NULL END,
		  $12, CASE WHEN $12::text IS NULL THEN NULL ELSE now() END
		)
		ON CONFLICT (name) DO UPDATE SET
		  role = excluded.role,
		  state = excluded.state,
		  activity = excluded.activity,
		  processed_users = crawler_workers.processed_users + $5,
		  processed_keys = crawler_workers.processed_keys + $6,
		  requests = crawler_workers.requests + CASE WHEN $7 THEN 1 ELSE 0 END,
		  rate_remaining = COALESCE($8, crawler_workers.rate_remaining),
		  rate_limit = COALESCE($9, crawler_workers.rate_limit),
		  rate_reset_at = COALESCE($10, crawler_workers.rate_reset_at),
		  last_success_at = CASE
		    WHEN $11 THEN now() ELSE crawler_workers.last_success_at
		  END,
		  last_error = CASE
		    WHEN $12::text IS NOT NULL THEN $12 ELSE crawler_workers.last_error
		  END,
		  last_error_at = CASE
		    WHEN $12::text IS NOT NULL THEN now() ELSE crawler_workers.last_error_at
		  END,
		  heartbeat_at = now()
	`, update.Name, update.Role, update.State, update.Activity,
		update.ProcessedUsers, update.ProcessedKeys, update.Request,
		update.RateRemaining, update.RateLimit, update.RateResetAt,
		update.Success, message)
	return err
}

func (s *Store) StopWorker(ctx context.Context, name, role string) {
	stopContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_ = s.UpdateWorker(stopContext, WorkerUpdate{
		Name: name, Role: role, State: "stopped", Activity: "stopped",
	})
}

func (s *Store) AcquireCrawlerLock(ctx context.Context) (func(), error) {
	connection, err := s.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	var acquired bool
	if err := connection.QueryRow(ctx,
		`SELECT pg_try_advisory_lock(742910238551)`,
	).Scan(&acquired); err != nil {
		connection.Release()
		return nil, err
	}
	if !acquired {
		connection.Release()
		return nil, errors.New("another crawler scheduler already holds the PostgreSQL advisory lock")
	}
	return func() {
		unlock, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = connection.Exec(unlock, `SELECT pg_advisory_unlock(742910238551)`)
		connection.Release()
	}, nil
}

func (s *Store) EnsureMainRun(ctx context.Context, initialURL string) (Run, error) {
	run, err := s.ActiveMainRun(ctx)
	if err == nil {
		return run, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Run{}, err
	}
	complete, err := s.State(ctx, "initial_complete")
	if err != nil {
		return Run{}, err
	}
	kind := "initial"
	var cutoff *int64
	if complete == "true" {
		kind = "global"
		highwater, err := s.StateInt(ctx, "tail_highwater")
		if err != nil {
			return Run{}, err
		}
		cutoff = &highwater
	}
	row := s.Pool.QueryRow(ctx, `
		INSERT INTO crawl_runs (kind, cutoff_user_id, next_url)
		VALUES ($1, $2, $3)
		RETURNING id, kind, status, cutoff_user_id, next_since_id,
		          next_url, enumeration_complete, enumerated_users,
		          processed_users, zero_key_users, key_owner_users,
		          inaccessible_users, error_users, started_at, completed_at
	`, kind, cutoff, initialURL)
	return scanRun(row)
}

func (s *Store) ActiveMainRun(ctx context.Context) (Run, error) {
	return scanRun(s.Pool.QueryRow(ctx, `
		SELECT id, kind, status, cutoff_user_id, next_since_id,
		       next_url, enumeration_complete, enumerated_users,
		       processed_users, zero_key_users, key_owner_users,
		       inaccessible_users, error_users, started_at, completed_at
		FROM crawl_runs
		WHERE status = 'running'
		ORDER BY id
		LIMIT 1
	`))
}

type rowScanner interface {
	Scan(...any) error
}

func scanRun(row rowScanner) (Run, error) {
	var run Run
	err := row.Scan(
		&run.ID, &run.Kind, &run.Status, &run.CutoffUserID,
		&run.NextSinceID, &run.NextURL, &run.EnumerationComplete,
		&run.EnumeratedUsers, &run.ProcessedUsers,
		&run.ZeroKeyUsers, &run.KeyOwnerUsers, &run.InaccessibleUsers,
		&run.ErrorUsers,
		&run.StartedAt, &run.CompletedAt,
	)
	return run, err
}

func lockCrawlRuns(ctx context.Context, tx pgx.Tx, runIDs []int64) error {
	if len(runIDs) == 0 {
		return nil
	}
	unique := make(map[int64]struct{}, len(runIDs))
	ordered := make([]int64, 0, len(runIDs))
	for _, runID := range runIDs {
		if _, exists := unique[runID]; exists {
			continue
		}
		unique[runID] = struct{}{}
		ordered = append(ordered, runID)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	_, err := tx.Exec(ctx, `
		SELECT id FROM crawl_runs WHERE id = ANY($1) ORDER BY id FOR UPDATE
	`, ordered)
	return err
}

func (s *Store) ApplyEnumerationPage(
	ctx context.Context,
	run Run,
	candidates []model.Candidate,
	nextSince int64,
	nextURL string,
	complete bool,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockCrawlRuns(ctx, tx, []int64{run.ID}); err != nil {
		return err
	}
	inserted := int64(0)
	for _, candidate := range candidates {
		result, err := tx.Exec(ctx, `
			INSERT INTO account_queue (
			  run_id, source, github_id, node_id, login
			) VALUES ($1, 'global', $2, $3, $4)
			ON CONFLICT DO NOTHING
		`, run.ID, candidate.GitHubID, candidate.NodeID, candidate.Login)
		if err != nil {
			return err
		}
		inserted += result.RowsAffected()
	}
	if nextURL == "" {
		nextURL = run.NextURL
	}
	_, err = tx.Exec(ctx, `
		UPDATE crawl_runs
		SET next_since_id = GREATEST(next_since_id, $2),
		    next_url = $3,
		    enumeration_complete = enumeration_complete OR $4,
		    enumerated_users = enumerated_users + $5,
		    cutoff_user_id = CASE
		      WHEN kind = 'initial' AND $4 THEN COALESCE(cutoff_user_id, $2)
		      ELSE cutoff_user_id
		    END
		WHERE id = $1
	`, run.ID, nextSince, nextURL, complete, inserted)
	if err != nil {
		return err
	}
	if run.Kind == "initial" && complete {
		if err := setStateMaxIntTx(ctx, tx, "tail_highwater", nextSince); err != nil {
			return err
		}
		if err := setStateTx(ctx, tx, "initial_enumerated", "true"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) EnsureEnumerationShards(ctx context.Context, run Run, count int, urlFor func(int64) string) error {
	if run.CutoffUserID == nil || *run.CutoffUserID <= run.NextSinceID || count < 2 {
		return nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Shards are durable work units. On a crawler restart the active run is
	// loaded again, so do not create a second set from the moving run
	// checkpoint. The old implementation could create overlapping ranges
	// after one shard had advanced run.next_since_id, wasting REST quota.
	var existing int
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM enumeration_shards WHERE run_id = $1
	`, run.ID).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return tx.Commit(ctx)
	}
	span := (*run.CutoffUserID - run.NextSinceID) / int64(count)
	if span < 1 {
		span = 1
	}
	lower := run.NextSinceID
	for index := 0; index < count && lower < *run.CutoffUserID; index++ {
		upper := lower + span
		if index == count-1 || upper > *run.CutoffUserID {
			upper = *run.CutoffUserID
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO enumeration_shards (run_id, lower_id, upper_id, next_since_id, next_url)
			VALUES ($1, $2, $3, $2, $4) ON CONFLICT DO NOTHING
		`, run.ID, lower, upper, urlFor(lower)); err != nil {
			return err
		}
		lower = upper
	}
	return tx.Commit(ctx)
}

func (s *Store) ClaimEnumerationShard(ctx context.Context, runID int64) (EnumerationShard, error) {
	row := s.Pool.QueryRow(ctx, `
		WITH picked AS (
			SELECT id FROM enumeration_shards
			WHERE run_id = $1 AND status IN ('pending','retry')
			ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE enumeration_shards AS shard
		SET status='running', attempts=attempts+1, claimed_at=now(), last_error=NULL
		FROM picked WHERE shard.id=picked.id
		RETURNING shard.id, shard.run_id, shard.lower_id, shard.upper_id,
		          shard.next_since_id, shard.next_url, shard.attempts, shard.enumerated_users
	`, runID)
	var shard EnumerationShard
	err := row.Scan(&shard.ID, &shard.RunID, &shard.LowerID, &shard.UpperID,
		&shard.NextSinceID, &shard.NextURL, &shard.Attempts, &shard.EnumeratedUsers)
	return shard, err
}

func (s *Store) ApplyEnumerationShardPage(ctx context.Context, shard EnumerationShard, candidates []model.Candidate, nextSince int64, nextURL string, complete bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockCrawlRuns(ctx, tx, []int64{shard.RunID}); err != nil {
		return err
	}
	var inserted int64
	for _, candidate := range candidates {
		result, err := tx.Exec(ctx, `
			INSERT INTO account_queue (run_id, source, github_id, node_id, login)
			VALUES ($1, 'global', $2, $3, $4) ON CONFLICT DO NOTHING
		`, shard.RunID, candidate.GitHubID, candidate.NodeID, candidate.Login)
		if err != nil {
			return err
		}
		inserted += result.RowsAffected()
	}
	status := "running"
	if complete {
		status = "completed"
	}
	_, err = tx.Exec(ctx, `
		UPDATE enumeration_shards
		SET next_since_id=$2, next_url=$3, status=$4,
		    enumerated_users=enumerated_users+$5,
		    claimed_at=CASE WHEN $4='completed' THEN NULL ELSE claimed_at END,
		    completed_at=CASE WHEN $4='completed' THEN now() ELSE completed_at END
		WHERE id=$1
	`, shard.ID, nextSince, nextURL, status, inserted)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE crawl_runs SET next_since_id=GREATEST(next_since_id,$2), enumerated_users=enumerated_users+$3,
			enumeration_complete=CASE WHEN NOT EXISTS (
				SELECT 1 FROM enumeration_shards WHERE run_id=$1 AND status <> 'completed'
			) THEN true ELSE enumeration_complete END
		WHERE id=$1
	`, shard.RunID, nextSince, inserted)
	if err != nil {
		return err
	}
	if complete {
		_, err = tx.Exec(ctx, `
			INSERT INTO runtime_state (key, value) SELECT 'initial_enumerated', 'true'
			WHERE NOT EXISTS (SELECT 1 FROM enumeration_shards WHERE run_id=$1 AND status <> 'completed')
			ON CONFLICT (key) DO UPDATE SET value=excluded.value, updated_at=now()
		`, shard.RunID)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RebalanceOwnedEnumerationShard splits the unprocessed suffix of a shard
// owned by the caller when fewer than desired shards remain available. Only
// the owning worker calls this between pages, so changing its upper boundary
// cannot race with an in-flight request using the old boundary.
func (s *Store) RebalanceOwnedEnumerationShard(
	ctx context.Context,
	shard EnumerationShard,
	desired int,
	urlFor func(int64) string,
) (int64, error) {
	if desired < 2 {
		return shard.UpperID, nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return shard.UpperID, err
	}
	defer tx.Rollback(ctx)

	var nextSince, originalUpper int64
	var status string
	if err := tx.QueryRow(ctx, `
		SELECT next_since_id, upper_id, status
		FROM enumeration_shards
		WHERE id = $1 AND run_id = $2
		FOR UPDATE
	`, shard.ID, shard.RunID).Scan(&nextSince, &originalUpper, &status); err != nil {
		return shard.UpperID, err
	}
	if status != "running" {
		return originalUpper, tx.Commit(ctx)
	}

	var active int
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM enumeration_shards
		WHERE run_id = $1 AND status <> 'completed'
	`, shard.RunID).Scan(&active); err != nil {
		return originalUpper, err
	}
	missing := desired - active
	if missing <= 0 {
		return originalUpper, tx.Commit(ctx)
	}
	pieces := missing + 1
	remaining := originalUpper - nextSince
	// Avoid creating ranges smaller than one full REST page worth of IDs.
	if remaining < int64(pieces*100) {
		return originalUpper, tx.Commit(ctx)
	}
	step := remaining / int64(pieces)
	newUpper := nextSince + step
	if _, err := tx.Exec(ctx, `
		UPDATE enumeration_shards SET upper_id = $2 WHERE id = $1
	`, shard.ID, newUpper); err != nil {
		return originalUpper, err
	}
	for part := 1; part < pieces; part++ {
		lower := nextSince + step*int64(part)
		upper := nextSince + step*int64(part+1)
		if part == pieces-1 {
			upper = originalUpper
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO enumeration_shards (
			  run_id, lower_id, upper_id, next_since_id, next_url
			) VALUES ($1, $2, $3, $2, $4)
		`, shard.RunID, lower, upper, urlFor(lower)); err != nil {
			return originalUpper, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return originalUpper, err
	}
	return newUpper, nil
}

func (s *Store) RequeueEnumerationShard(ctx context.Context, shard EnumerationShard, cause error) error {
	_, err := s.Pool.Exec(ctx, `UPDATE enumeration_shards SET status='retry', claimed_at=NULL, last_error=$2, last_error_at=now() WHERE id=$1`, shard.ID, cause.Error())
	return err
}

func (s *Store) QueueDepth(ctx context.Context) (int, error) {
	var count int
	err := s.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM account_queue`).Scan(&count)
	return count, err
}

func (s *Store) QueueDepthByClass(ctx context.Context, class string) (int, error) {
	var count int
	err := s.Pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM account_queue
		WHERE CASE $1
		  WHEN 'global' THEN source = 'global'
		  WHEN 'live' THEN source IN ('tail', 'onboarding')
		  WHEN 'owner' THEN source = 'priority'
		  ELSE true
		END
	`, class).Scan(&count)
	return count, err
}

func (s *Store) ClaimAccounts(ctx context.Context, limit int, preferPriority bool) ([]model.Candidate, error) {
	preferred := "global"
	if preferPriority {
		preferred = "owner"
	}
	return s.ClaimScheduledAccounts(ctx, limit, preferred)
}

func (s *Store) ClaimScheduledAccounts(
	ctx context.Context,
	limit int,
	preferred string,
) ([]model.Candidate, error) {
	preferredSources := []string{"global"}
	switch preferred {
	case "live":
		preferredSources = []string{"tail", "onboarding"}
	case "owner":
		preferredSources = []string{"priority"}
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	result, err := claimAccountSources(ctx, tx, limit, preferredSources, false)
	if err != nil {
		return nil, err
	}
	if len(result) < limit {
		fallback, err := claimAccountSources(
			ctx, tx, limit-len(result), preferredSources, true,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, fallback...)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].QueueID < result[j].QueueID })
	return result, nil
}

func claimAccountSources(
	ctx context.Context,
	tx pgx.Tx,
	limit int,
	sources []string,
	exclude bool,
) ([]model.Candidate, error) {
	condition := "source = ANY($2::text[])"
	if exclude {
		condition = "NOT (source = ANY($2::text[]))"
	}
	rows, err := tx.Query(ctx, fmt.Sprintf(`
		WITH picked AS (
		  SELECT id
		  FROM account_queue
		  WHERE status IN ('pending', 'retry')
		    AND %s
		  ORDER BY id
		  FOR UPDATE SKIP LOCKED
		  LIMIT $1
		)
		UPDATE account_queue AS q
		SET status = 'running', attempts = attempts + 1,
		    claimed_at = now(), last_error = NULL, last_error_at = NULL
		FROM picked
		WHERE q.id = picked.id
		RETURNING q.id, q.run_id, q.source, q.github_id,
		          q.node_id, q.login, q.scan_id::text, q.attempts
	`, condition), limit, sources)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Candidate
	for rows.Next() {
		var item model.Candidate
		if err := rows.Scan(
			&item.QueueID, &item.RunID, &item.Source, &item.GitHubID,
			&item.NodeID, &item.Login, &item.ScanID, &item.Attempts,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) ApplyTailPage(
	ctx context.Context,
	candidates []model.Candidate,
	highwater int64,
	nextURL string,
	etag string,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, candidate := range candidates {
		if _, err := tx.Exec(ctx, `
			INSERT INTO account_queue (
			  source, github_id, node_id, login
			) VALUES ('tail', $1, $2, $3)
			ON CONFLICT DO NOTHING
		`, candidate.GitHubID, candidate.NodeID, candidate.Login); err != nil {
			return err
		}
	}
	if err := setStateMaxIntTx(ctx, tx, "tail_highwater", highwater); err != nil {
		return err
	}
	for key, value := range map[string]string{
		"tail_url":  nextURL,
		"tail_etag": etag,
	} {
		if err := setStateTx(ctx, tx, key, value); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) InitializeLiveTail(
	ctx context.Context,
	cutoff int64,
	tailURL string,
) (bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var initialized bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM runtime_state
		  WHERE key = 'live_tail_initialized' AND value = 'true'
		)
	`).Scan(&initialized); err != nil {
		return false, err
	}
	if initialized {
		return false, tx.Commit(ctx)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE crawl_runs
		SET cutoff_user_id = COALESCE(cutoff_user_id, $1)
		WHERE kind = 'initial' AND status = 'running'
	`, cutoff); err != nil {
		return false, err
	}
	for key, value := range map[string]string{
		"tail_highwater":        strconv.FormatInt(cutoff, 10),
		"tail_url":              tailURL,
		"tail_etag":             "",
		"live_tail_initialized": "true",
	} {
		if err := setStateTx(ctx, tx, key, value); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) CompleteAccounts(
	ctx context.Context,
	jobs []model.Candidate,
	results []*model.UserResult,
	ownerRefresh time.Duration,
) error {
	return s.CompleteAccountsScheduled(
		ctx, jobs, results, []time.Duration{ownerRefresh}, nil,
	)
}

func (s *Store) CompleteAccountsScheduled(
	ctx context.Context,
	jobs []model.Candidate,
	results []*model.UserResult,
	ownerSchedule []time.Duration,
	zeroKeyAges []time.Duration,
) error {
	if len(jobs) != len(results) {
		return errors.New("jobs/results length mismatch")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	runIDs := make([]int64, 0, len(jobs))
	for _, job := range jobs {
		if job.RunID != nil {
			runIDs = append(runIDs, *job.RunID)
		}
	}
	if err := lockCrawlRuns(ctx, tx, runIDs); err != nil {
		return err
	}
	for index, job := range jobs {
		result := results[index]
		if result == nil {
			if err := finishQueueRow(ctx, tx, job, "inaccessible"); err != nil {
				return err
			}
			continue
		}
		var ownerExists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM github_owners WHERE github_id = $1)`,
			job.GitHubID,
		).Scan(&ownerExists); err != nil {
			return err
		}
		if len(result.Keys) > 0 || ownerExists {
			if err := upsertOwner(
				ctx, tx, job, result.Login, scheduleDuration(ownerSchedule, 0),
			); err != nil {
				return err
			}
			for _, key := range result.Keys {
				if err := observeKey(ctx, tx, job.GitHubID, job.ScanID, key); err != nil {
					return err
				}
			}
			if result.HasMoreKeys {
				if result.NextCursor == "" {
					return fmt.Errorf("user %s has more keys but no cursor", result.Login)
				}
				_, err := tx.Exec(ctx, `
					INSERT INTO overflow_queue (
					  run_id, source, github_id, node_id, login,
					  scan_id, cursor
					) VALUES ($1, $2, $3, $4, $5, $6::uuid, $7)
					ON CONFLICT (source, github_id, scan_id)
					DO UPDATE SET cursor = excluded.cursor,
					              status = 'pending', last_error = NULL
				`, job.RunID, job.Source, job.GitHubID, result.NodeID,
					result.Login, job.ScanID, result.NextCursor)
				if err != nil {
					return err
				}
			} else if err := finalizeObservation(
				ctx, tx, job.GitHubID, job.ScanID, ownerSchedule,
			); err != nil {
				return err
			}
		}
		if len(result.Keys) > 0 || ownerExists {
			if _, err := tx.Exec(
				ctx, `DELETE FROM zero_key_rechecks WHERE github_id = $1`,
				job.GitHubID,
			); err != nil {
				return err
			}
		} else {
			switch job.Source {
			case "tail":
				if err := scheduleZeroKeyRecheck(
					ctx, tx, job, result.Login, zeroKeyAges,
				); err != nil {
					return err
				}
			case "onboarding":
				if err := advanceZeroKeyRecheck(
					ctx, tx, job.GitHubID, result.Login, zeroKeyAges,
				); err != nil {
					return err
				}
			}
		}
		classification := "zero"
		if len(result.Keys) > 0 {
			classification = "owner"
		}
		if err := finishQueueRow(ctx, tx, job, classification); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func upsertOwner(ctx context.Context, tx pgx.Tx, job model.Candidate, login string, refresh time.Duration) error {
	if login == "" {
		login = job.Login
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO github_owners (
		  github_id, node_id, login, first_seen_at, last_seen_at,
		  next_priority_scan_at, refresh_stage, last_changed_at, inaccessible
		) VALUES (
		  $1, $2, $3, now(), now(), now() + $4::interval,
		  0, now(), false
		)
		ON CONFLICT (github_id) DO UPDATE SET
		  node_id = excluded.node_id,
		  login = excluded.login,
		  last_seen_at = now(),
		  inaccessible = false
	`, job.GitHubID, job.NodeID, login, pgInterval(refresh))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE github_owner_logins
		SET currently_present = false
		WHERE github_id = $1 AND lower(login) <> lower($2)
	`, job.GitHubID, login); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO github_owner_logins (
		  github_id, login, first_seen_at, last_seen_at, currently_present
		) VALUES ($1, $2, now(), now(), true)
		ON CONFLICT (github_id, login) DO UPDATE SET
		  last_seen_at = now(), currently_present = true
	`, job.GitHubID, login)
	return err
}

func observeKey(ctx context.Context, tx pgx.Tx, githubID int64, scanID string, key model.PublicKey) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO ssh_keys (
		  fingerprint_sha256, fingerprint_text, key_type, public_key
		) VALUES ($1, $2, $3, $4)
		ON CONFLICT (fingerprint_sha256) DO UPDATE SET
		  fingerprint_text = excluded.fingerprint_text,
		  key_type = excluded.key_type,
		  public_key = excluded.public_key
	`, key.Fingerprint, key.Text, key.Type, key.Canonical); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO github_owner_keys (
		  github_id, fingerprint_sha256, first_seen_at, last_seen_at,
		  last_verified_at, currently_present, removed_at,
		  last_observation_scan, state_changed_scan
		) VALUES (
		  $1, $2, now(), now(), now(), true, NULL, $3::uuid, $3::uuid
		)
		ON CONFLICT (github_id, fingerprint_sha256) DO UPDATE SET
		  last_seen_at = now(),
		  last_verified_at = now(),
		  currently_present = true,
		  removed_at = NULL,
		  last_observation_scan = $3::uuid,
		  state_changed_scan = CASE
		    WHEN NOT github_owner_keys.currently_present THEN $3::uuid
		    ELSE github_owner_keys.state_changed_scan
		  END
	`, githubID, key.Fingerprint, scanID)
	return err
}

func finalizeObservation(
	ctx context.Context,
	tx pgx.Tx,
	githubID int64,
	scanID string,
	ownerSchedule []time.Duration,
) error {
	if _, err := tx.Exec(ctx, `
		UPDATE github_owner_keys
		SET currently_present = false,
		    removed_at = COALESCE(removed_at, now()),
		    last_verified_at = now(),
		    state_changed_scan = $2::uuid
		WHERE github_id = $1
		  AND currently_present
		  AND last_observation_scan <> $2::uuid
	`, githubID, scanID); err != nil {
		return err
	}
	var changed bool
	var currentStage int
	if err := tx.QueryRow(ctx, `
		SELECT
		  EXISTS (
		    SELECT 1
		    FROM github_owner_keys
		    WHERE github_id = $1 AND state_changed_scan = $2::uuid
		  ),
		  refresh_stage
		FROM github_owners
		WHERE github_id = $1
	`, githubID, scanID).Scan(&changed, &currentStage); err != nil {
		return err
	}
	nextStage := currentStage
	if changed {
		nextStage = 0
	} else if nextStage < len(ownerSchedule)-1 {
		nextStage++
	}
	refresh := scheduleDuration(ownerSchedule, nextStage)
	_, err := tx.Exec(ctx, `
		UPDATE github_owners
		SET last_verified_at = now(),
		    refresh_stage = $2,
		    last_changed_at = CASE WHEN $3 THEN now() ELSE last_changed_at END,
		    next_priority_scan_at =
		      now() + $4::interval +
		      make_interval(secs => mod(github_id, 900)::int)
		WHERE github_id = $1
	`, githubID, nextStage, changed, pgInterval(refresh))
	return err
}

func scheduleDuration(schedule []time.Duration, stage int) time.Duration {
	if len(schedule) == 0 {
		return 7 * 24 * time.Hour
	}
	if stage < 0 {
		stage = 0
	}
	if stage >= len(schedule) {
		stage = len(schedule) - 1
	}
	if schedule[stage] <= 0 {
		return 7 * 24 * time.Hour
	}
	return schedule[stage]
}

func scheduleZeroKeyRecheck(
	ctx context.Context,
	tx pgx.Tx,
	job model.Candidate,
	login string,
	ages []time.Duration,
) error {
	if len(ages) == 0 {
		return nil
	}
	if login == "" {
		login = job.Login
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO zero_key_rechecks (
		  github_id, node_id, login, stage, first_checked_at,
		  last_checked_at, next_scan_at, expires_at
		) VALUES (
		  $1, $2, $3, 0, now(), now(),
		  now() + $4::interval, now() + $5::interval
		)
		ON CONFLICT (github_id) DO UPDATE SET
		  node_id = excluded.node_id,
		  login = excluded.login,
		  last_checked_at = now()
	`, job.GitHubID, job.NodeID, login,
		pgInterval(ages[0]), pgInterval(ages[len(ages)-1]))
	return err
}

func advanceZeroKeyRecheck(
	ctx context.Context,
	tx pgx.Tx,
	githubID int64,
	login string,
	ages []time.Duration,
) error {
	if len(ages) == 0 {
		return nil
	}
	var stage int
	err := tx.QueryRow(ctx, `
		SELECT stage
		FROM zero_key_rechecks
		WHERE github_id = $1
		FOR UPDATE
	`, githubID).Scan(&stage)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if stage >= len(ages)-1 {
		_, err = tx.Exec(
			ctx, `DELETE FROM zero_key_rechecks WHERE github_id = $1`, githubID,
		)
		return err
	}
	nextStage := stage + 1
	_, err = tx.Exec(ctx, `
		UPDATE zero_key_rechecks
		SET stage = $2,
		    login = CASE WHEN $3 = '' THEN login ELSE $3 END,
		    last_checked_at = now(),
		    next_scan_at = GREATEST(
		      first_checked_at + $4::interval,
		      now() + interval '5 minutes'
		    )
		WHERE github_id = $1
	`, githubID, nextStage, login, pgInterval(ages[nextStage]))
	return err
}

func finishQueueRow(ctx context.Context, tx pgx.Tx, job model.Candidate, classification string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM account_queue WHERE id = $1`, job.QueueID); err != nil {
		return err
	}
	if job.RunID == nil {
		return nil
	}
	column := "zero_key_users"
	switch classification {
	case "owner":
		column = "key_owner_users"
	case "inaccessible":
		column = "inaccessible_users"
	}
	_, err := tx.Exec(ctx, fmt.Sprintf(`
		UPDATE crawl_runs
		SET processed_users = processed_users + 1,
		    %s = %s + 1
		WHERE id = $1
	`, column, column), *job.RunID)
	return err
}

func (s *Store) RequeueAccounts(ctx context.Context, jobs []model.Candidate, cause error) error {
	ids := make([]int64, 0, len(jobs))
	for _, job := range jobs {
		ids = append(ids, job.QueueID)
	}
	_, err := s.Pool.Exec(ctx, `
		UPDATE account_queue
		SET status = 'retry', claimed_at = NULL, last_error = $2,
		    last_error_at = now()
		WHERE id = ANY($1)
	`, ids, cause.Error())
	return err
}

func (s *Store) ClaimOverflow(ctx context.Context) (*model.OverflowJob, error) {
	var job model.OverflowJob
	err := s.Pool.QueryRow(ctx, `
		WITH picked AS (
		  SELECT id FROM overflow_queue
		  WHERE status IN ('pending', 'retry')
		  ORDER BY CASE source
		             WHEN 'tail' THEN 0
		             WHEN 'priority' THEN 1
		             ELSE 2
		           END, id
		  FOR UPDATE SKIP LOCKED
		  LIMIT 1
		)
		UPDATE overflow_queue AS q
		SET status = 'running', attempts = attempts + 1,
		    claimed_at = now(), last_error = NULL, last_error_at = NULL
		FROM picked
		WHERE q.id = picked.id
		RETURNING q.id, q.run_id, q.source, q.github_id,
		          q.node_id, q.login, q.scan_id::text, q.cursor, q.attempts
	`).Scan(
		&job.ID, &job.RunID, &job.Source, &job.GitHubID,
		&job.NodeID, &job.Login, &job.ScanID, &job.Cursor, &job.Attempts,
	)
	if err != nil {
		return nil, err
	}
	return &job, nil
}

func (s *Store) CompleteOverflow(
	ctx context.Context,
	job model.OverflowJob,
	keys []model.PublicKey,
	hasMore bool,
	nextCursor string,
	ownerRefresh time.Duration,
) error {
	return s.CompleteOverflowScheduled(
		ctx, job, keys, hasMore, nextCursor,
		[]time.Duration{ownerRefresh},
	)
}

func (s *Store) CompleteOverflowScheduled(
	ctx context.Context,
	job model.OverflowJob,
	keys []model.PublicKey,
	hasMore bool,
	nextCursor string,
	ownerSchedule []time.Duration,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, key := range keys {
		if err := observeKey(ctx, tx, job.GitHubID, job.ScanID, key); err != nil {
			return err
		}
	}
	if hasMore {
		if nextCursor == "" {
			return errors.New("overflow response has no next cursor")
		}
		_, err = tx.Exec(ctx, `
			UPDATE overflow_queue
			SET cursor = $2, status = 'pending', claimed_at = NULL
			WHERE id = $1
		`, job.ID, nextCursor)
	} else {
		if err = finalizeObservation(
			ctx, tx, job.GitHubID, job.ScanID, ownerSchedule,
		); err == nil {
			_, err = tx.Exec(ctx, `DELETE FROM overflow_queue WHERE id = $1`, job.ID)
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RequeueOverflow(ctx context.Context, job model.OverflowJob, cause error) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE overflow_queue
		SET status = 'retry', claimed_at = NULL, last_error = $2,
		    last_error_at = now()
		WHERE id = $1
	`, job.ID, cause.Error())
	return err
}

func (s *Store) MaybeCompleteMain(ctx context.Context) (bool, error) {
	run, err := s.ActiveMainRun(ctx)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if !run.EnumerationComplete {
		return false, nil
	}
	var pending int
	err = s.Pool.QueryRow(ctx, `
		SELECT
		  (SELECT COUNT(*) FROM account_queue WHERE run_id = $1) +
		  (SELECT COUNT(*) FROM overflow_queue WHERE run_id = $1)
	`, run.ID).Scan(&pending)
	if err != nil || pending != 0 {
		return false, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
		UPDATE crawl_runs
		SET status = 'completed', completed_at = now()
		WHERE id = $1 AND status = 'running'
	`, run.ID)
	if err != nil {
		return false, err
	}
	if run.Kind == "initial" {
		if err := setStateTx(ctx, tx, "initial_complete", "true"); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) Enqueue(ctx context.Context, source string, candidates []model.Candidate) (int64, error) {
	if source != "tail" && source != "priority" && source != "onboarding" {
		return 0, errors.New("invalid non-global queue source")
	}
	var inserted int64
	for _, candidate := range candidates {
		tag, err := s.Pool.Exec(ctx, `
			INSERT INTO account_queue (
			  source, github_id, node_id, login
			) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING
		`, source, candidate.GitHubID, candidate.NodeID, candidate.Login)
		if err != nil {
			return inserted, err
		}
		inserted += tag.RowsAffected()
	}
	return inserted, nil
}

func (s *Store) EnqueueDueZeroKeyRechecks(ctx context.Context, limit int) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `
		INSERT INTO account_queue (source, github_id, node_id, login)
		SELECT 'onboarding', z.github_id, z.node_id, z.login
		FROM zero_key_rechecks AS z
		WHERE z.next_scan_at <= now()
		  AND NOT EXISTS (
		    SELECT 1 FROM account_queue AS q
		    WHERE q.github_id = z.github_id
		  )
		ORDER BY z.next_scan_at, z.github_id
		LIMIT $1
		ON CONFLICT DO NOTHING
	`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) EnqueueDueOwners(ctx context.Context, limit int) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `
		INSERT INTO account_queue (source, github_id, node_id, login)
		SELECT 'priority', o.github_id, o.node_id, o.login
		FROM github_owners AS o
		WHERE o.next_priority_scan_at <= now()
		  AND NOT EXISTS (
		    SELECT 1 FROM account_queue AS q
		    WHERE q.github_id = o.github_id
		  )
		ORDER BY o.next_priority_scan_at, o.github_id
		LIMIT $1
		ON CONFLICT DO NOTHING
	`, limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) State(ctx context.Context, key string) (string, error) {
	var value string
	err := s.Pool.QueryRow(ctx, `SELECT value FROM runtime_state WHERE key = $1`, key).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func (s *Store) StateInt(ctx context.Context, key string) (int64, error) {
	value, err := s.State(ctx, key)
	if err != nil || value == "" {
		return 0, err
	}
	return strconv.ParseInt(value, 10, 64)
}

func (s *Store) SetState(ctx context.Context, key, value string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO runtime_state (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET
		  value = excluded.value, updated_at = now()
	`, key, value)
	return err
}

func setStateTx(ctx context.Context, tx pgx.Tx, key, value string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO runtime_state (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET
		  value = excluded.value, updated_at = now()
	`, key, value)
	return err
}

func setStateMaxIntTx(ctx context.Context, tx pgx.Tx, key string, value int64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO runtime_state (key, value)
		VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET
		  value = GREATEST(
		    runtime_state.value::bigint,
		    excluded.value::bigint
		  )::text,
		  updated_at = now()
	`, key, strconv.FormatInt(value, 10))
	return err
}

func (s *Store) Lookup(ctx context.Context, fingerprint string) ([]Match, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT o.github_id, o.login,
		       'https://github.com/' || o.login,
		       ok.first_seen_at, ok.last_seen_at, ok.last_verified_at,
		       ok.currently_present, ok.removed_at
		FROM ssh_keys AS k
		JOIN github_owner_keys AS ok
		  ON ok.fingerprint_sha256 = k.fingerprint_sha256
		JOIN github_owners AS o ON o.github_id = ok.github_id
		WHERE k.fingerprint_text = $1
		ORDER BY ok.currently_present DESC, lower(o.login)
	`, fingerprint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	matches := make([]Match, 0)
	for rows.Next() {
		var match Match
		if err := rows.Scan(
			&match.GitHubID, &match.Login, &match.ProfileURL,
			&match.FirstSeenAt, &match.LastSeenAt, &match.LastVerifiedAt,
			&match.CurrentlyPresent, &match.RemovedAt,
		); err != nil {
			return nil, err
		}
		aliases, err := s.aliases(ctx, match.GitHubID)
		if err != nil {
			return nil, err
		}
		match.Aliases = aliases
		matches = append(matches, match)
	}
	return matches, rows.Err()
}

func (s *Store) aliases(ctx context.Context, githubID int64) ([]Alias, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT login, first_seen_at, last_seen_at, currently_present
		FROM github_owner_logins
		WHERE github_id = $1
		ORDER BY first_seen_at, lower(login)
	`, githubID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	aliases := make([]Alias, 0)
	for rows.Next() {
		var alias Alias
		if err := rows.Scan(
			&alias.Login, &alias.FirstSeenAt, &alias.LastSeenAt,
			&alias.CurrentlyPresent,
		); err != nil {
			return nil, err
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

func (s *Store) SnapshotTime(ctx context.Context) (time.Time, error) {
	var snapshot time.Time
	err := s.Pool.QueryRow(ctx, `SELECT statement_timestamp()`).Scan(&snapshot)
	return snapshot.UTC(), err
}

func (s *Store) ListIndexedUsers(
	ctx context.Context, afterID int64, snapshot time.Time, limit int,
) ([]IndexedUser, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT github_id, login, 'https://github.com/' || login,
		       first_seen_at, last_seen_at, last_verified_at, inaccessible
		FROM github_owners
		WHERE github_id > $1
		  AND first_seen_at <= $2
		ORDER BY github_id
		LIMIT $3
	`, afterID, snapshot, limit)
	if err != nil {
		return nil, err
	}
	users := make([]IndexedUser, 0, limit)
	ids := make([]int64, 0, limit)
	positions := make(map[int64]int, limit)
	for rows.Next() {
		var user IndexedUser
		if err := rows.Scan(
			&user.GitHubID, &user.Login, &user.ProfileURL,
			&user.FirstSeenAt, &user.LastSeenAt, &user.LastVerifiedAt,
			&user.Inaccessible,
		); err != nil {
			rows.Close()
			return nil, err
		}
		user.Keys = make([]IndexedKey, 0)
		positions[user.GitHubID] = len(users)
		ids = append(ids, user.GitHubID)
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(ids) == 0 {
		return users, nil
	}
	keyRows, err := s.Pool.Query(ctx, `
		SELECT ok.github_id, k.fingerprint_text, k.key_type, k.public_key,
		       ok.first_seen_at, ok.last_seen_at, ok.last_verified_at,
		       ok.currently_present, ok.removed_at
		FROM github_owner_keys AS ok
		JOIN ssh_keys AS k
		  ON k.fingerprint_sha256 = ok.fingerprint_sha256
		WHERE ok.github_id = ANY($1)
		ORDER BY ok.github_id, ok.currently_present DESC, k.fingerprint_text
	`, ids)
	if err != nil {
		return nil, err
	}
	defer keyRows.Close()
	for keyRows.Next() {
		var githubID int64
		var key IndexedKey
		if err := keyRows.Scan(
			&githubID, &key.Fingerprint, &key.Type, &key.PublicKey,
			&key.FirstSeenAt, &key.LastSeenAt, &key.LastVerifiedAt,
			&key.CurrentlyPresent, &key.RemovedAt,
		); err != nil {
			return nil, err
		}
		if position, ok := positions[githubID]; ok {
			users[position].Keys = append(users[position].Keys, key)
		}
	}
	return users, keyRows.Err()
}

func (s *Store) Status(ctx context.Context) (map[string]any, error) {
	var owners, keys, associations, currentAssociations, queued, overflow int64
	err := s.Pool.QueryRow(ctx, `
		SELECT
		  COALESCE(MAX(n_live_tup) FILTER (WHERE relname = 'github_owners'), 0),
		  COALESCE(MAX(n_live_tup) FILTER (WHERE relname = 'ssh_keys'), 0),
		  COALESCE(MAX(n_live_tup) FILTER (WHERE relname = 'github_owner_keys'), 0),
		  COALESCE(MAX(n_live_tup) FILTER (WHERE relname = 'github_owner_keys'), 0),
		  COALESCE(MAX(n_live_tup) FILTER (WHERE relname = 'account_queue'), 0),
		  COALESCE(MAX(n_live_tup) FILTER (WHERE relname = 'overflow_queue'), 0)
		FROM pg_stat_user_tables
		WHERE relname IN (
		  'github_owners', 'ssh_keys', 'github_owner_keys',
		  'account_queue', 'overflow_queue'
		)
	`).Scan(&owners, &keys, &associations, &currentAssociations, &queued, &overflow)
	if err != nil {
		return nil, err
	}
	var zeroKeyRechecks, dueZeroKeyRechecks int64
	var dueZeroKeyRechecksCapped bool
	var oldestDueZeroKeyAt *time.Time
	if err := s.Pool.QueryRow(ctx, `
		SELECT COALESCE(n_live_tup, 0)
		FROM pg_stat_user_tables
		WHERE relname = 'zero_key_rechecks'
	`).Scan(&zeroKeyRechecks); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	// A status request must never count an unbounded due queue. The first 10,001
	// index entries tell us the exact count up to 10,000, or a useful lower bound.
	if err := s.Pool.QueryRow(ctx, `
		SELECT COUNT(*), MIN(next_scan_at)
		FROM (
		  SELECT next_scan_at
		  FROM zero_key_rechecks
		  WHERE next_scan_at <= now()
		  ORDER BY next_scan_at, github_id
		  LIMIT 10001
		) AS due
	`).Scan(&dueZeroKeyRechecks, &oldestDueZeroKeyAt); err != nil {
		return nil, err
	}
	if dueZeroKeyRechecks > 10000 {
		dueZeroKeyRechecks = 10000
		dueZeroKeyRechecksCapped = true
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, kind, status, cutoff_user_id, next_since_id,
		       next_url, enumeration_complete, enumerated_users,
		       processed_users, zero_key_users, key_owner_users,
		       inaccessible_users, error_users, started_at, completed_at
		FROM crawl_runs ORDER BY id DESC LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := make([]Run, 0)
	for rows.Next() {
		run, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	shardStatus := map[string]any{
		"count":     0,
		"completed": 0,
		"remaining": 0,
		"ranges":    []map[string]any{},
	}
	if len(runs) > 0 {
		shardRows, err := s.Pool.Query(ctx, `
			SELECT id, lower_id, upper_id, next_since_id, status,
			       enumerated_users, attempts
			FROM enumeration_shards
			WHERE run_id = $1
			ORDER BY lower_id, id
		`, runs[0].ID)
		if err != nil {
			return nil, err
		}
		var ranges []map[string]any
		completed := 0
		remaining := 0
		for shardRows.Next() {
			var id, lowerID, upperID, nextSince, enumerated int64
			var status string
			var attempts int
			if err := shardRows.Scan(
				&id, &lowerID, &upperID, &nextSince, &status,
				&enumerated, &attempts,
			); err != nil {
				shardRows.Close()
				return nil, err
			}
			if status == "completed" {
				completed++
			} else {
				remaining++
			}
			ranges = append(ranges, map[string]any{
				"id": id, "lower_id": lowerID, "upper_id": upperID,
				"next_since_id": nextSince, "status": status,
				"enumerated_users": enumerated, "attempts": attempts,
			})
		}
		if err := shardRows.Err(); err != nil {
			shardRows.Close()
			return nil, err
		}
		shardRows.Close()
		shardStatus = map[string]any{
			"count": len(ranges), "completed": completed,
			"remaining": remaining, "ranges": ranges,
		}
	}
	queueRows, err := s.Pool.Query(ctx, `
		SELECT source, status, COUNT(*)
		FROM account_queue
		WHERE status IN ('running', 'retry')
		GROUP BY source, status
		ORDER BY source, status
	`)
	if err != nil {
		return nil, err
	}
	queueBreakdown := make(map[string]map[string]int64)
	for queueRows.Next() {
		var source, state string
		var count int64
		if err := queueRows.Scan(&source, &state, &count); err != nil {
			queueRows.Close()
			return nil, err
		}
		if queueBreakdown[source] == nil {
			queueBreakdown[source] = make(map[string]int64)
		}
		queueBreakdown[source][state] = count
	}
	if err := queueRows.Err(); err != nil {
		queueRows.Close()
		return nil, err
	}
	queueRows.Close()
	var retryingJobs, runningJobs int64
	var maximumAttempts int
	var oldestJobAt *time.Time
	if err := s.Pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE status = 'retry'),
		  COUNT(*) FILTER (WHERE status = 'running'),
		  COALESCE(MAX(attempts), 0)
		FROM (
		  SELECT status, attempts FROM account_queue
		  WHERE status IN ('running', 'retry')
		  UNION ALL
		  SELECT status, attempts FROM overflow_queue
		  WHERE status IN ('running', 'retry')
		) AS jobs
	`).Scan(
		&retryingJobs, &runningJobs, &maximumAttempts,
	); err != nil {
		return nil, err
	}
	if err := s.Pool.QueryRow(ctx, `
		SELECT MIN(created_at)
		FROM (
		  (SELECT created_at FROM account_queue ORDER BY id LIMIT 1)
		  UNION ALL
		  (SELECT created_at FROM overflow_queue ORDER BY id LIMIT 1)
		) AS oldest
	`).Scan(&oldestJobAt); err != nil {
		return nil, err
	}
	var latestQueueError *string
	var latestQueueErrorAt *time.Time
	err = s.Pool.QueryRow(ctx, `
		SELECT last_error, last_error_at
		FROM (
		  SELECT last_error, last_error_at FROM account_queue
		  WHERE status = 'retry' AND last_error IS NOT NULL
		  UNION ALL
		  SELECT last_error, last_error_at FROM overflow_queue
		  WHERE status = 'retry' AND last_error IS NOT NULL
		) AS errors
		ORDER BY last_error_at DESC NULLS LAST
		LIMIT 1
	`).Scan(&latestQueueError, &latestQueueErrorAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	workerRows, err := s.Pool.Query(ctx, `
		SELECT name, role, state, activity, processed_users, processed_keys,
		       requests, rate_remaining, rate_limit, rate_reset_at,
		       last_success_at, last_error, last_error_at, started_at, heartbeat_at
		FROM crawler_workers
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	workers := make([]WorkerStatus, 0)
	for workerRows.Next() {
		var worker WorkerStatus
		if err := workerRows.Scan(
			&worker.Name, &worker.Role, &worker.State, &worker.Activity,
			&worker.ProcessedUsers, &worker.ProcessedKeys, &worker.Requests,
			&worker.RateRemaining, &worker.RateLimit, &worker.RateResetAt,
			&worker.LastSuccessAt, &worker.LastError, &worker.LastErrorAt,
			&worker.StartedAt, &worker.HeartbeatAt,
		); err != nil {
			workerRows.Close()
			return nil, err
		}
		workers = append(workers, worker)
	}
	if err := workerRows.Err(); err != nil {
		workerRows.Close()
		return nil, err
	}
	workerRows.Close()
	now := time.Now()
	activeWorkers := 0
	staleWorkers := 0
	var latestHeartbeat *time.Time
	var sessionStartedAt *time.Time
	var sessionLastSuccessAt *time.Time
	var sessionProcessedUsers int64
	for index := range workers {
		worker := workers[index]
		if latestHeartbeat == nil || worker.HeartbeatAt.After(*latestHeartbeat) {
			value := worker.HeartbeatAt
			latestHeartbeat = &value
		}
		if worker.State == "stopped" {
			// Stopped workers still provide the last completed session's
			// throughput, but do not count toward crawler liveness.
		} else if worker.State == "running" && worker.Name != "scheduler" {
			if now.Sub(worker.HeartbeatAt) <= 90*time.Second {
				activeWorkers++
			} else {
				staleWorkers++
			}
		}
		if worker.Role != "SSH key batch worker" {
			continue
		}
		sessionProcessedUsers += worker.ProcessedUsers
		if sessionStartedAt == nil || worker.StartedAt.Before(*sessionStartedAt) {
			value := worker.StartedAt
			sessionStartedAt = &value
		}
		if worker.LastSuccessAt != nil &&
			(sessionLastSuccessAt == nil || worker.LastSuccessAt.After(*sessionLastSuccessAt)) {
			value := *worker.LastSuccessAt
			sessionLastSuccessAt = &value
		}
	}
	var sessionUsersPerHour float64
	var sessionElapsedHours float64
	if sessionStartedAt != nil && sessionLastSuccessAt != nil &&
		sessionLastSuccessAt.After(*sessionStartedAt) {
		sessionElapsedHours = sessionLastSuccessAt.Sub(*sessionStartedAt).Hours()
		sessionUsersPerHour = float64(sessionProcessedUsers) / sessionElapsedHours
	}
	highwater, _ := s.StateInt(ctx, "tail_highwater")
	initialComplete, _ := s.State(ctx, "initial_complete")
	liveTailInitialized, _ := s.State(ctx, "live_tail_initialized")
	estimatedLow, _ := s.StateInt(ctx, "estimated_accounts_low")
	estimatedHigh, _ := s.StateInt(ctx, "estimated_accounts_high")
	if estimatedLow <= 0 {
		estimatedLow = 190_000_000
	}
	if estimatedHigh < estimatedLow {
		estimatedHigh = 220_000_000
	}
	progress := map[string]any{
		"phase":                     "starting",
		"percentage":                nil,
		"percentage_available_when": "account enumeration for the active run is complete",
	}
	if len(runs) > 0 {
		active := runs[0]
		if active.Status == "running" {
			progress["phase"] = active.Kind + "_scan"
		} else {
			progress["phase"] = "between_runs"
		}
		progress["run_id"] = active.ID
		progress["enumerated_users"] = active.EnumeratedUsers
		progress["processed_users"] = active.ProcessedUsers
		progress["checkpoint_user_id"] = active.NextSinceID
		progress["enumeration_complete"] = active.EnumerationComplete
		elapsed := time.Since(active.StartedAt).Hours()
		if active.CompletedAt != nil {
			elapsed = active.CompletedAt.Sub(active.StartedAt).Hours()
		}
		if elapsed > 0 {
			wallClockAverage := float64(active.ProcessedUsers) / elapsed
			progress["wall_clock_users_per_hour"] = wallClockAverage
			if sessionUsersPerHour > 0 {
				progress["current_session_users_per_hour"] = sessionUsersPerHour
				progress["current_session_elapsed_hours"] = sessionElapsedHours
			}
			etaRate := sessionUsersPerHour
			rateBasis := "current crawler session, including throttling and cooldowns during that session"
			if etaRate <= 0 {
				etaRate = wallClockAverage
				rateBasis = "wall-clock average since run start, including downtime and throttling"
			}
			if etaRate > 0 {
				lowTotal, highTotal := estimatedLow, estimatedHigh
				basis := "planning population envelope"
				if active.EnumerationComplete && active.EnumeratedUsers > 0 {
					lowTotal = active.EnumeratedUsers
					highTotal = active.EnumeratedUsers
					basis = "exact users enumerated for this run"
				}
				lowRemaining := max(int64(0), lowTotal-active.ProcessedUsers)
				highRemaining := max(int64(0), highTotal-active.ProcessedUsers)
				lowHours := float64(lowRemaining) / etaRate
				highHours := float64(highRemaining) / etaRate
				progress["estimated_completion"] = map[string]any{
					"basis":                  basis,
					"rate_basis":             rateBasis,
					"rate_users_per_hour":    etaRate,
					"rate_is_preliminary":    sessionElapsedHours > 0 && sessionElapsedHours < 6,
					"paused":                 activeWorkers == 0,
					"estimated_total_low":    lowTotal,
					"estimated_total_high":   highTotal,
					"remaining_hours_low":    lowHours,
					"remaining_hours_high":   highHours,
					"estimated_finish_early": now.Add(time.Duration(lowHours * float64(time.Hour))),
					"estimated_finish_late":  now.Add(time.Duration(highHours * float64(time.Hour))),
					"exact":                  basis == "exact users enumerated for this run",
				}
			}
		}
		if active.EnumerationComplete && active.EnumeratedUsers > 0 {
			percentage := 100 * float64(active.ProcessedUsers) / float64(active.EnumeratedUsers)
			if percentage > 100 {
				percentage = 100
			}
			progress["percentage"] = percentage
			delete(progress, "percentage_available_when")
		}
	}
	recoveryState := "healthy"
	recoveryMessage := "crawler is active and no jobs are awaiting retry"
	if activeWorkers == 0 {
		recoveryState = "offline"
		recoveryMessage = "crawler is not active; persisted checkpoints and queued jobs remain resumable"
	} else if staleWorkers > 0 {
		recoveryState = "stalled"
		recoveryMessage = "one or more workers have stale heartbeats"
	} else if retryingJobs > 0 {
		recoveryState = "recovering"
		recoveryMessage = "crawler is active and retrying persisted jobs"
	}
	var oldestJobAgeSeconds *int64
	if oldestJobAt != nil {
		age := int64(now.Sub(*oldestJobAt).Seconds())
		if age < 0 {
			age = 0
		}
		oldestJobAgeSeconds = &age
	}
	pacing := make(map[string]any)
	for _, resource := range []string{"rest", "graphql"} {
		raw, _ := s.State(ctx, resource+"_pacer")
		if raw == "" {
			continue
		}
		var value any
		if json.Unmarshal([]byte(raw), &value) == nil {
			pacing[resource] = value
		}
	}
	schedulerAllocation, _ := s.State(ctx, "scheduler_allocation")
	ownerSchedule, _ := s.State(ctx, "owner_refresh_schedule")
	zeroKeySchedule, _ := s.State(ctx, "zero_key_retry_ages")
	return map[string]any{
		"count_accuracy": map[string]any{
			"index_and_queue_totals": "PostgreSQL live-row estimates; refreshed by autovacuum/analyze",
			"active_and_retry_jobs":  "exact",
			"progress_and_workers":   "exact",
		},
		"index": map[string]int64{
			"owners": owners, "keys": keys, "associations": associations,
			"current_associations": currentAssociations,
		},
		"queue": map[string]any{
			"accounts": queued, "overflow": overflow, "by_source_and_state": queueBreakdown,
			"counts_approximate": true,
			"breakdown_scope":    "running and retry jobs only",
			"zero_key_rechecks": map[string]any{
				"tracked":       zeroKeyRechecks,
				"due":           dueZeroKeyRechecks,
				"due_capped":    dueZeroKeyRechecksCapped,
				"oldest_due_at": oldestDueZeroKeyAt,
			},
		},
		"coverage": map[string]any{
			"initial_complete":      initialComplete == "true",
			"live_tail_initialized": liveTailInitialized == "true",
			"tail_highwater":        highwater,
			"historical_retention":  "observed keys and account associations are retained permanently",
			"scope":                 "public GitHub SSH authentication keys observable through the API",
		},
		"progress": progress,
		"enumeration": map[string]any{
			"checkpoint_meaning": "furthest parallel shard position; inspect ranges for contiguous coverage",
			"shards":             shardStatus,
		},
		"recovery": map[string]any{
			"state":                  recoveryState,
			"message":                recoveryMessage,
			"durable_checkpoint":     true,
			"restart_recovery":       "running jobs are changed to retry when the crawler starts",
			"retrying_jobs":          retryingJobs,
			"running_jobs":           runningJobs,
			"maximum_attempts":       maximumAttempts,
			"oldest_job_at":          oldestJobAt,
			"oldest_job_age_seconds": oldestJobAgeSeconds,
			"latest_queue_error":     latestQueueError,
			"latest_queue_error_at":  latestQueueErrorAt,
		},
		"pacing": pacing,
		"scheduler": map[string]any{
			"algorithm":              "weighted earliest-deadline-first",
			"allocation":             schedulerAllocation,
			"owner_refresh_schedule": ownerSchedule,
			"zero_key_retry_ages":    zeroKeySchedule,
		},
		"crawler": map[string]any{
			"online":            activeWorkers > 0,
			"active_workers":    activeWorkers,
			"stale_workers":     staleWorkers,
			"registered":        len(workers),
			"last_heartbeat_at": latestHeartbeat,
		},
		"workers": workers,
		"runs":    runs,
	}, nil
}

func pgInterval(duration time.Duration) string {
	seconds := int64(duration.Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%d seconds", seconds)
}

func JSON(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}
