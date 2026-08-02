package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/local/github-ssh-index/internal/model"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	Pool *pgxpool.Pool
}

type Run struct {
	ID                   int64      `json:"id"`
	Kind                 string     `json:"kind"`
	Status               string     `json:"status"`
	CutoffUserID         *int64     `json:"cutoff_user_id"`
	NextSinceID          int64      `json:"next_since_id"`
	NextURL              string     `json:"next_url"`
	EnumerationComplete  bool       `json:"enumeration_complete"`
	EnumeratedUsers      int64      `json:"enumerated_users"`
	ProcessedUsers       int64      `json:"processed_users"`
	ZeroKeyUsers         int64      `json:"zero_key_users"`
	KeyOwnerUsers        int64      `json:"key_owner_users"`
	InaccessibleUsers    int64      `json:"inaccessible_users"`
	ErrorUsers           int64      `json:"error_users"`
	CoverageVersion      int16      `json:"coverage_version"`
	CoverageGenerationID *int64     `json:"coverage_generation_id,omitempty"`
	SettledCutoff        *time.Time `json:"settled_cutoff,omitempty"`
	StartedAt            time.Time  `json:"started_at"`
	CompletedAt          *time.Time `json:"completed_at,omitempty"`
}

type EnumerationShard struct {
	ID                   int64
	RunID                int64
	LowerID              int64
	UpperID              int64
	NextSinceID          int64
	NextURL              string
	Attempts             int
	EnumeratedUsers      int64
	CoverageGenerationID *int64
}

const coverageChunkSize int64 = 8192

func coverageBitField(field string) (string, error) {
	switch field {
	case "discovered_bits", "successful_bits", "inaccessible_bits":
		return field, nil
	default:
		return "", fmt.Errorf("invalid coverage bitmap field %q", field)
	}
}

func setCoverageBitsTx(
	ctx context.Context,
	tx pgx.Tx,
	generationID *int64,
	field string,
	githubIDs []int64,
) ([]int64, error) {
	if generationID == nil || len(githubIDs) == 0 {
		return nil, nil
	}
	field, err := coverageBitField(field)
	if err != nil {
		return nil, err
	}
	chunks := make(map[int64][]int64)
	for _, githubID := range githubIDs {
		if githubID <= 0 {
			return nil, fmt.Errorf("invalid GitHub ID for coverage ledger: %d", githubID)
		}
		chunk := githubID / coverageChunkSize
		chunks[chunk] = append(chunks[chunk], githubID)
	}
	chunkNumbers := make([]int64, 0, len(chunks))
	for chunk := range chunks {
		chunkNumbers = append(chunkNumbers, chunk)
	}
	sort.Slice(chunkNumbers, func(i, j int) bool { return chunkNumbers[i] < chunkNumbers[j] })
	changed := make([]int64, 0, len(githubIDs))
	for _, chunk := range chunkNumbers {
		if _, err := tx.Exec(ctx, `
			INSERT INTO coverage_bitmap_chunks (generation_id, chunk_no)
			VALUES ($1, $2) ON CONFLICT DO NOTHING
		`, *generationID, chunk); err != nil {
			return nil, err
		}
		var current string
		if err := tx.QueryRow(ctx, fmt.Sprintf(`
			SELECT %s::text FROM coverage_bitmap_chunks
			WHERE generation_id=$1 AND chunk_no=$2 FOR UPDATE
		`, field), *generationID, chunk).Scan(&current); err != nil {
			return nil, err
		}
		if len(current) != int(coverageChunkSize) {
			return nil, fmt.Errorf("coverage chunk %d has %d bits", chunk, len(current))
		}
		updated := []byte(current)
		for _, githubID := range chunks[chunk] {
			offset := githubID % coverageChunkSize
			if updated[offset] == '0' {
				updated[offset] = '1'
				changed = append(changed, githubID)
			}
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`
			UPDATE coverage_bitmap_chunks
			SET %s=$3::bit(8192), updated_at=now()
			WHERE generation_id=$1 AND chunk_no=$2
		`, field), *generationID, chunk, string(updated)); err != nil {
			return nil, err
		}
	}
	return changed, nil
}

func markCoverageDiscoveredTx(
	ctx context.Context, tx pgx.Tx, generationID *int64, githubIDs []int64,
) error {
	changed, err := setCoverageBitsTx(
		ctx, tx, generationID, "discovered_bits", githubIDs,
	)
	if err != nil || len(changed) == 0 || generationID == nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE coverage_generations
		SET discovered_accounts=discovered_accounts+$2
		WHERE id=$1
	`, *generationID, len(changed))
	return err
}

func markCoverageSuccessfulTx(
	ctx context.Context,
	tx pgx.Tx,
	generationID *int64,
	createdAt map[int64]time.Time,
) error {
	ids := make([]int64, 0, len(createdAt))
	for id := range createdAt {
		ids = append(ids, id)
	}
	changed, err := setCoverageBitsTx(
		ctx, tx, generationID, "successful_bits", ids,
	)
	if err != nil || len(changed) == 0 || generationID == nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_generations
		SET successful_accounts=successful_accounts+$2
		WHERE id=$1
	`, *generationID, len(changed)); err != nil {
		return err
	}
	perDay := make(map[time.Time]int64)
	for _, id := range changed {
		created := createdAt[id]
		if created.IsZero() {
			return fmt.Errorf("successful GitHub account %d has no creation time", id)
		}
		day := created.UTC().Truncate(24 * time.Hour)
		perDay[day]++
	}
	for day, count := range perDay {
		if _, err := tx.Exec(ctx, `
			INSERT INTO coverage_day_counts (
			  generation_id, day, successful_accounts
			) VALUES ($1, $2, $3)
			ON CONFLICT (generation_id, day) DO UPDATE SET
			  successful_accounts = coverage_day_counts.successful_accounts + excluded.successful_accounts
		`, *generationID, day, count); err != nil {
			return err
		}
	}
	return nil
}

func markCoverageInaccessibleTx(
	ctx context.Context, tx pgx.Tx, generationID *int64, ids []int64,
) error {
	changed, err := setCoverageBitsTx(
		ctx, tx, generationID, "inaccessible_bits", ids,
	)
	if err != nil || len(changed) == 0 || generationID == nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		UPDATE coverage_generations
		SET inaccessible_accounts=inaccessible_accounts+$2
		WHERE id=$1
	`, *generationID, len(changed))
	return err
}

var CoverageAuditEpoch = time.Date(2007, time.October, 20, 0, 0, 0, 0, time.UTC)

type CoverageAuditProgress struct {
	Start           time.Time
	CutoffExclusive time.Time
	NextDay         time.Time
	DaysTotal       int64
	DaysComplete    int64
	SearchableUsers int64
	Complete        bool
}

type CoverageGeneration struct {
	ID                   int64
	RunID                int64
	Status               string
	CutoffUserID         int64
	SettledCutoff        time.Time
	DiscoveredAccounts   int64
	SuccessfulAccounts   int64
	InaccessibleAccounts int64
	UnresolvedAccounts   int64
}

type CoveragePartition struct {
	ID           int64
	GenerationID int64
	Start        time.Time
	End          time.Time
	Attempts     int
	LocalCount   *int64
	Sample       bool
}

func (s *Store) CoverageAuditGeneration(ctx context.Context) (CoverageGeneration, error) {
	var generation CoverageGeneration
	err := s.Pool.QueryRow(ctx, `
		SELECT id, run_id, status, cutoff_user_id, settled_cutoff,
		       discovered_accounts, successful_accounts,
		       inaccessible_accounts, unresolved_accounts
		FROM coverage_generations
		WHERE status IN ('auditing', 'repairing')
		ORDER BY id LIMIT 1
	`).Scan(
		&generation.ID, &generation.RunID, &generation.Status,
		&generation.CutoffUserID, &generation.SettledCutoff,
		&generation.DiscoveredAccounts, &generation.SuccessfulAccounts,
		&generation.InaccessibleAccounts, &generation.UnresolvedAccounts,
	)
	return generation, err
}

func (s *Store) EnsureCoveragePartitions(
	ctx context.Context, generation CoverageGeneration,
) error {
	cutoff := generation.SettledCutoff.UTC().Truncate(time.Second)
	if cutoff.Before(CoverageAuditEpoch) {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO coverage_partitions (
		  generation_id, start_at, end_at
		)
		SELECT $1, day,
		       LEAST(day + interval '1 day' - interval '1 second', $3)
		FROM generate_series($2, $3, interval '1 day') AS day
		ON CONFLICT (generation_id, start_at, end_at) DO NOTHING
	`, generation.ID, CoverageAuditEpoch, cutoff)
	return err
}

func (s *Store) ClaimCoveragePartition(
	ctx context.Context, generationID int64,
) (CoveragePartition, error) {
	var partition CoveragePartition
	err := s.Pool.QueryRow(ctx, `
		WITH picked AS (
		  SELECT p.id
		  FROM coverage_partitions AS p
		  WHERE p.generation_id=$1 AND p.status='pending'
		    AND p.next_attempt_at <= now()
		  ORDER BY p.start_at, p.id
		  FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE coverage_partitions AS p
		SET status='enumerating', attempts=attempts+1,
		    last_error=NULL, last_error_at=NULL
		FROM picked WHERE p.id=picked.id
		RETURNING p.id, p.generation_id, p.start_at, p.end_at, p.attempts, p.sample,
		  CASE
		    WHEN p.start_at=date_trunc('day', p.start_at)
		     AND p.end_at >= LEAST(
		       p.start_at + interval '1 day' - interval '1 second',
		       (SELECT settled_cutoff FROM coverage_generations WHERE id=p.generation_id)
		     )
		    THEN COALESCE((
		      SELECT successful_accounts FROM coverage_day_counts
		      WHERE generation_id=p.generation_id AND day=p.start_at::date
		    ), 0)
		    ELSE NULL
		  END
	`, generationID).Scan(
		&partition.ID, &partition.GenerationID, &partition.Start,
		&partition.End, &partition.Attempts, &partition.Sample, &partition.LocalCount,
	)
	return partition, err
}

func (s *Store) RetryCoveragePartition(
	ctx context.Context, partition CoveragePartition, cause error, delay time.Duration,
) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE coverage_partitions
		SET status='pending', next_attempt_at=now()+$2::interval,
		    last_error=$3, last_error_at=now()
		WHERE id=$1
	`, partition.ID, pgInterval(delay), cause.Error())
	return err
}

func (s *Store) MarkCoverageCountConsistent(
	ctx context.Context, partition CoveragePartition, remote, local int64,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_partitions
		SET status='count_consistent', remote_count=$2, local_count=$3,
		    incomplete_results=false, completed_at=now()
		WHERE id=$1
	`, partition.ID, remote, local); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_generations
		SET partitions_consistent=partitions_consistent+1
		WHERE id=$1
	`, partition.GenerationID); err != nil {
		return err
	}
	dayIndex := int64(partition.Start.UTC().Sub(CoverageAuditEpoch) / (24 * time.Hour))
	if !partition.Sample && (dayIndex+partition.GenerationID)%100 == 0 {
		minute := (dayIndex*1103515245 + partition.GenerationID) % 1440
		if minute < 0 {
			minute = -minute
		}
		start := partition.Start.Add(time.Duration(minute) * time.Minute)
		if start.Before(partition.End) {
			end := start.Add(time.Minute - time.Second)
			if end.After(partition.End) {
				end = partition.End
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO coverage_partitions (
				  generation_id, start_at, end_at, sample
				) VALUES ($1, $2, $3, true)
				ON CONFLICT (generation_id, start_at, end_at) DO NOTHING
			`, partition.GenerationID, start, end); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) SplitCoveragePartition(
	ctx context.Context, partition CoveragePartition, remote int64, incomplete bool,
) error {
	leftStart, leftEnd, rightStart, rightEnd, ok := splitCoverageRange(
		partition.Start, partition.End,
	)
	if !ok {
		return s.MarkCoverageUnresolved(
			ctx, partition, remote,
			"GitHub Search cannot resolve more than 1,000 identities in one creation second",
		)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, bounds := range [][2]time.Time{{leftStart, leftEnd}, {rightStart, rightEnd}} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO coverage_partitions (
			  generation_id, start_at, end_at, sample
			) VALUES ($1, $2, $3, $4)
			ON CONFLICT (generation_id, start_at, end_at) DO NOTHING
		`, partition.GenerationID, bounds[0], bounds[1], partition.Sample); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_partitions
		SET status='splitting', remote_count=$2,
		    incomplete_results=$3, completed_at=now()
		WHERE id=$1
	`, partition.ID, remote, incomplete); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func splitCoverageRange(start, end time.Time) (
	leftStart, leftEnd, rightStart, rightEnd time.Time, ok bool,
) {
	seconds := int64(end.Sub(start) / time.Second)
	if seconds < 1 {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, false
	}
	middle := start.Add(time.Duration(seconds/2) * time.Second)
	return start, middle, middle.Add(time.Second), end, true
}

func (s *Store) MarkCoverageUnresolved(
	ctx context.Context, partition CoveragePartition, remote int64, message string,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_partitions
		SET status='unresolved', remote_count=$2,
		    last_error=$3, last_error_at=now(), completed_at=now()
		WHERE id=$1
	`, partition.ID, remote, message); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_generations
		SET partitions_unresolved=partitions_unresolved+1,
		    unresolved_accounts=unresolved_accounts+1
		WHERE id=$1
	`, partition.GenerationID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) StageCoveragePartition(
	ctx context.Context,
	partition CoveragePartition,
	preCount, postCount int64,
	candidates []model.Candidate,
) (int64, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM coverage_partition_ids WHERE partition_id=$1`, partition.ID); err != nil {
		return 0, err
	}
	if len(candidates) > 0 {
		ids := make([]int64, len(candidates))
		nodes := make([]string, len(candidates))
		logins := make([]string, len(candidates))
		for index, candidate := range candidates {
			ids[index], nodes[index], logins[index] = candidate.GitHubID, candidate.NodeID, candidate.Login
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO coverage_partition_ids (
			  partition_id, github_id, node_id, login, resolved
			)
			SELECT $1, input.github_id, input.node_id, input.login,
			       COALESCE(get_bit(chunks.successful_bits, (input.github_id % 8192)::integer), 0)=1
			FROM unnest($2::bigint[], $3::text[], $4::text[])
			  AS input(github_id, node_id, login)
			LEFT JOIN coverage_bitmap_chunks AS chunks
			  ON chunks.generation_id=$5 AND chunks.chunk_no=input.github_id/8192
			ON CONFLICT (partition_id, github_id) DO UPDATE SET
			  node_id=excluded.node_id, login=excluded.login,
			  resolved=excluded.resolved
		`, partition.ID, ids, nodes, logins, partition.GenerationID); err != nil {
			return 0, err
		}
		generationID := partition.GenerationID
		if err := markCoverageDiscoveredTx(ctx, tx, &generationID, ids); err != nil {
			return 0, err
		}
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO account_queue (
		  source, github_id, node_id, login,
		  coverage_generation_id, coverage_partition_id
		)
		SELECT 'reconcile', github_id, node_id, login, $2, $1
		FROM coverage_partition_ids
		WHERE partition_id=$1 AND NOT resolved
		ON CONFLICT DO NOTHING
	`, partition.ID, partition.GenerationID)
	if err != nil {
		return 0, err
	}
	missing := tag.RowsAffected()
	status := "resolved"
	if missing > 0 {
		status = "repairing"
	}
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_partitions
		SET status=$2, pre_count=$3, post_count=$4,
		    remote_count=$4, incomplete_results=false,
		    completed_at=CASE WHEN $2='resolved' THEN now() ELSE NULL END
		WHERE id=$1
	`, partition.ID, status, preCount, postCount); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_generations
		SET status=CASE WHEN $2='repairing' THEN 'repairing' ELSE status END,
		    partitions_repairing=partitions_repairing+CASE WHEN $2='repairing' THEN 1 ELSE 0 END
		WHERE id=$1
	`, partition.GenerationID, status); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return missing, nil
}

func (s *Store) FinalizeCoverageGeneration(ctx context.Context, generationID int64) (bool, error) {
	var active, unresolved int64
	if err := s.Pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE status IN ('pending','enumerating','repairing')),
		  COUNT(*) FILTER (WHERE status='unresolved')
		FROM coverage_partitions WHERE generation_id=$1
	`, generationID).Scan(&active, &unresolved); err != nil {
		return false, err
	}
	if active > 0 {
		return false, nil
	}
	status := "count_reconciled"
	if unresolved > 0 {
		status = "unresolved"
	}
	_, err := s.Pool.Exec(ctx, `
		UPDATE coverage_generations SET status=$2 WHERE id=$1
	`, generationID, status)
	return true, err
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
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, `
			SET statement_timeout='30s';
			SET lock_timeout='5s';
		`)
		return err
	}
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
	connection, err := s.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer connection.Release()
	if _, err := connection.Exec(ctx, `SET statement_timeout=0`); err != nil {
		return fmt.Errorf("disable migration statement timeout: %w", err)
	}
	defer func() {
		resetContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = connection.Exec(resetContext, `SET statement_timeout='30s'`)
	}()

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

	if _, err := connection.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
		  version TEXT PRIMARY KEY,
		  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	const initialVersion = "001_init_20260802"
	applied, err := migrationAppliedOn(ctx, connection, initialVersion)
	if err != nil {
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
	if !applied {
		if err := recordMigration(ctx, connection, initialVersion); err != nil {
			return err
		}
	}

	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("list database migrations: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == "001_init.sql" || !strings.HasSuffix(name, ".sql") {
			continue
		}
		version := strings.TrimSuffix(name, ".sql")
		applied, err := migrationAppliedOn(ctx, connection, version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read database migration %s: %w", version, err)
		}
		// Files suffixed _concurrently contain exactly one statement. Keeping
		// each in a separate Exec ensures PostgreSQL does not wrap concurrent
		// index creation in a multi-statement transaction.
		if _, err := connection.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("apply database migration %s: %w", version, err)
		}
		if err := recordMigration(ctx, connection, version); err != nil {
			return err
		}
	}
	return nil
}

type migrationExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func recordMigration(ctx context.Context, database migrationExecutor, version string) error {
	if _, err := database.Exec(ctx, `
		INSERT INTO schema_migrations (version) VALUES ($1)
		ON CONFLICT (version) DO NOTHING
	`, version); err != nil {
		return fmt.Errorf("record database migration %s: %w", version, err)
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
		SET status = 'retry', claimed_at = NULL, claim_token = NULL,
		    lease_expires_at = NULL, next_attempt_at = now(),
		    last_error = COALESCE(last_error, 'recovered after restart'),
		    last_error_at = now()
		WHERE status = 'running';
		UPDATE overflow_queue
		SET status = 'retry', claimed_at = NULL, claim_token = NULL,
		    lease_expires_at = NULL, next_attempt_at = now(),
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

func (s *Store) SaveCoverageAuditDay(ctx context.Context, day time.Time, count int64) error {
	if count < 0 {
		return errors.New("coverage audit count cannot be negative")
	}
	day = day.UTC().Truncate(24 * time.Hour)
	key := "coverage_audit_day:" + day.Format(time.DateOnly)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO runtime_state (key, value, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE
		SET value=excluded.value, updated_at=excluded.updated_at
	`, key, strconv.FormatInt(count, 10))
	return err
}

func (s *Store) CoverageAuditProgress(
	ctx context.Context, cutoffExclusive time.Time,
) (CoverageAuditProgress, error) {
	cutoffExclusive = cutoffExclusive.UTC().Truncate(24 * time.Hour)
	progress := CoverageAuditProgress{
		Start: CoverageAuditEpoch, CutoffExclusive: cutoffExclusive,
		NextDay: CoverageAuditEpoch,
	}
	if !cutoffExclusive.After(CoverageAuditEpoch) {
		progress.NextDay = cutoffExclusive
		progress.Complete = true
		return progress, nil
	}
	var firstMissing *time.Time
	err := s.Pool.QueryRow(ctx, `
		WITH expected AS (
		  SELECT day::date AS day
		  FROM generate_series($1::date, $2::date - 1, interval '1 day') AS day
		), observed AS (
		  SELECT replace(key, 'coverage_audit_day:', '')::date AS day,
		         value::bigint AS users
		  FROM runtime_state
		  WHERE key LIKE 'coverage_audit_day:%'
		)
		SELECT COUNT(*) AS days_total,
		       COUNT(observed.day) AS days_complete,
		       COALESCE(SUM(observed.users), 0) AS searchable_users,
		       MIN(expected.day) FILTER (WHERE observed.day IS NULL)
		FROM expected LEFT JOIN observed USING (day)
	`, CoverageAuditEpoch, cutoffExclusive).Scan(
		&progress.DaysTotal, &progress.DaysComplete,
		&progress.SearchableUsers, &firstMissing,
	)
	if err != nil {
		return CoverageAuditProgress{}, err
	}
	if firstMissing == nil {
		progress.NextDay = cutoffExclusive
		progress.Complete = true
	} else {
		progress.NextDay = firstMissing.UTC()
	}
	return progress, nil
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
	coverageVersion := int16(0)
	var settledCutoff *time.Time
	if complete == "true" {
		kind = "global"
		highwater, err := s.StateInt(ctx, "tail_highwater")
		if err != nil {
			return Run{}, err
		}
		cutoff = &highwater
		coverageVersion = 1
		value := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
		settledCutoff = &value
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Run{}, err
	}
	defer tx.Rollback(ctx)
	row := tx.QueryRow(ctx, `
		INSERT INTO crawl_runs (
		  kind, cutoff_user_id, next_url, coverage_version, settled_cutoff
		)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, kind, status, cutoff_user_id, next_since_id,
		          next_url, enumeration_complete, enumerated_users,
		          processed_users, zero_key_users, key_owner_users,
		          inaccessible_users, error_users, coverage_version,
		          coverage_generation_id, settled_cutoff, started_at, completed_at
	`, kind, cutoff, initialURL, coverageVersion, settledCutoff)
	run, err = scanRun(row)
	if err != nil {
		return Run{}, err
	}
	if coverageVersion > 0 && cutoff != nil && settledCutoff != nil {
		var generationID int64
		if err := tx.QueryRow(ctx, `
			INSERT INTO coverage_generations (
			  run_id, cutoff_user_id, settled_cutoff
			) VALUES ($1, $2, $3)
			RETURNING id
		`, run.ID, *cutoff, *settledCutoff).Scan(&generationID); err != nil {
			return Run{}, err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE crawl_runs SET coverage_generation_id=$2 WHERE id=$1
		`, run.ID, generationID); err != nil {
			return Run{}, err
		}
		run.CoverageGenerationID = &generationID
	}
	if err := tx.Commit(ctx); err != nil {
		return Run{}, err
	}
	return run, nil
}

func (s *Store) ActiveMainRun(ctx context.Context) (Run, error) {
	return scanRun(s.Pool.QueryRow(ctx, `
		SELECT id, kind, status, cutoff_user_id, next_since_id,
		       next_url, enumeration_complete, enumerated_users,
		       processed_users, zero_key_users, key_owner_users,
		       inaccessible_users, error_users, coverage_version,
		       coverage_generation_id, settled_cutoff, started_at, completed_at
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
		&run.ErrorUsers, &run.CoverageVersion, &run.CoverageGenerationID,
		&run.SettledCutoff,
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
	insertedIDs, err := enqueueGlobalPageTx(ctx, tx, run.ID, candidates)
	if err != nil {
		return err
	}
	inserted := int64(len(insertedIDs))
	if err := markCoverageDiscoveredTx(
		ctx, tx, run.CoverageGenerationID, insertedIDs,
	); err != nil {
		return err
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
			SELECT shard.id, run.coverage_generation_id
			FROM enumeration_shards AS shard
			JOIN crawl_runs AS run ON run.id=shard.run_id
			WHERE shard.run_id = $1 AND shard.status IN ('pending','retry')
			ORDER BY shard.id FOR UPDATE OF shard SKIP LOCKED LIMIT 1
		)
		UPDATE enumeration_shards AS shard
		SET status='running', attempts=attempts+1, claimed_at=now(), last_error=NULL
		FROM picked WHERE shard.id=picked.id
		RETURNING shard.id, shard.run_id, shard.lower_id, shard.upper_id,
		          shard.next_since_id, shard.next_url, shard.attempts, shard.enumerated_users,
		          picked.coverage_generation_id
	`, runID)
	var shard EnumerationShard
	err := row.Scan(&shard.ID, &shard.RunID, &shard.LowerID, &shard.UpperID,
		&shard.NextSinceID, &shard.NextURL, &shard.Attempts, &shard.EnumeratedUsers,
		&shard.CoverageGenerationID)
	return shard, err
}

func (s *Store) ApplyEnumerationShardPage(ctx context.Context, shard EnumerationShard, candidates []model.Candidate, nextSince int64, nextURL string, complete bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	insertedIDs, err := enqueueGlobalPageTx(ctx, tx, shard.RunID, candidates)
	if err != nil {
		return err
	}
	inserted := int64(len(insertedIDs))
	if err := markCoverageDiscoveredTx(
		ctx, tx, shard.CoverageGenerationID, insertedIDs,
	); err != nil {
		return err
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

func enqueueGlobalPageTx(
	ctx context.Context, tx pgx.Tx, runID int64, candidates []model.Candidate,
) ([]int64, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	githubIDs := make([]int64, len(candidates))
	nodeIDs := make([]string, len(candidates))
	logins := make([]string, len(candidates))
	for index, candidate := range candidates {
		githubIDs[index] = candidate.GitHubID
		nodeIDs[index] = candidate.NodeID
		logins[index] = candidate.Login
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO account_queue (
		  run_id, source, github_id, node_id, login
		)
		SELECT $1, 'global', github_id, node_id, login
		FROM unnest($2::bigint[], $3::text[], $4::text[])
		  AS input(github_id, node_id, login)
		ON CONFLICT DO NOTHING
		RETURNING github_id
	`, runID, githubIDs, nodeIDs, logins)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inserted := make([]int64, 0, len(candidates))
	for rows.Next() {
		var githubID int64
		if err := rows.Scan(&githubID); err != nil {
			return nil, err
		}
		inserted = append(inserted, githubID)
	}
	return inserted, rows.Err()
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

func (s *Store) GlobalBacklog(ctx context.Context, runID int64) (int64, error) {
	var backlog int64
	err := s.Pool.QueryRow(ctx, `
		SELECT GREATEST(0, enumerated_users-processed_users)
		FROM crawl_runs WHERE id=$1
	`, runID).Scan(&backlog)
	return backlog, err
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

// QueueDepthByClassCapped performs bounded work even while a historical global
// backlog contains millions of rows. A result greater than limit is a lower
// bound and is sufficient for producer backpressure.
func (s *Store) QueueDepthByClassCapped(
	ctx context.Context, class string, limit int,
) (int, error) {
	if limit < 1 {
		limit = 1
	}
	var count int
	err := s.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
		  SELECT 1
		  FROM account_queue
		  WHERE CASE $1
		    WHEN 'global' THEN source IN ('global', 'reconcile')
		    WHEN 'live' THEN source IN ('tail', 'onboarding')
		    WHEN 'owner' THEN source = 'priority'
		    ELSE source = $1
		  END
		  LIMIT $2
		) AS bounded
	`, class, limit+1).Scan(&count)
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
	// Claim one exact source and status at a time. A negative/fallback source
	// predicate forces PostgreSQL to sort the entire multi-million-row global
	// queue when the preferred class is empty, while equality can walk the
	// existing status/source index and stop after the requested batch.
	sourceOrder := []string{
		"anomaly", "reconcile", "global", "tail", "onboarding", "priority",
	}
	switch preferred {
	case "live":
		sourceOrder = []string{
			"anomaly", "tail", "onboarding", "reconcile", "global", "priority",
		}
	case "owner":
		sourceOrder = []string{
			"anomaly", "priority", "reconcile", "global", "tail", "onboarding",
		}
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	result := make([]model.Candidate, 0, limit)
	// Retry is the outer loop so a recovered or failed observation cannot sit
	// behind millions of never-attempted legacy pending rows.
	for _, status := range []string{"retry", "pending"} {
		for _, source := range sourceOrder {
			if len(result) == limit {
				break
			}
			claimed, err := claimAccountSourceStatus(
				ctx, tx, limit-len(result), source, status,
			)
			if err != nil {
				return nil, err
			}
			result = append(result, claimed...)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].QueueID < result[j].QueueID })
	return result, nil
}

func claimAccountSourceStatus(
	ctx context.Context,
	tx pgx.Tx,
	limit int,
	source string,
	status string,
) ([]model.Candidate, error) {
	rows, err := tx.Query(ctx, `
		WITH picked AS (
		  SELECT id
		  FROM account_queue
		  WHERE status = $3
		    AND next_attempt_at <= now()
		    AND source = $2
		  ORDER BY next_attempt_at, id
		  FOR UPDATE SKIP LOCKED
		  LIMIT $1
		)
		UPDATE account_queue AS q
		SET status = 'running', attempts = attempts + 1,
		    claimed_at = now(), lease_expires_at = now() + interval '5 minutes',
		    claim_token = gen_random_uuid(),
		    last_error = NULL, last_error_at = NULL
		FROM picked
		WHERE q.id = picked.id
		RETURNING q.id, q.run_id, q.source, q.github_id,
		          q.node_id, q.login, q.scan_id::text, q.attempts,
		          q.claim_token::text, q.coverage_generation_id,
		          q.coverage_partition_id
	`, limit, source, status)
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
			&item.ClaimToken, &item.GenerationID, &item.PartitionID,
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
	if _, err := enqueuePageTx(ctx, tx, "tail", candidates); err != nil {
		return err
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
	if len(jobs) == 0 {
		return nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	githubIDs := make([]int64, 0, len(jobs))
	runIDs := make([]int64, 0, len(jobs))
	for _, job := range jobs {
		githubIDs = append(githubIDs, job.GitHubID)
		if job.RunID != nil {
			runIDs = append(runIDs, *job.RunID)
		}
	}
	sort.Slice(githubIDs, func(i, j int) bool { return githubIDs[i] < githubIDs[j] })
	if _, err := tx.Exec(ctx, `
		SELECT pg_advisory_xact_lock(github_id)
		FROM unnest($1::bigint[]) AS ids(github_id)
		ORDER BY github_id
	`, githubIDs); err != nil {
		return err
	}
	ownerIDs := make(map[int64]bool)
	ownerRows, err := tx.Query(ctx, `
		SELECT github_id FROM github_owners WHERE github_id=ANY($1)
	`, githubIDs)
	if err != nil {
		return err
	}
	for ownerRows.Next() {
		var githubID int64
		if err := ownerRows.Scan(&githubID); err != nil {
			ownerRows.Close()
			return err
		}
		ownerIDs[githubID] = true
	}
	if err := ownerRows.Err(); err != nil {
		ownerRows.Close()
		return err
	}
	ownerRows.Close()
	generations, err := runGenerationsTx(ctx, tx, runIDs)
	if err != nil {
		return err
	}
	type runCounts struct{ zero, owner, inaccessible int64 }
	counts := make(map[int64]*runCounts)
	successByGeneration := make(map[int64]map[int64]time.Time)
	completedIDs := make([]int64, 0, len(jobs))
	for index, job := range jobs {
		result := results[index]
		if result == nil {
			return fmt.Errorf("nil result for GitHub account %d must be retried or confirmed", job.GitHubID)
		}
		generationID := job.GenerationID
		if generationID == nil && job.RunID != nil {
			generationID = generations[*job.RunID]
		}
		ownerExists := ownerIDs[job.GitHubID]
		if len(result.Keys) > 0 || ownerExists {
			if err := upsertOwner(
				ctx, tx, job, result.Login, scheduleDuration(ownerSchedule, 0),
			); err != nil {
				return err
			}
			if result.HasMoreKeys {
				if result.NextCursor == "" {
					return fmt.Errorf("user %s has more keys but no cursor", result.Login)
				}
				if _, err := tx.Exec(ctx, `
					INSERT INTO key_scan_attempts (
					  scan_id, github_id, run_id, generation_id,
					  pass, expected_count, next_cursor, page_count
					) VALUES ($1::uuid, $2, $3, $4, 1, $5, $6, 1)
					ON CONFLICT (scan_id) DO UPDATE SET
					  expected_count=excluded.expected_count,
					  next_cursor=excluded.next_cursor,
					  updated_at=now()
				`, job.ScanID, job.GitHubID, job.RunID, generationID,
					result.TotalKeyCount, result.NextCursor); err != nil {
					return err
				}
				if err := stageKeysTx(ctx, tx, job.ScanID, 1, result.Keys); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `
					INSERT INTO overflow_queue (
					  run_id, source, github_id, node_id, login,
					  scan_id, cursor, account_created_at,
					  coverage_generation_id, coverage_partition_id,
					  expected_key_count, observed_key_count, verification_pass
					) VALUES ($1, $2, $3, $4, $5, $6::uuid, $7, $8, $9, $10, $11, $12, 1)
					ON CONFLICT (source, github_id, scan_id)
					DO UPDATE SET cursor = excluded.cursor,
					              status = 'pending', last_error = NULL
				`, job.RunID, job.Source, job.GitHubID, result.NodeID,
					result.Login, job.ScanID, result.NextCursor, result.CreatedAt,
					generationID, job.PartitionID, result.TotalKeyCount, len(result.Keys))
				if err != nil {
					return err
				}
			} else {
				for _, key := range result.Keys {
					if err := observeKey(ctx, tx, job.GitHubID, job.ScanID, key); err != nil {
						return err
					}
				}
				if err := finalizeObservation(
					ctx, tx, job.GitHubID, job.ScanID, ownerSchedule,
				); err != nil {
					return err
				}
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
		if job.RunID != nil {
			entry := counts[*job.RunID]
			if entry == nil {
				entry = &runCounts{}
				counts[*job.RunID] = entry
			}
			if classification == "owner" {
				entry.owner++
			} else {
				entry.zero++
			}
		}
		if generationID != nil && !result.HasMoreKeys {
			if successByGeneration[*generationID] == nil {
				successByGeneration[*generationID] = make(map[int64]time.Time)
			}
			successByGeneration[*generationID][job.GitHubID] = result.CreatedAt
		}
		if !result.HasMoreKeys {
			completedIDs = append(completedIDs, job.GitHubID)
		}
	}
	queueIDs := make([]int64, len(jobs))
	claimTokens := make([]string, len(jobs))
	for index, job := range jobs {
		queueIDs[index] = job.QueueID
		claimTokens[index] = job.ClaimToken
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM account_queue AS q
		USING unnest($1::bigint[], $2::text[]) AS claimed(id, token)
		WHERE q.id=claimed.id AND q.claim_token::text=claimed.token
	`, queueIDs, claimTokens)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(jobs)) {
		return fmt.Errorf("stale account claims: completed %d of %d", tag.RowsAffected(), len(jobs))
	}
	anomalyRows, err := tx.Query(ctx, `
		DELETE FROM scan_anomalies WHERE github_id=ANY($1)
		RETURNING generation_id
	`, completedIDs)
	if err != nil {
		return err
	}
	resolvedAnomalies := make(map[int64]int64)
	for anomalyRows.Next() {
		var generationID *int64
		if err := anomalyRows.Scan(&generationID); err != nil {
			anomalyRows.Close()
			return err
		}
		if generationID != nil {
			resolvedAnomalies[*generationID]++
		}
	}
	if err := anomalyRows.Err(); err != nil {
		anomalyRows.Close()
		return err
	}
	anomalyRows.Close()
	for generationID, count := range resolvedAnomalies {
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_generations
			SET unresolved_accounts=GREATEST(0, unresolved_accounts-$2),
			    status=CASE
			      WHEN GREATEST(0, unresolved_accounts-$2)=0 AND status='unresolved'
			      THEN 'auditing' ELSE status
			    END
			WHERE id=$1
		`, generationID, count); err != nil {
			return err
		}
	}
	if err := lockCrawlRuns(ctx, tx, runIDs); err != nil {
		return err
	}
	for runID, entry := range counts {
		if _, err := tx.Exec(ctx, `
			UPDATE crawl_runs SET
			  processed_users=processed_users+$2+$3+$4,
			  zero_key_users=zero_key_users+$2,
			  key_owner_users=key_owner_users+$3,
			  inaccessible_users=inaccessible_users+$4
			WHERE id=$1
		`, runID, entry.zero, entry.owner, entry.inaccessible); err != nil {
			return err
		}
	}
	for generationID, created := range successByGeneration {
		id := generationID
		if err := markCoverageSuccessfulTx(ctx, tx, &id, created); err != nil {
			return err
		}
	}
	for index, job := range jobs {
		if job.PartitionID == nil || results[index].HasMoreKeys {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_partition_ids
			SET resolved=true
			WHERE partition_id=$1 AND github_id=$2
		`, *job.PartitionID, job.GitHubID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_partitions SET status='resolved', completed_at=now()
			WHERE id=$1 AND NOT EXISTS (
			  SELECT 1 FROM coverage_partition_ids
			  WHERE partition_id=$1 AND NOT resolved
			)
		`, *job.PartitionID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func runGenerationsTx(
	ctx context.Context, tx pgx.Tx, runIDs []int64,
) (map[int64]*int64, error) {
	result := make(map[int64]*int64)
	if len(runIDs) == 0 {
		return result, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id, coverage_generation_id FROM crawl_runs WHERE id=ANY($1)
	`, runIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var runID int64
		var generationID *int64
		if err := rows.Scan(&runID, &generationID); err != nil {
			return nil, err
		}
		result[runID] = generationID
	}
	return result, rows.Err()
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

func stageKeysTx(
	ctx context.Context, tx pgx.Tx, scanID string, pass int, keys []model.PublicKey,
) error {
	for _, key := range keys {
		if _, err := tx.Exec(ctx, `
			INSERT INTO key_scan_staging (
			  scan_id, pass, fingerprint_sha256, fingerprint_text,
			  key_type, public_key
			) VALUES ($1::uuid, $2, $3, $4, $5, $6)
			ON CONFLICT (scan_id, pass, fingerprint_sha256) DO UPDATE SET
			  fingerprint_text=excluded.fingerprint_text,
			  key_type=excluded.key_type,
			  public_key=excluded.public_key
		`, scanID, pass, key.Fingerprint, key.Text, key.Type, key.Canonical); err != nil {
			return err
		}
	}
	return nil
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

func (s *Store) RequeueAccounts(ctx context.Context, jobs []model.Candidate, cause error) error {
	return s.RequeueAccountsAfter(ctx, jobs, cause, 0)
}

func (s *Store) RequeueAccountsAfter(
	ctx context.Context,
	jobs []model.Candidate,
	cause error,
	delay time.Duration,
) error {
	if len(jobs) == 0 {
		return nil
	}
	retryJobs := make([]model.Candidate, 0, len(jobs))
	quarantine := make([]model.Candidate, 0)
	for _, job := range jobs {
		if job.Attempts >= 8 || job.Source == "anomaly" {
			quarantine = append(quarantine, job)
		} else {
			retryJobs = append(retryJobs, job)
		}
	}
	if len(quarantine) > 0 {
		if err := s.quarantineAccounts(ctx, quarantine, cause); err != nil {
			return err
		}
	}
	if len(retryJobs) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(retryJobs))
	tokens := make([]string, 0, len(retryJobs))
	for _, job := range retryJobs {
		ids = append(ids, job.QueueID)
		tokens = append(tokens, job.ClaimToken)
	}
	if delay <= 0 {
		attempt := 1
		for _, job := range retryJobs {
			attempt = max(attempt, job.Attempts)
		}
		exponent := min(attempt-1, 12)
		delay = min(time.Duration(1<<exponent)*5*time.Second, 6*time.Hour)
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE account_queue AS q
		SET status = 'retry', claimed_at = NULL, claim_token = NULL,
		    lease_expires_at = NULL, next_attempt_at = now() + $3::interval,
		    last_error = $4, last_error_at = now()
		FROM unnest($1::bigint[], $2::text[]) AS claimed(id, token)
		WHERE q.id=claimed.id AND q.claim_token::text=claimed.token
	`, ids, tokens, pgInterval(delay), cause.Error())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != int64(len(retryJobs)) {
		return fmt.Errorf(
			"stale account retry claims: updated %d of %d",
			tag.RowsAffected(), len(retryJobs),
		)
	}
	return nil
}

func (s *Store) quarantineAccounts(
	ctx context.Context, jobs []model.Candidate, cause error,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, job := range jobs {
		generationID := job.GenerationID
		if generationID == nil && job.RunID != nil {
			generations, err := runGenerationsTx(ctx, tx, []int64{*job.RunID})
			if err != nil {
				return err
			}
			generationID = generations[*job.RunID]
		}
		var inserted bool
		if err := tx.QueryRow(ctx, `
			INSERT INTO scan_anomalies (
			  github_id, node_id, login, run_id, generation_id, partition_id,
			  kind, attempts, next_attempt_at, last_error
			) VALUES ($1, $2, $3, $4, $5, $6, 'persistent_scan_failure',
			          $7, now()+interval '6 hours', $8)
			ON CONFLICT (github_id) DO UPDATE SET
			  node_id=excluded.node_id, login=excluded.login,
			  generation_id=COALESCE(excluded.generation_id, scan_anomalies.generation_id),
			  partition_id=COALESCE(excluded.partition_id, scan_anomalies.partition_id),
			  attempts=scan_anomalies.attempts+excluded.attempts,
			  next_attempt_at=excluded.next_attempt_at,
			  last_seen_at=now(), last_error=excluded.last_error
			RETURNING xmax=0
		`, job.GitHubID, job.NodeID, job.Login, job.RunID, generationID,
			job.PartitionID, max(job.Attempts, 1), cause.Error()).Scan(&inserted); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `
			DELETE FROM account_queue
			WHERE id=$1 AND claim_token::text=$2
		`, job.QueueID, job.ClaimToken)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("stale account claim during quarantine")
		}
		if job.RunID != nil && job.Source != "anomaly" {
			if err := lockCrawlRuns(ctx, tx, []int64{*job.RunID}); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				UPDATE crawl_runs
				SET processed_users=processed_users+1,
				    error_users=error_users+1
				WHERE id=$1
			`, *job.RunID); err != nil {
				return err
			}
		}
		if generationID != nil && inserted {
			if _, err := tx.Exec(ctx, `
				UPDATE coverage_generations
				SET unresolved_accounts=unresolved_accounts+1
				WHERE id=$1
			`, *generationID); err != nil {
				return err
			}
		}
		if job.PartitionID != nil {
			if _, err := tx.Exec(ctx, `
				UPDATE coverage_partitions
				SET status='unresolved', last_error=$2,
				    last_error_at=now(), completed_at=now()
				WHERE id=$1
			`, *job.PartitionID, cause.Error()); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) RefreshClaimIdentity(
	ctx context.Context, job model.Candidate, nodeID, login string,
) error {
	if nodeID == "" || login == "" {
		return errors.New("refreshed GitHub identity is incomplete")
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE account_queue
		SET node_id=$3, login=$4
		WHERE id=$1 AND claim_token::text=$2
	`, job.QueueID, job.ClaimToken, nodeID, login)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("stale account claim during identity refresh")
	}
	return nil
}

func (s *Store) CompleteInaccessible(ctx context.Context, job model.Candidate) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, job.GitHubID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE github_owners
		SET inaccessible=true, last_verified_at=now(), last_seen_at=now()
		WHERE github_id=$1
	`, job.GitHubID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE github_owner_keys
		SET currently_present=false,
		    removed_at=COALESCE(removed_at, now()),
		    last_verified_at=now()
		WHERE github_id=$1 AND currently_present
	`, job.GitHubID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM zero_key_rechecks WHERE github_id=$1`, job.GitHubID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM account_queue
		WHERE id=$1 AND claim_token::text=$2
	`, job.QueueID, job.ClaimToken)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("stale inaccessible-account claim")
	}
	if job.RunID != nil {
		if err := lockCrawlRuns(ctx, tx, []int64{*job.RunID}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE crawl_runs
			SET processed_users=processed_users+1,
			    inaccessible_users=inaccessible_users+1
			WHERE id=$1
		`, *job.RunID); err != nil {
			return err
		}
		generations, err := runGenerationsTx(ctx, tx, []int64{*job.RunID})
		if err != nil {
			return err
		}
		if err := markCoverageInaccessibleTx(
			ctx, tx, generations[*job.RunID], []int64{job.GitHubID},
		); err != nil {
			return err
		}
	}
	if job.GenerationID != nil {
		if err := markCoverageInaccessibleTx(
			ctx, tx, job.GenerationID, []int64{job.GitHubID},
		); err != nil {
			return err
		}
	}
	var anomalyDeleted bool
	if err := tx.QueryRow(ctx, `
		WITH deleted AS (
		  DELETE FROM scan_anomalies WHERE github_id=$1 RETURNING 1
		)
		SELECT EXISTS(SELECT 1 FROM deleted)
	`, job.GitHubID).Scan(&anomalyDeleted); err != nil {
		return err
	}
	if anomalyDeleted && job.GenerationID != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_generations
			SET unresolved_accounts=GREATEST(0, unresolved_accounts-1),
			    status=CASE WHEN status='unresolved' THEN 'auditing' ELSE status END
			WHERE id=$1
		`, *job.GenerationID); err != nil {
			return err
		}
	}
	if job.PartitionID != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_partition_ids SET resolved=true
			WHERE partition_id=$1 AND github_id=$2
		`, *job.PartitionID, job.GitHubID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_partitions SET status='resolved', completed_at=now()
			WHERE id=$1 AND NOT EXISTS (
			  SELECT 1 FROM coverage_partition_ids
			  WHERE partition_id=$1 AND NOT resolved
			)
		`, *job.PartitionID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) ReapExpiredLeases(ctx context.Context) (int64, error) {
	var count int64
	err := s.Pool.QueryRow(ctx, `
		WITH accounts AS (
		  UPDATE account_queue SET
		    status='retry', claimed_at=NULL, claim_token=NULL,
		    lease_expires_at=NULL, next_attempt_at=now(),
		    last_error='claim lease expired', last_error_at=now()
		  WHERE status='running' AND lease_expires_at < now()
		  RETURNING 1
		), overflow AS (
		  UPDATE overflow_queue SET
		    status='retry', claimed_at=NULL, claim_token=NULL,
		    lease_expires_at=NULL, next_attempt_at=now(),
		    last_error='claim lease expired', last_error_at=now()
		  WHERE status='running' AND lease_expires_at < now()
		  RETURNING 1
		)
		SELECT (SELECT COUNT(*) FROM accounts) + (SELECT COUNT(*) FROM overflow)
	`).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) DueWorkHealth(
	ctx context.Context,
) (bool, *time.Time, *time.Time, error) {
	var due bool
	if err := s.Pool.QueryRow(ctx, `
		SELECT
		  EXISTS (
		    SELECT 1 FROM account_queue
		    WHERE status IN ('pending','retry') AND next_attempt_at <= now()
		    LIMIT 1
		  ) OR EXISTS (
		    SELECT 1 FROM overflow_queue
		    WHERE status IN ('pending','retry') AND next_attempt_at <= now()
		    LIMIT 1
		  )
	`).Scan(&due); err != nil {
		return false, nil, nil, err
	}
	var graphQLSuccess, restSuccess *time.Time
	if err := s.Pool.QueryRow(ctx, `
		SELECT
		  MAX(last_success_at) FILTER (WHERE name LIKE 'graphql-%'),
		  MAX(last_success_at) FILTER (WHERE name LIKE 'rest-enumerator-%')
		FROM crawler_workers
	`).Scan(&graphQLSuccess, &restSuccess); err != nil {
		return false, nil, nil, err
	}
	return due, graphQLSuccess, restSuccess, nil
}

func (s *Store) ClaimOverflow(ctx context.Context) (*model.OverflowJob, error) {
	var job model.OverflowJob
	err := s.Pool.QueryRow(ctx, `
		WITH picked AS (
		  SELECT id FROM overflow_queue
		  WHERE status IN ('pending', 'retry')
		    AND next_attempt_at <= now()
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
		    claimed_at = now(), lease_expires_at = now() + interval '5 minutes',
		    claim_token = gen_random_uuid(),
		    last_error = NULL, last_error_at = NULL
		FROM picked
		WHERE q.id = picked.id
		RETURNING q.id, q.run_id, q.source, q.github_id,
		          q.node_id, q.login, q.scan_id::text, q.cursor, q.attempts,
		          q.claim_token::text, q.account_created_at,
		          q.coverage_generation_id, q.coverage_partition_id,
		          COALESCE(q.expected_key_count, -1), q.observed_key_count,
		          q.verification_pass
	`).Scan(
		&job.ID, &job.RunID, &job.Source, &job.GitHubID,
		&job.NodeID, &job.Login, &job.ScanID, &job.Cursor, &job.Attempts,
		&job.ClaimToken, &job.CreatedAt, &job.GenerationID, &job.PartitionID,
		&job.ExpectedKeyCount, &job.ObservedKeyCount, &job.VerificationPass,
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
	return s.CompleteOverflowPageScheduled(
		ctx, job, keys, hasMore, nextCursor, job.ExpectedKeyCount, ownerSchedule,
	)
}

func (s *Store) CompleteOverflowPageScheduled(
	ctx context.Context,
	job model.OverflowJob,
	keys []model.PublicKey,
	hasMore bool,
	nextCursor string,
	totalCount int,
	ownerSchedule []time.Duration,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, job.GitHubID); err != nil {
		return err
	}
	pass := job.VerificationPass
	if pass != 1 && pass != 2 {
		pass = 1
	}
	expected := job.ExpectedKeyCount
	if expected < 0 && job.Cursor == "" {
		expected = totalCount
	}
	if totalCount != expected {
		return fmt.Errorf(
			"overflow key count changed: expected=%d received=%d", expected, totalCount,
		)
	}
	if err := stageKeysTx(ctx, tx, job.ScanID, pass, keys); err != nil {
		return err
	}
	observed := job.ObservedKeyCount + len(keys)
	if observed > expected {
		return fmt.Errorf("overflow observed %d keys, expected %d", observed, expected)
	}
	if hasMore {
		if nextCursor == "" || nextCursor == job.Cursor {
			return errors.New("overflow response has missing or repeated next cursor")
		}
		tag, err := tx.Exec(ctx, `
			UPDATE overflow_queue
			SET cursor = $2, observed_key_count=$4,
			    expected_key_count=$5,
			    status = 'pending', claimed_at = NULL,
			    claim_token = NULL, lease_expires_at = NULL,
			    next_attempt_at = now()
			WHERE id = $1 AND claim_token::text=$3
		`, job.ID, nextCursor, job.ClaimToken, observed, expected)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("stale overflow claim")
		}
		return tx.Commit(ctx)
	}
	if observed != expected {
		return fmt.Errorf("overflow ended after %d of %d keys", observed, expected)
	}
	var stagedCount int
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM key_scan_staging
		WHERE scan_id=$1::uuid AND pass=$2
	`, job.ScanID, pass).Scan(&stagedCount); err != nil {
		return err
	}
	if stagedCount != expected {
		if err := restartOverflowScanTx(
			ctx, tx, job,
			fmt.Sprintf("overflow pass contained %d unique keys, expected %d", stagedCount, expected),
		); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if pass == 1 {
		tag, err := tx.Exec(ctx, `
			UPDATE overflow_queue
			SET verification_pass=2, cursor='', observed_key_count=0,
			    expected_key_count=$3, status='pending', claimed_at=NULL,
			    claim_token=NULL, lease_expires_at=NULL, next_attempt_at=now()
			WHERE id=$1 AND claim_token::text=$2
		`, job.ID, job.ClaimToken, expected)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("stale overflow claim")
		}
		if _, err := tx.Exec(ctx, `
			UPDATE key_scan_attempts
			SET pass=2, status='verifying', next_cursor=NULL,
			    page_count=0, updated_at=now()
			WHERE scan_id=$1::uuid
		`, job.ScanID); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	var stable bool
	if err := tx.QueryRow(ctx, `
		SELECT NOT EXISTS (
		  (SELECT fingerprint_sha256 FROM key_scan_staging
		   WHERE scan_id=$1::uuid AND pass=1
		   EXCEPT
		   SELECT fingerprint_sha256 FROM key_scan_staging
		   WHERE scan_id=$1::uuid AND pass=2)
		  UNION ALL
		  (SELECT fingerprint_sha256 FROM key_scan_staging
		   WHERE scan_id=$1::uuid AND pass=2
		   EXCEPT
		   SELECT fingerprint_sha256 FROM key_scan_staging
		   WHERE scan_id=$1::uuid AND pass=1)
		)
	`, job.ScanID).Scan(&stable); err != nil {
		return err
	}
	if !stable {
		if err := restartOverflowScanTx(ctx, tx, job, "key set changed between verification passes"); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	rows, err := tx.Query(ctx, `
		SELECT fingerprint_sha256, fingerprint_text, key_type, public_key
		FROM key_scan_staging
		WHERE scan_id=$1::uuid AND pass=2
		ORDER BY fingerprint_sha256
	`, job.ScanID)
	if err != nil {
		return err
	}
	verified := make([]model.PublicKey, 0, expected)
	for rows.Next() {
		var key model.PublicKey
		if err := rows.Scan(&key.Fingerprint, &key.Text, &key.Type, &key.Canonical); err != nil {
			rows.Close()
			return err
		}
		verified = append(verified, key)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(verified) != expected {
		return fmt.Errorf("stable overflow set contains %d of %d keys", len(verified), expected)
	}
	for _, key := range verified {
		if err := observeKey(ctx, tx, job.GitHubID, job.ScanID, key); err != nil {
			return err
		}
	}
	if err := finalizeObservation(ctx, tx, job.GitHubID, job.ScanID, ownerSchedule); err != nil {
		return err
	}
	if err := completeOverflowCoverageTx(ctx, tx, job); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM overflow_queue WHERE id=$1 AND claim_token::text=$2
	`, job.ID, job.ClaimToken)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("stale overflow claim")
	}
	if _, err := tx.Exec(ctx, `DELETE FROM key_scan_attempts WHERE scan_id=$1::uuid`, job.ScanID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func completeOverflowCoverageTx(ctx context.Context, tx pgx.Tx, job model.OverflowJob) error {
	generationID := job.GenerationID
	if generationID == nil && job.RunID != nil {
		generations, err := runGenerationsTx(ctx, tx, []int64{*job.RunID})
		if err != nil {
			return err
		}
		generationID = generations[*job.RunID]
	}
	if job.CreatedAt != nil {
		if generationID != nil {
			created := map[int64]time.Time{job.GitHubID: *job.CreatedAt}
			if err := markCoverageSuccessfulTx(ctx, tx, generationID, created); err != nil {
				return err
			}
		}
	}
	var anomalyGenerationID *int64
	if err := tx.QueryRow(ctx, `
		DELETE FROM scan_anomalies WHERE github_id=$1
		RETURNING generation_id
	`, job.GitHubID).Scan(&anomalyGenerationID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if anomalyGenerationID != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_generations
			SET unresolved_accounts=GREATEST(0, unresolved_accounts-1),
			    status=CASE
			      WHEN GREATEST(0, unresolved_accounts-1)=0 AND status='unresolved'
			      THEN 'auditing' ELSE status
			    END
			WHERE id=$1
		`, *anomalyGenerationID); err != nil {
			return err
		}
	}
	if job.PartitionID == nil {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE coverage_partition_ids SET resolved=true
		WHERE partition_id=$1 AND github_id=$2
	`, *job.PartitionID, job.GitHubID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		UPDATE coverage_partitions SET status='resolved', completed_at=now()
		WHERE id=$1 AND NOT EXISTS (
		  SELECT 1 FROM coverage_partition_ids
		  WHERE partition_id=$1 AND NOT resolved
		)
	`, *job.PartitionID)
	return err
}

func restartOverflowScanTx(
	ctx context.Context, tx pgx.Tx, job model.OverflowJob, reason string,
) error {
	if _, err := tx.Exec(ctx, `DELETE FROM key_scan_staging WHERE scan_id=$1::uuid`, job.ScanID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE key_scan_attempts
		SET pass=1, expected_count=-1, next_cursor=NULL, page_count=0,
		    status='collecting', updated_at=now()
		WHERE scan_id=$1::uuid
	`, job.ScanID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE overflow_queue
		SET verification_pass=1, expected_key_count=-1,
		    observed_key_count=0, cursor='', status='pending',
		    claimed_at=NULL, claim_token=NULL, lease_expires_at=NULL,
		    next_attempt_at=now()+interval '1 minute',
		    last_error=$3, last_error_at=now()
		WHERE id=$1 AND claim_token::text=$2
	`, job.ID, job.ClaimToken, reason)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("stale overflow claim during scan restart")
	}
	return nil
}

func (s *Store) RestartOverflowScan(
	ctx context.Context, job model.OverflowJob, reason string,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := restartOverflowScanTx(ctx, tx, job, reason); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) RequeueOverflow(ctx context.Context, job model.OverflowJob, cause error) error {
	return s.RequeueOverflowAfter(ctx, job, cause, 0)
}

func (s *Store) RequeueOverflowAfter(
	ctx context.Context, job model.OverflowJob, cause error, delay time.Duration,
) error {
	if job.Attempts >= 8 {
		return s.quarantineOverflow(ctx, job, cause)
	}
	if delay <= 0 {
		exponent := min(max(job.Attempts, 1)-1, 12)
		delay = min(time.Duration(1<<exponent)*5*time.Second, 6*time.Hour)
	}
	tag, err := s.Pool.Exec(ctx, `
		UPDATE overflow_queue
		SET status = 'retry', claimed_at = NULL, claim_token = NULL,
		    lease_expires_at = NULL, next_attempt_at = now() + $3::interval,
		    last_error = $4, last_error_at = now()
		WHERE id = $1 AND claim_token::text=$2
	`, job.ID, job.ClaimToken, pgInterval(delay), cause.Error())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("stale overflow claim during retry")
	}
	return nil
}

func (s *Store) quarantineOverflow(
	ctx context.Context, job model.OverflowJob, cause error,
) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, job.GitHubID); err != nil {
		return err
	}
	generationID := job.GenerationID
	if generationID == nil && job.RunID != nil {
		generations, err := runGenerationsTx(ctx, tx, []int64{*job.RunID})
		if err != nil {
			return err
		}
		generationID = generations[*job.RunID]
	}
	var inserted bool
	if err := tx.QueryRow(ctx, `
		INSERT INTO scan_anomalies (
		  github_id, node_id, login, run_id, generation_id, partition_id,
		  kind, attempts, next_attempt_at, last_error
		) VALUES ($1, $2, $3, $4, $5, $6, 'unstable_large_key_set',
		          $7, now()+interval '6 hours', $8)
		ON CONFLICT (github_id) DO UPDATE SET
		  node_id=excluded.node_id, login=excluded.login,
		  run_id=COALESCE(excluded.run_id, scan_anomalies.run_id),
		  generation_id=COALESCE(excluded.generation_id, scan_anomalies.generation_id),
		  partition_id=COALESCE(excluded.partition_id, scan_anomalies.partition_id),
		  kind=excluded.kind,
		  attempts=scan_anomalies.attempts+excluded.attempts,
		  next_attempt_at=excluded.next_attempt_at,
		  last_seen_at=now(), last_error=excluded.last_error
		RETURNING xmax=0
	`, job.GitHubID, job.NodeID, job.Login, job.RunID, generationID,
		job.PartitionID, max(job.Attempts, 1), cause.Error()).Scan(&inserted); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		DELETE FROM overflow_queue WHERE id=$1 AND claim_token::text=$2
	`, job.ID, job.ClaimToken)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("stale overflow claim during quarantine")
	}
	if _, err := tx.Exec(ctx, `DELETE FROM key_scan_attempts WHERE scan_id=$1::uuid`, job.ScanID); err != nil {
		return err
	}
	if job.RunID != nil && job.Source != "anomaly" {
		if err := lockCrawlRuns(ctx, tx, []int64{*job.RunID}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE crawl_runs SET error_users=error_users+1 WHERE id=$1
		`, *job.RunID); err != nil {
			return err
		}
	}
	if generationID != nil && inserted {
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_generations
			SET unresolved_accounts=unresolved_accounts+1
			WHERE id=$1
		`, *generationID); err != nil {
			return err
		}
	}
	if job.PartitionID != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_partitions
			SET status='unresolved', last_error=$2,
			    last_error_at=now(), completed_at=now()
			WHERE id=$1
		`, *job.PartitionID, cause.Error()); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
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
	if run.ProcessedUsers < run.EnumeratedUsers {
		return false, nil
	}
	var overflowPending bool
	err = s.Pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM overflow_queue WHERE run_id=$1)
	`, run.ID).Scan(&overflowPending)
	if err != nil || overflowPending {
		return false, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	if run.CoverageGenerationID != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE coverage_generations
			SET status=CASE
			  WHEN unresolved_accounts > 0 THEN 'unresolved'
			  ELSE 'auditing'
			END,
			completed_at=now()
			WHERE id=$1
		`, *run.CoverageGenerationID); err != nil {
			return false, err
		}
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
		for key, value := range map[string]string{
			"initial_enumerated_users": strconv.FormatInt(run.EnumeratedUsers, 10),
			"initial_processed_users":  strconv.FormatInt(run.ProcessedUsers, 10),
		} {
			if err := setStateTx(ctx, tx, key, value); err != nil {
				return false, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func (s *Store) Enqueue(ctx context.Context, source string, candidates []model.Candidate) (int64, error) {
	if source != "tail" && source != "priority" && source != "onboarding" &&
		source != "reconcile" && source != "anomaly" {
		return 0, errors.New("invalid non-global queue source")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	inserted, err := enqueuePageTx(ctx, tx, source, candidates)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return int64(len(inserted)), nil
}

func enqueuePageTx(
	ctx context.Context, tx pgx.Tx, source string, candidates []model.Candidate,
) ([]int64, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	githubIDs := make([]int64, len(candidates))
	nodeIDs := make([]string, len(candidates))
	logins := make([]string, len(candidates))
	for index, candidate := range candidates {
		githubIDs[index] = candidate.GitHubID
		nodeIDs[index] = candidate.NodeID
		logins[index] = candidate.Login
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO account_queue (source, github_id, node_id, login)
		SELECT $1, github_id, node_id, login
		FROM unnest($2::bigint[], $3::text[], $4::text[])
		  AS input(github_id, node_id, login)
		ON CONFLICT DO NOTHING
		RETURNING github_id
	`, source, githubIDs, nodeIDs, logins)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inserted := make([]int64, 0, len(candidates))
	for rows.Next() {
		var githubID int64
		if err := rows.Scan(&githubID); err != nil {
			return nil, err
		}
		inserted = append(inserted, githubID)
	}
	return inserted, rows.Err()
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

func (s *Store) EnqueueDueAnomalies(ctx context.Context, limit int) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `
		INSERT INTO account_queue (
		  source, github_id, node_id, login,
		  coverage_generation_id, coverage_partition_id
		)
		SELECT 'anomaly', a.github_id, a.node_id, a.login,
		       a.generation_id, a.partition_id
		FROM scan_anomalies AS a
		WHERE a.next_attempt_at <= now()
		  AND NOT EXISTS (
		    SELECT 1 FROM account_queue AS q WHERE q.github_id=a.github_id
		  )
		ORDER BY a.next_attempt_at, a.github_id
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

func (s *Store) SaveStatusSnapshot(ctx context.Context) error {
	status, err := s.Status(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(status)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO service_snapshots (name, payload, updated_at)
		VALUES ('status', $1::jsonb, now())
		ON CONFLICT (name) DO UPDATE SET
		  payload=excluded.payload, updated_at=excluded.updated_at
	`, payload)
	return err
}

func (s *Store) LoadStatusSnapshot(
	ctx context.Context,
) (map[string]any, time.Time, error) {
	var raw []byte
	var updated time.Time
	if err := s.Pool.QueryRow(ctx, `
		SELECT payload, updated_at FROM service_snapshots WHERE name='status'
	`).Scan(&raw, &updated); err != nil {
		return nil, time.Time{}, err
	}
	var status map[string]any
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, time.Time{}, err
	}
	return status, updated, nil
}

func (s *Store) SaveRateSample(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO crawler_rate_samples (
		  sampled_at, processed_users, enumerated_users
		)
		SELECT date_trunc('minute', now()),
		       COALESCE(SUM(processed_users), 0),
		       COALESCE(SUM(enumerated_users), 0)
		FROM crawl_runs
		ON CONFLICT (sampled_at) DO UPDATE SET
		  processed_users=excluded.processed_users,
		  enumerated_users=excluded.enumerated_users;
		DELETE FROM crawler_rate_samples
		WHERE sampled_at < now() - interval '7 days'
	`)
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
		       inaccessible_users, error_users, coverage_version,
		       coverage_generation_id, settled_cutoff, started_at, completed_at
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
	var remainingShardIDs, observedShardIDs, observedShardUsers int64
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
				observedShardIDs += max(int64(0), nextSince-lowerID)
				observedShardUsers += enumerated
				remainingShardIDs += max(int64(0), upperID-nextSince)
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
	var enumerationStartedAt *time.Time
	var enumerationLastSuccessAt *time.Time
	var enumerationProcessedUsers int64
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
		switch worker.Role {
		case "SSH key batch worker":
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
		case "parallel global account enumeration":
			enumerationProcessedUsers += worker.ProcessedUsers
			if enumerationStartedAt == nil || worker.StartedAt.Before(*enumerationStartedAt) {
				value := worker.StartedAt
				enumerationStartedAt = &value
			}
			if worker.LastSuccessAt != nil &&
				(enumerationLastSuccessAt == nil || worker.LastSuccessAt.After(*enumerationLastSuccessAt)) {
				value := *worker.LastSuccessAt
				enumerationLastSuccessAt = &value
			}
		}
	}
	var sessionUsersPerHour float64
	var sessionElapsedHours float64
	if sessionStartedAt != nil && sessionLastSuccessAt != nil &&
		sessionLastSuccessAt.After(*sessionStartedAt) {
		sessionElapsedHours = sessionLastSuccessAt.Sub(*sessionStartedAt).Hours()
		sessionUsersPerHour = float64(sessionProcessedUsers) / sessionElapsedHours
	}
	var enumerationUsersPerHour float64
	var enumerationElapsedHours float64
	if enumerationStartedAt != nil && enumerationLastSuccessAt != nil &&
		enumerationLastSuccessAt.After(*enumerationStartedAt) {
		enumerationElapsedHours = enumerationLastSuccessAt.Sub(*enumerationStartedAt).Hours()
		enumerationUsersPerHour = float64(enumerationProcessedUsers) / enumerationElapsedHours
	}
	var rollingOneHour, rollingSixHours float64
	if err := s.Pool.QueryRow(ctx, `
		WITH one_hour AS (
		  SELECT MIN(sampled_at) AS first_at, MAX(sampled_at) AS last_at,
		         MIN(processed_users) AS first_value,
		         MAX(processed_users) AS last_value
		  FROM crawler_rate_samples WHERE sampled_at >= now()-interval '1 hour'
		), six_hours AS (
		  SELECT MIN(sampled_at) AS first_at, MAX(sampled_at) AS last_at,
		         MIN(processed_users) AS first_value,
		         MAX(processed_users) AS last_value
		  FROM crawler_rate_samples WHERE sampled_at >= now()-interval '6 hours'
		)
		SELECT
		  COALESCE((one_hour.last_value-one_hour.first_value) /
		    NULLIF(EXTRACT(epoch FROM one_hour.last_at-one_hour.first_at)/3600.0, 0), 0),
		  COALESCE((six_hours.last_value-six_hours.first_value) /
		    NULLIF(EXTRACT(epoch FROM six_hours.last_at-six_hours.first_at)/3600.0, 0), 0)
		FROM one_hour, six_hours
	`).Scan(&rollingOneHour, &rollingSixHours); err != nil {
		return nil, err
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
		progress["processing_backlog"] = max(
			int64(0), active.EnumeratedUsers-active.ProcessedUsers,
		)
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
			if enumerationUsersPerHour > 0 {
				progress["current_enumeration_users_per_hour"] = enumerationUsersPerHour
				progress["current_enumeration_elapsed_hours"] = enumerationElapsedHours
			}
			progress["rolling_1h_users_per_hour"] = rollingOneHour
			progress["rolling_6h_users_per_hour"] = rollingSixHours
			etaRate := sessionUsersPerHour
			rateBasis := "current crawler session, including throttling and cooldowns during that session"
			if rollingOneHour > 0 {
				etaRate = rollingOneHour
				rateBasis = "persisted rolling one-hour processing rate across restarts"
			} else if rollingSixHours > 0 {
				etaRate = rollingSixHours
				rateBasis = "persisted rolling six-hour processing rate across restarts"
			}
			if etaRate <= 0 {
				etaRate = wallClockAverage
				rateBasis = "wall-clock average since run start, including downtime and throttling"
			}
			if etaRate > 0 {
				lowTotal, highTotal := estimatedLow, estimatedHigh
				basis := "planning population envelope"
				lowRemaining := max(int64(0), lowTotal-active.ProcessedUsers)
				highRemaining := max(int64(0), highTotal-active.ProcessedUsers)
				lowHours := float64(lowRemaining) / etaRate
				highHours := float64(highRemaining) / etaRate
				if active.EnumerationComplete && active.EnumeratedUsers > 0 {
					lowTotal = active.EnumeratedUsers
					highTotal = active.EnumeratedUsers
					basis = "exact users enumerated for this run"
					lowRemaining = max(int64(0), lowTotal-active.ProcessedUsers)
					highRemaining = lowRemaining
					lowHours = float64(lowRemaining) / etaRate
					highHours = lowHours
				} else if remainingShardIDs > 0 && observedShardIDs > 0 &&
					enumerationUsersPerHour > 0 {
					density := float64(observedShardUsers) / float64(observedShardIDs)
					density = math.Max(0, math.Min(1, density))
					estimatedFutureUsers := int64(math.Ceil(float64(remainingShardIDs) * density))
					backlog := max(int64(0), active.EnumeratedUsers-active.ProcessedUsers)
					lowTotal = active.EnumeratedUsers + estimatedFutureUsers
					highTotal = active.EnumeratedUsers + remainingShardIDs
					lowRemaining = backlog + estimatedFutureUsers
					highRemaining = backlog + remainingShardIDs
					enumerationHours := float64(estimatedFutureUsers) / enumerationUsersPerHour
					conservativeEnumerationHours := float64(remainingShardIDs) / enumerationUsersPerHour
					lowHours = math.Max(float64(lowRemaining)/etaRate, enumerationHours)
					highHours = math.Max(float64(highRemaining)/etaRate, conservativeEnumerationHours)
					basis = "active shard ranges and observed user density"
					rateBasis = "current GraphQL processing and REST enumeration sessions"
					progress["remaining_id_positions"] = remainingShardIDs
					progress["observed_users_per_id"] = density
					progress["estimated_future_users"] = estimatedFutureUsers
					progress["processing_backlog"] = backlog
				}
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
	audit, err := s.CoverageAuditProgress(ctx, time.Now().UTC().Truncate(24*time.Hour))
	if err != nil {
		return nil, err
	}
	auditStatus, _ := s.State(ctx, "coverage_audit_status")
	if auditStatus == "" {
		auditStatus = "pending"
	}
	auditLastError, _ := s.State(ctx, "coverage_audit_last_error")
	auditLastSuccessAt, _ := s.State(ctx, "coverage_audit_last_success_at")
	initialEnumerated, _ := s.StateInt(ctx, "initial_enumerated_users")
	if initialEnumerated == 0 {
		for _, run := range runs {
			if run.Kind == "initial" {
				initialEnumerated = run.EnumeratedUsers
				break
			}
		}
	}
	var searchableGap any
	verificationState := "measuring_searchable_population"
	if audit.Complete {
		gap := max(int64(0), audit.SearchableUsers-initialEnumerated)
		searchableGap = gap
		if initialComplete != "true" {
			verificationState = "initial_crawl_in_progress"
		} else if gap > 0 {
			verificationState = "coverage_gap_detected"
		} else {
			verificationState = "count_consistent"
		}
	}
	var auditedThrough *time.Time
	if audit.NextDay.After(audit.Start) {
		value := audit.NextDay.Add(-24 * time.Hour)
		auditedThrough = &value
	}
	coverageStatus := map[string]any{
		"initial_complete":         initialComplete == "true",
		"live_tail_initialized":    liveTailInitialized == "true",
		"tail_highwater":           highwater,
		"audit_status":             auditStatus,
		"audit_complete":           audit.Complete,
		"audit_days_complete":      audit.DaysComplete,
		"audit_days_total":         audit.DaysTotal,
		"audited_through":          auditedThrough,
		"searchable_users":         audit.SearchableUsers,
		"initial_enumerated_users": initialEnumerated,
		"searchable_user_gap":      searchableGap,
		"verification_state":       verificationState,
		"audit_last_error":         auditLastError,
		"audit_last_success_at":    auditLastSuccessAt,
		"identity_proven":          false,
		"audit_method":             "date-aligned counts with conditional identity repair",
		"historical_retention":     "observed keys and account associations are retained permanently",
		"scope":                    "public GitHub SSH authentication keys observable through the API",
	}
	var generation CoverageGeneration
	err = s.Pool.QueryRow(ctx, `
		SELECT id, run_id, status, cutoff_user_id, settled_cutoff,
		       discovered_accounts, successful_accounts,
		       inaccessible_accounts, unresolved_accounts
		FROM coverage_generations ORDER BY id DESC LIMIT 1
	`).Scan(
		&generation.ID, &generation.RunID, &generation.Status,
		&generation.CutoffUserID, &generation.SettledCutoff,
		&generation.DiscoveredAccounts, &generation.SuccessfulAccounts,
		&generation.InaccessibleAccounts, &generation.UnresolvedAccounts,
	)
	if err == nil {
		var consistent, repairing, unresolved, pending, missing int64
		if err := s.Pool.QueryRow(ctx, `
			SELECT
			  COUNT(*) FILTER (WHERE status IN ('count_consistent','resolved')),
			  COUNT(*) FILTER (WHERE status='repairing'),
			  COUNT(*) FILTER (WHERE status='unresolved'),
			  COUNT(*) FILTER (WHERE status IN ('pending','enumerating')),
			  (SELECT COUNT(*) FROM coverage_partition_ids AS ids
			   JOIN coverage_partitions AS p ON p.id=ids.partition_id
			   WHERE p.generation_id=$1 AND NOT ids.resolved)
			FROM coverage_partitions WHERE generation_id=$1
		`, generation.ID).Scan(
			&consistent, &repairing, &unresolved, &pending, &missing,
		); err != nil {
			return nil, err
		}
		coverageStatus = map[string]any{
			"initial_complete":      initialComplete == "true",
			"live_tail_initialized": liveTailInitialized == "true",
			"tail_highwater":        highwater,
			"generation_id":         generation.ID,
			"generation_run_id":     generation.RunID,
			"generation_status":     generation.Status,
			"settled_cutoff":        generation.SettledCutoff,
			"discovered_accounts":   generation.DiscoveredAccounts,
			"successful_accounts":   generation.SuccessfulAccounts,
			"inaccessible_accounts": generation.InaccessibleAccounts,
			"unresolved_accounts":   generation.UnresolvedAccounts,
			"consistent_partitions": consistent,
			"repairing_partitions":  repairing,
			"unresolved_partitions": unresolved,
			"pending_partitions":    pending,
			"missing_accounts":      missing,
			"audit_status":          generation.Status,
			"audit_complete":        generation.Status == "count_reconciled",
			"audited_through":       generation.SettledCutoff,
			"verification_state":    generation.Status,
			"confidence":            "count_reconciled",
			"identity_proven":       false,
			"audit_last_success_at": auditLastSuccessAt,
			"audit_method":          "date-aligned counts with stable conditional identity repair",
			"historical_retention":  "observed keys and account associations are retained permanently",
			"scope":                 "public GitHub SSH authentication keys observable through the API",
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
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
		"coverage": coverageStatus,
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
