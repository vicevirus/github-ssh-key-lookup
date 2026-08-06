package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"github.com/local/github-ssh-index/internal/model"
	"github.com/local/github-ssh-index/internal/sshkey"
)

func integrationStore(t *testing.T) *Store {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	database, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx); err != nil {
		database.Close()
		t.Fatal(err)
	}
	_, err = database.Pool.Exec(ctx, `
		TRUNCATE crawler_workers, overflow_queue, account_queue, zero_key_rechecks,
		         github_owner_keys, ssh_keys, github_owner_logins, github_owners,
		         crawl_runs, runtime_state RESTART IDENTITY CASCADE
	`)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	return database
}

func parsedTestKey(t *testing.T, offset byte) model.PublicKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index+1) + offset
	}
	public, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatal(err)
	}
	key, err := sshkey.Parse(strings.TrimSpace(
		string(ssh.MarshalAuthorizedKey(public)),
	) + " test@example")
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestRepeatedMigrationDoesNotLockLiveQueueTables(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	tx, err := database.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `LOCK TABLE account_queue IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	migrateContext, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := database.Migrate(migrateContext); err != nil {
		t.Fatalf("repeat migration touched a live queue table: %v", err)
	}
}

func TestGlobalBackpressureCountsOnlyUnattemptedAccounts(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	var runID int64
	if err := database.Pool.QueryRow(ctx, `
		INSERT INTO crawl_runs (
		  kind, next_since_id, next_url, enumerated_users,
		  attempted_users, processed_users
		) VALUES ('initial', 1000, 'https://api.github.com/users?since=1000',
		          1000, 900, 100)
		RETURNING id
	`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	backlog, err := database.GlobalBacklog(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if backlog != 100 {
		t.Fatalf("producer backpressure=%d, want 100 unattempted accounts", backlog)
	}
}

func TestZeroKeyUserIsDiscardedThenDiscoveredOnLaterPass(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	candidate := model.Candidate{GitHubID: 42, NodeID: "U_42", Login: "actor"}
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimAccounts(ctx, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	zero := &model.UserResult{NodeID: "U_42", GitHubID: 42, Login: "actor"}
	if err := database.CompleteAccounts(ctx, jobs, []*model.UserResult{zero}, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var owners int
	if err := database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM github_owners`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if owners != 0 {
		t.Fatalf("zero-key user was retained: %d", owners)
	}

	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err = database.ClaimAccounts(ctx, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	key := parsedTestKey(t, 0)
	withKey := &model.UserResult{
		NodeID: "U_42", GitHubID: 42, Login: "actor", Keys: []model.PublicKey{key},
	}
	if err := database.CompleteAccounts(ctx, jobs, []*model.UserResult{withKey}, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	matches, err := database.Lookup(ctx, key.Text)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].Login != "actor" || !matches[0].CurrentlyPresent {
		t.Fatalf("later key was not discovered: %#v", matches)
	}
}

func TestCompleteObservationMarksRemovedKeyHistorical(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	candidate := model.Candidate{GitHubID: 7, NodeID: "U_7", Login: "alice"}
	key := parsedTestKey(t, 0)
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, _ := database.ClaimAccounts(ctx, 100, false)
	if err := database.CompleteAccounts(ctx, jobs, []*model.UserResult{{
		NodeID: "U_7", GitHubID: 7, Login: "alice", Keys: []model.PublicKey{key},
	}}, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Enqueue(ctx, "priority", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, _ = database.ClaimAccounts(ctx, 100, true)
	if err := database.CompleteAccounts(ctx, jobs, []*model.UserResult{{
		NodeID: "U_7", GitHubID: 7, Login: "alice",
	}}, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	matches, err := database.Lookup(ctx, key.Text)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].CurrentlyPresent || matches[0].RemovedAt == nil {
		t.Fatalf("key was not retained as historical: %#v", matches)
	}
}

func TestOverflowPagesFinalizeOnlyAfterLastPage(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	candidate := model.Candidate{GitHubID: 9, NodeID: "U_9", Login: "many"}
	firstKey := parsedTestKey(t, 0)
	secondKey := parsedTestKey(t, 5)
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimAccounts(ctx, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CompleteAccounts(ctx, jobs, []*model.UserResult{{
		NodeID: "U_9", GitHubID: 9, Login: "many",
		Keys: []model.PublicKey{firstKey}, HasMoreKeys: true,
		NextCursor: "cursor-100", TotalKeyCount: 2,
	}}, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	overflow, err := database.ClaimOverflow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if overflow.Cursor != "cursor-100" {
		t.Fatalf("unexpected overflow cursor %q", overflow.Cursor)
	}
	if err := database.CompleteOverflow(
		ctx, *overflow, []model.PublicKey{secondKey}, false, "", 7*24*time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	if matches, err := database.Lookup(ctx, firstKey.Text); err != nil {
		t.Fatal(err)
	} else if len(matches) != 0 {
		t.Fatalf("unstable first-pass keys became visible: %#v", matches)
	}
	overflow, err = database.ClaimOverflow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if overflow.VerificationPass != 2 || overflow.Cursor != "" {
		t.Fatalf("second verification pass was not started: %#v", overflow)
	}
	if err := database.CompleteOverflow(
		ctx, *overflow, []model.PublicKey{firstKey, secondKey}, false, "", 7*24*time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	for _, fingerprint := range []string{firstKey.Text, secondKey.Text} {
		matches, err := database.Lookup(ctx, fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 1 || !matches[0].CurrentlyPresent {
			t.Fatalf("overflow key not current: %#v", matches)
		}
	}
	snapshot, err := database.SnapshotTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	users, err := database.ListIndexedUsers(ctx, 0, snapshot, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || len(users[0].Keys) != 2 {
		t.Fatalf("indexed user listing omitted overflow keys: %#v", users)
	}
}

func TestCoverageLedgerAndConditionalRepairAreExact(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	if err := database.SetState(ctx, "initial_complete", "true"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetState(ctx, "tail_highwater", "100"); err != nil {
		t.Fatal(err)
	}
	run, err := database.EnsureMainRun(
		ctx, "https://api.github.com/users?since=0&per_page=100",
	)
	if err != nil {
		t.Fatal(err)
	}
	if run.CoverageGenerationID == nil {
		t.Fatal("global run did not create a coverage generation")
	}
	created := time.Date(2020, time.January, 2, 3, 4, 5, 0, time.UTC)
	first := model.Candidate{GitHubID: 42, NodeID: "U_42", Login: "covered"}
	if err := database.ApplyEnumerationPage(
		ctx, run, []model.Candidate{first}, 42,
		"https://api.github.com/users?since=42&per_page=100", false,
	); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimScheduledAccounts(ctx, 100, "global")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CompleteAccountsScheduled(
		ctx, jobs, []*model.UserResult{{
			NodeID: first.NodeID, GitHubID: first.GitHubID,
			Login: first.Login, CreatedAt: created,
		}}, []time.Duration{time.Hour}, nil,
	); err != nil {
		t.Fatal(err)
	}
	var discovered, successful, dayCount int64
	if err := database.Pool.QueryRow(ctx, `
		SELECT discovered_accounts, successful_accounts
		FROM coverage_generations WHERE id=$1
	`, *run.CoverageGenerationID).Scan(&discovered, &successful); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `
		SELECT successful_accounts FROM coverage_day_counts
		WHERE generation_id=$1 AND day=$2
	`, *run.CoverageGenerationID, created).Scan(&dayCount); err != nil {
		t.Fatal(err)
	}
	if discovered != 1 || successful != 1 || dayCount != 1 {
		t.Fatalf(
			"incorrect coverage counters: discovered=%d successful=%d day=%d",
			discovered, successful, dayCount,
		)
	}

	var partitionID int64
	if err := database.Pool.QueryRow(ctx, `
		INSERT INTO coverage_partitions (
		  generation_id, start_at, end_at, status
		) VALUES ($1, $2, $3, 'enumerating') RETURNING id
	`, *run.CoverageGenerationID, created.Truncate(24*time.Hour),
		created.Truncate(24*time.Hour).Add(time.Minute-time.Second)).Scan(&partitionID); err != nil {
		t.Fatal(err)
	}
	partition := CoveragePartition{
		ID: partitionID, GenerationID: *run.CoverageGenerationID,
		Start: created.Truncate(24 * time.Hour),
		End:   created.Truncate(24 * time.Hour).Add(time.Minute - time.Second),
	}
	missing, err := database.StageCoveragePartition(ctx, partition, 2, 2, []model.Candidate{
		first,
		{GitHubID: 43, NodeID: "U_43", Login: "missing"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if missing != 1 {
		t.Fatalf("conditional repair queued %d accounts, want 1", missing)
	}
	jobs, err = database.ClaimScheduledAccounts(ctx, 100, "global")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].GitHubID != 43 || jobs[0].Source != "reconcile" {
		t.Fatalf("conditional repair claimed unexpected jobs: %#v", jobs)
	}
}

func TestClaimLeasesRejectStaleWorkersAndHonorRetryDueTime(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	candidate := model.Candidate{GitHubID: 77, NodeID: "U_77", Login: "leased"}
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	oldJobs, err := database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil || len(oldJobs) != 1 {
		t.Fatalf("initial claim: jobs=%#v err=%v", oldJobs, err)
	}
	if _, err := database.Pool.Exec(ctx, `
		UPDATE account_queue SET lease_expires_at=now()-interval '1 second'
		WHERE id=$1
	`, oldJobs[0].QueueID); err != nil {
		t.Fatal(err)
	}
	if reaped, err := database.ReapExpiredLeases(ctx); err != nil || reaped != 1 {
		t.Fatalf("reap: count=%d err=%v", reaped, err)
	}
	newJobs, err := database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil || len(newJobs) != 1 {
		t.Fatalf("replacement claim: jobs=%#v err=%v", newJobs, err)
	}
	if newJobs[0].ClaimToken == oldJobs[0].ClaimToken {
		t.Fatal("expired claim token was reused")
	}
	if err := database.RequeueAccountsAfter(
		ctx, oldJobs, errors.New("late worker"), time.Hour,
	); err == nil {
		t.Fatal("stale worker was allowed to mutate the replacement claim")
	}
	if err := database.RequeueAccountsAfter(
		ctx, newJobs, errors.New("retry later"), time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	claimed, err := database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil {
		t.Fatal(err)
	}
	if len(claimed) != 0 {
		t.Fatalf("future retry was claimed early: %#v", claimed)
	}
}

func TestRESTFallbackClaimsAreDurableAndExcludedFromGraphQL(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	candidate := model.Candidate{GitHubID: 771, NodeID: "U_771", Login: "fallback"}
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil || len(jobs) != 1 {
		t.Fatalf("GraphQL claim: jobs=%#v err=%v", jobs, err)
	}
	if err := database.MoveAccountsToRESTFallback(ctx, jobs, errors.New("null node")); err != nil {
		t.Fatal(err)
	}
	jobs, err = database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil || len(jobs) != 0 {
		t.Fatalf("REST fallback leaked into GraphQL lane: jobs=%#v err=%v", jobs, err)
	}
	fallback, err := database.ClaimRESTFallback(ctx)
	if err != nil || fallback.GitHubID != candidate.GitHubID || fallback.FallbackAttempts != 1 {
		t.Fatalf("REST fallback claim: job=%#v err=%v", fallback, err)
	}
	if err := database.RequeueRESTFallbackAfter(
		ctx, *fallback, errors.New("temporary REST error"), time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ClaimRESTFallback(ctx); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("future REST retry was claimed early: %v", err)
	}
	if _, err := database.Pool.Exec(ctx, `
		UPDATE account_queue
		SET next_attempt_at=now()-interval '1 second'
		WHERE github_id=$1
	`, candidate.GitHubID); err != nil {
		t.Fatal(err)
	}
	fallback, err = database.ClaimRESTFallback(ctx)
	if err != nil || fallback.FallbackAttempts != 2 {
		t.Fatalf("second REST fallback claim: job=%#v err=%v", fallback, err)
	}
	if _, err := database.Pool.Exec(ctx, `
		UPDATE account_queue SET lease_expires_at=now()-interval '1 second'
		WHERE id=$1
	`, fallback.QueueID); err != nil {
		t.Fatal(err)
	}
	if reaped, err := database.ReapExpiredLeases(ctx); err != nil || reaped != 1 {
		t.Fatalf("reap REST fallback: count=%d err=%v", reaped, err)
	}
	recovered, err := database.ClaimRESTFallback(ctx)
	if err != nil || recovered.FallbackAttempts != 3 {
		t.Fatalf("recovered REST fallback claim: job=%#v err=%v", recovered, err)
	}
}

func TestRESTFallbackBatchClaimsAreBoundedAndRestartSafe(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	candidates := make([]model.Candidate, 150)
	for index := range candidates {
		candidates[index] = model.Candidate{
			GitHubID: int64(10_000 + index),
			NodeID:   "U_" + strconv.Itoa(10_000+index),
			Login:    "repair-" + strconv.Itoa(index),
		}
	}
	if _, err := database.Enqueue(ctx, "reconcile", candidates); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimScheduledAccounts(ctx, 150, "global")
	if err != nil || len(jobs) != 150 {
		t.Fatalf("initial claims=%d err=%v", len(jobs), err)
	}
	if err := database.MoveAccountsToRESTFallback(ctx, jobs, errors.New("null nodes")); err != nil {
		t.Fatal(err)
	}
	first, err := database.ClaimRESTFallbackBatch(ctx, 100)
	if err != nil || len(first) != 100 {
		t.Fatalf("first repair batch=%d err=%v", len(first), err)
	}
	second, err := database.ClaimRESTFallbackBatch(ctx, 100)
	if err != nil || len(second) != 50 {
		t.Fatalf("second repair batch=%d err=%v", len(second), err)
	}
	if err := database.RequeueRESTFallbackBatchAfter(
		ctx, first, errors.New("temporary GraphQL error"), time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ClaimRESTFallbackBatch(ctx, 100); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("future repair batch was claimed early: %v", err)
	}
}

func TestMainRunCannotCompleteWithAnUnresolvedAnomaly(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	var runID int64
	if err := database.Pool.QueryRow(ctx, `
		INSERT INTO crawl_runs (
		  kind, next_url, enumeration_complete, enumerated_users, processed_users
		) VALUES ('initial', 'https://api.github.com/users?since=1', true, 1, 1)
		RETURNING id
	`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO scan_anomalies (
		  github_id, node_id, login, run_id, kind, next_attempt_at, last_error
		) VALUES (991, 'U_991', 'unresolved', $1, 'test', now(), 'test')
	`, runID); err != nil {
		t.Fatal(err)
	}
	if completed, err := database.MaybeCompleteMain(ctx); err != nil || completed {
		t.Fatalf("run completed across unresolved anomaly: completed=%t err=%v", completed, err)
	}
	if _, err := database.Pool.Exec(ctx, `DELETE FROM scan_anomalies WHERE run_id=$1`, runID); err != nil {
		t.Fatal(err)
	}
	if completed, err := database.MaybeCompleteMain(ctx); err != nil || !completed {
		t.Fatalf("settled run did not complete: completed=%t err=%v", completed, err)
	}
}

func TestDueRetryPrecedesPendingWork(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	retryCandidate := model.Candidate{GitHubID: 78, NodeID: "U_78", Login: "retry-first"}
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{retryCandidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil || len(jobs) != 1 {
		t.Fatalf("initial claim: jobs=%#v err=%v", jobs, err)
	}
	if err := database.RequeueAccountsAfter(
		ctx, jobs, errors.New("retry me"), time.Hour,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		UPDATE account_queue SET next_attempt_at=now()-interval '1 second'
		WHERE github_id=$1
	`, retryCandidate.GitHubID); err != nil {
		t.Fatal(err)
	}
	pending := model.Candidate{GitHubID: 79, NodeID: "U_79", Login: "pending-second"}
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{pending}); err != nil {
		t.Fatal(err)
	}
	jobs, err = database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].GitHubID != retryCandidate.GitHubID {
		t.Fatalf("pending work jumped ahead of a due retry: %#v", jobs)
	}
}

func TestMarkAccountsAttemptedIsDurableAndIdempotent(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	var runID int64
	if err := database.Pool.QueryRow(ctx, `
		INSERT INTO crawl_runs (
		  kind, next_since_id, next_url, enumerated_users
		) VALUES (
		  'initial', 42, 'https://api.github.com/users?since=42', 1
		) RETURNING id
	`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO account_queue (
		  run_id, source, github_id, node_id, login
		) VALUES ($1, 'global', 42, 'U_42', 'attempted')
	`, runID); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimScheduledAccounts(ctx, 1, "global")
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: jobs=%#v err=%v", jobs, err)
	}
	// Simulate a crash after the durable per-account observation was written
	// but before its aggregate run counter was advanced.
	if _, err := database.Pool.Exec(ctx, `
		UPDATE account_queue SET first_attempted_at=now() WHERE id=$1
	`, jobs[0].QueueID); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAccountsAttempted(ctx, jobs); err != nil {
		t.Fatal(err)
	}
	if err := database.MarkAccountsAttempted(ctx, jobs); err != nil {
		t.Fatalf("repeated first-attempt mark was not idempotent: %v", err)
	}
	var attempted int64
	var firstAttemptedAt *time.Time
	var firstAttemptCountedAt *time.Time
	if err := database.Pool.QueryRow(ctx, `
		SELECT run.attempted_users, queue.first_attempted_at,
		       queue.first_attempt_counted_at
		FROM crawl_runs AS run
		JOIN account_queue AS queue ON queue.run_id=run.id
		WHERE run.id=$1
	`, runID).Scan(
		&attempted, &firstAttemptedAt, &firstAttemptCountedAt,
	); err != nil {
		t.Fatal(err)
	}
	if attempted != 1 || firstAttemptedAt == nil || firstAttemptCountedAt == nil {
		t.Fatalf(
			"attempt progress was not persisted exactly once: count=%d observed=%v counted=%v",
			attempted, firstAttemptedAt, firstAttemptCountedAt,
		)
	}
}

func TestRunCounterLockDoesNotConflictWithQueueForeignKeys(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	var runID int64
	if err := database.Pool.QueryRow(ctx, `
		INSERT INTO crawl_runs (kind, next_since_id, next_url)
		VALUES ('initial', 0, 'https://api.github.com/users?since=0')
		RETURNING id
	`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	first, err := database.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(ctx)
	second, err := database.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback(ctx)
	for index, tx := range []pgx.Tx{first, second} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO account_queue (
			  run_id, source, github_id, node_id, login
			) VALUES ($1, 'global', $2, $3, $4)
		`, runID, 100+index, "U_"+strconv.Itoa(100+index),
			"queued-"+strconv.Itoa(index)); err != nil {
			t.Fatal(err)
		}
	}
	// The second transaction now holds a foreign-key KEY SHARE lock on the run.
	// A FOR UPDATE counter lock deadlocks here; NO KEY UPDATE is compatible.
	lockContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := lockCrawlRuns(lockContext, first, []int64{runID}); err != nil {
		t.Fatalf("run counter lock conflicted with queue foreign key: %v", err)
	}
}

func TestPersistentOverflowFailureRemainsDurableWithoutPublishingKeys(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	candidate := model.Candidate{GitHubID: 88, NodeID: "U_88", Login: "unstable"}
	firstKey := parsedTestKey(t, 20)
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CompleteAccounts(ctx, jobs, []*model.UserResult{{
		NodeID: candidate.NodeID, GitHubID: candidate.GitHubID,
		Login: candidate.Login, Keys: []model.PublicKey{firstKey},
		HasMoreKeys: true, NextCursor: "cursor-100", TotalKeyCount: 101,
	}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `UPDATE overflow_queue SET attempts=7`); err != nil {
		t.Fatal(err)
	}
	overflow, err := database.ClaimOverflow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if overflow.Attempts != 8 {
		t.Fatalf("overflow attempts=%d, want 8", overflow.Attempts)
	}
	if err := database.RequeueOverflow(
		ctx, *overflow, errors.New("key set kept changing"),
	); err != nil {
		t.Fatal(err)
	}
	var anomalies, overflowRows, scanRows int
	if err := database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_anomalies`).Scan(&anomalies); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM overflow_queue`).Scan(&overflowRows); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM key_scan_attempts`).Scan(&scanRows); err != nil {
		t.Fatal(err)
	}
	if anomalies != 0 || overflowRows != 1 || scanRows != 1 {
		t.Fatalf(
			"bad durable overflow retry state: anomalies=%d overflow=%d scans=%d",
			anomalies, overflowRows, scanRows,
		)
	}
	matches, err := database.Lookup(ctx, firstKey.Text)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("unverified overflow key became visible: %#v", matches)
	}
}

func TestRESTOverflowCompletionPublishesOnlyTheFullSnapshot(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	candidate := model.Candidate{GitHubID: 881, NodeID: "U_881", Login: "large"}
	firstKey := parsedTestKey(t, 21)
	secondKey := parsedTestKey(t, 22)
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimScheduledAccounts(ctx, 1, "live")
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: jobs=%#v err=%v", jobs, err)
	}
	if err := database.CompleteAccounts(ctx, jobs, []*model.UserResult{{
		NodeID: candidate.NodeID, GitHubID: candidate.GitHubID,
		Login: candidate.Login, CreatedAt: time.Now().Add(-time.Hour),
		Keys: []model.PublicKey{firstKey}, HasMoreKeys: true,
		NextCursor: "cursor-100", TotalKeyCount: 101,
	}}, time.Hour); err != nil {
		t.Fatal(err)
	}
	overflow, err := database.ClaimOverflow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().Add(-24 * time.Hour).UTC()
	if err := database.CompleteOverflowFromREST(ctx, *overflow, &model.UserResult{
		NodeID: candidate.NodeID, GitHubID: candidate.GitHubID,
		Login: candidate.Login, CreatedAt: createdAt,
		Keys: []model.PublicKey{firstKey, secondKey}, TotalKeyCount: 2,
	}, []time.Duration{time.Hour}); err != nil {
		t.Fatal(err)
	}
	var overflowRows, scanRows int
	if err := database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM overflow_queue`).Scan(&overflowRows); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM key_scan_attempts`).Scan(&scanRows); err != nil {
		t.Fatal(err)
	}
	if overflowRows != 0 || scanRows != 0 {
		t.Fatalf("REST overflow cleanup incomplete: overflow=%d scans=%d", overflowRows, scanRows)
	}
	for _, key := range []model.PublicKey{firstKey, secondKey} {
		matches, err := database.Lookup(ctx, key.Text)
		if err != nil || len(matches) != 1 || matches[0].GitHubID != candidate.GitHubID {
			t.Fatalf("REST overflow key missing: key=%s matches=%#v err=%v", key.Text, matches, err)
		}
	}
}

func TestIndexedUsersUseKeysetPagination(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	for index, githubID := range []int64{10, 20, 30} {
		candidate := model.Candidate{
			GitHubID: githubID,
			NodeID:   "U_" + string(rune('A'+index)),
			Login:    "owner-" + string(rune('a'+index)),
		}
		if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
			t.Fatal(err)
		}
		jobs, err := database.ClaimAccounts(ctx, 100, false)
		if err != nil {
			t.Fatal(err)
		}
		result := &model.UserResult{
			NodeID: candidate.NodeID, GitHubID: githubID, Login: candidate.Login,
			Keys: []model.PublicKey{parsedTestKey(t, byte(index))},
		}
		if err := database.CompleteAccounts(
			ctx, jobs, []*model.UserResult{result}, 7*24*time.Hour,
		); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := database.SnapshotTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := database.ListIndexedUsers(ctx, 0, snapshot, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].GitHubID != 10 || first[1].GitHubID != 20 {
		t.Fatalf("unexpected first page: %#v", first)
	}

	late := model.Candidate{GitHubID: 25, NodeID: "U_LATE", Login: "owner-late"}
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{late}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimAccounts(ctx, 100, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CompleteAccounts(ctx, jobs, []*model.UserResult{{
		NodeID: late.NodeID, GitHubID: late.GitHubID, Login: late.Login,
		Keys: []model.PublicKey{parsedTestKey(t, 10)},
	}}, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}

	second, err := database.ListIndexedUsers(ctx, first[1].GitHubID, snapshot, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].GitHubID != 30 {
		t.Fatalf("snapshot changed between pages: %#v", second)
	}

	freshSnapshot, err := database.SnapshotTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := database.ListIndexedUsers(ctx, first[1].GitHubID, freshSnapshot, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 2 || fresh[0].GitHubID != 25 || fresh[1].GitHubID != 30 {
		t.Fatalf("fresh snapshot omitted late owner: %#v", fresh)
	}
}

func TestStatusIncludesWorkerActivity(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO crawl_runs (
		  kind, next_url, enumeration_complete, enumerated_users,
		  processed_users, started_at
		) VALUES (
		  'initial', 'https://api.github.com/users?since=1000',
		  false, 1500, 1000, now() - interval '1 hour'
		)
	`); err != nil {
		t.Fatal(err)
	}
	if err := database.SetState(ctx, "estimated_accounts_low", "2000"); err != nil {
		t.Fatal(err)
	}
	if err := database.SetState(ctx, "estimated_accounts_high", "3000"); err != nil {
		t.Fatal(err)
	}
	candidates := []model.Candidate{
		{GitHubID: 99, NodeID: "U_99", Login: "retry-user"},
		{GitHubID: 100, NodeID: "U_100", Login: "resource-user"},
	}
	if _, err := database.Enqueue(ctx, "tail", candidates); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimAccounts(ctx, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RequeueAccounts(ctx, jobs, errors.New("temporary test failure")); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		UPDATE account_queue SET status='rest_fallback' WHERE github_id=100
	`); err != nil {
		t.Fatal(err)
	}
	remaining, limit := 4999, 5000
	reset := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := database.UpdateWorker(ctx, WorkerUpdate{
		Name: "graphql-0", Role: "SSH key batch worker", State: "running",
		Activity: "indexed SSH key batch", ProcessedUsers: 100,
		ProcessedKeys: 3, Request: true, RateRemaining: &remaining,
		RateLimit: &limit, RateResetAt: &reset, Success: true,
	}); err != nil {
		t.Fatal(err)
	}
	status, err := database.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	workers, ok := status["workers"].([]WorkerStatus)
	if !ok || len(workers) != 1 {
		t.Fatalf("worker status missing: %#v", status["workers"])
	}
	if workers[0].ProcessedUsers != 100 || workers[0].RateRemaining == nil ||
		*workers[0].RateRemaining != 4999 {
		t.Fatalf("unexpected worker status: %#v", workers[0])
	}
	crawler, ok := status["crawler"].(map[string]any)
	if !ok || crawler["online"] != true {
		t.Fatalf("crawler should be online: %#v", status["crawler"])
	}
	recovery, ok := status["recovery"].(map[string]any)
	if !ok || recovery["state"] != "recovering" ||
		recovery["retrying_jobs"] != int64(1) {
		t.Fatalf("retry recovery status missing: %#v", status["recovery"])
	}
	progress, ok := status["progress"].(map[string]any)
	if !ok || progress["estimated_completion"] == nil {
		t.Fatalf("estimated completion missing: %#v", status["progress"])
	}
}

func TestStatusEstimatesCompletionFromLiveShardRanges(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	var runID int64
	if err := database.Pool.QueryRow(ctx, `
		INSERT INTO crawl_runs (
		  kind, cutoff_user_id, next_since_id, next_url,
		  enumeration_complete, enumerated_users, attempted_users,
		  processed_users, started_at
		) VALUES (
		  'initial', 2000, 1000, 'https://api.github.com/users?since=1000',
		  false, 800, 500, 500, now() - interval '1 hour'
		) RETURNING id
	`).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO enumeration_shards (
		  run_id, lower_id, upper_id, next_since_id, next_url,
		  status, enumerated_users
		) VALUES (
		  $1, 0, 2000, 1000, 'https://api.github.com/users?since=1000',
		  'running', 800
		)
	`, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		INSERT INTO crawler_workers (
		  name, role, state, activity, processed_users,
		  last_success_at, started_at, heartbeat_at
		) VALUES (
		  'graphql-0', 'SSH key batch worker', 'running', 'working', 400,
		  now(), now() - interval '1 hour', now()
		)
	`); err != nil {
		t.Fatal(err)
	}

	status, err := database.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	progress := status["progress"].(map[string]any)
	estimate := progress["estimated_completion"].(map[string]any)
	if estimate["basis"] != "active shard ranges and observed user density" {
		t.Fatalf("status used stale population envelope: %#v", estimate)
	}
	if progress["remaining_id_positions"] != int64(1000) ||
		progress["estimated_future_users"] != int64(800) ||
		progress["processing_backlog"] != int64(300) {
		t.Fatalf("unexpected live range estimate: %#v", progress)
	}
	if estimate["estimated_total_low"] != int64(1600) ||
		estimate["estimated_total_high"] != int64(1800) {
		t.Fatalf("unexpected estimate bounds: %#v", estimate)
	}
	passes := status["passes"].(map[string]any)
	first := passes["first"].(map[string]any)
	if first["unattempted_discovered_users"] != int64(300) ||
		first["estimated_remaining_observations_low"] != int64(1100) ||
		first["estimated_remaining_observations_high"] != int64(1300) {
		t.Fatalf("unexpected first-pass progress: %#v", first)
	}
}

func TestCoverageAuditDateCheckpointsAreRestartSafe(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	if err := database.SaveCoverageAuditDay(ctx, CoverageAuditEpoch, 10); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveCoverageAuditDay(ctx, CoverageAuditEpoch.Add(24*time.Hour), 20); err != nil {
		t.Fatal(err)
	}
	// Re-saving the last durable day simulates a retry after an uncertain
	// process exit. It replaces the partition count instead of double-counting.
	if err := database.SaveCoverageAuditDay(ctx, CoverageAuditEpoch.Add(24*time.Hour), 21); err != nil {
		t.Fatal(err)
	}
	cutoff := CoverageAuditEpoch.Add(3 * 24 * time.Hour)
	progress, err := database.CoverageAuditProgress(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Complete || progress.DaysComplete != 2 || progress.DaysTotal != 3 ||
		progress.SearchableUsers != 31 ||
		!progress.NextDay.Equal(CoverageAuditEpoch.Add(2*24*time.Hour)) {
		t.Fatalf("unexpected durable audit progress: %#v", progress)
	}
	if err := database.SaveCoverageAuditDay(ctx, progress.NextDay, 30); err != nil {
		t.Fatal(err)
	}
	progress, err = database.CoverageAuditProgress(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if !progress.Complete || progress.SearchableUsers != 61 || !progress.NextDay.Equal(cutoff) {
		t.Fatalf("audit did not complete exactly once: %#v", progress)
	}
}

func TestCompletedInitialRunStartsGlobalReconciliationAtZero(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	run, err := database.EnsureMainRun(ctx, "https://api.github.com/users?since=0&per_page=100")
	if err != nil {
		t.Fatal(err)
	}
	if run.Kind != "initial" {
		t.Fatalf("first run kind = %q", run.Kind)
	}
	if err := database.ApplyEnumerationPage(
		ctx, run, nil, 123, "https://api.github.com/users?since=123&per_page=100", true,
	); err != nil {
		t.Fatal(err)
	}
	completed, err := database.MaybeCompleteMain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !completed {
		t.Fatal("initial run did not complete")
	}
	next, err := database.EnsureMainRun(ctx, "https://api.github.com/users?since=0&per_page=100")
	if err != nil {
		t.Fatal(err)
	}
	if next.Kind != "global" || next.CutoffUserID == nil || *next.CutoffUserID != 123 {
		t.Fatalf("unexpected reconciliation run: %#v", next)
	}
	if next.NextSinceID != 0 {
		t.Fatalf("reconciliation did not restart at zero: %d", next.NextSinceID)
	}
}

func TestParallelTailInitializationPreservesBackfillAndHighwater(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	run, err := database.EnsureMainRun(
		ctx, "https://api.github.com/users?since=0&per_page=100",
	)
	if err != nil {
		t.Fatal(err)
	}
	created, err := database.InitializeLiveTail(
		ctx, 1_000, "https://api.github.com/users?since=1000&per_page=100",
	)
	if err != nil || !created {
		t.Fatalf("initialize live tail: created=%v err=%v", created, err)
	}
	active, err := database.ActiveMainRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if active.CutoffUserID == nil || *active.CutoffUserID != 1_000 ||
		active.NextSinceID != run.NextSinceID {
		t.Fatalf("backfill checkpoint or cutoff changed incorrectly: %#v", active)
	}
	if err := database.ApplyTailPage(
		ctx, nil, 1_025,
		"https://api.github.com/users?since=1025&per_page=100", "",
	); err != nil {
		t.Fatal(err)
	}
	if err := database.ApplyEnumerationPage(
		ctx, active, nil, 1_000,
		"https://api.github.com/users?since=1000&per_page=100", true,
	); err != nil {
		t.Fatal(err)
	}
	highwater, err := database.StateInt(ctx, "tail_highwater")
	if err != nil {
		t.Fatal(err)
	}
	if highwater != 1_025 {
		t.Fatalf("historical completion regressed live highwater to %d", highwater)
	}
	created, err = database.InitializeLiveTail(
		ctx, 2_000, "https://api.github.com/users?since=2000&per_page=100",
	)
	if err != nil || created {
		t.Fatalf("live tail initialization was not idempotent: created=%v err=%v", created, err)
	}
}

func TestEnumerationShardsAreNotDuplicatedAfterRestart(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	run, err := database.EnsureMainRun(
		ctx, "https://api.github.com/users?since=0&per_page=100",
	)
	if err != nil {
		t.Fatal(err)
	}
	cutoff := int64(1_000)
	run.CutoffUserID = &cutoff
	run.NextSinceID = 0
	urlFor := func(since int64) string {
		return "https://api.github.com/users?since=" + strconv.FormatInt(since, 10)
	}
	if err := database.EnsureEnumerationShards(ctx, run, 4, urlFor); err != nil {
		t.Fatal(err)
	}
	// A restarted process sees a later moving run checkpoint but must reuse
	// the durable shard set instead of creating overlapping ranges.
	run.NextSinceID = 250
	if err := database.EnsureEnumerationShards(ctx, run, 4, urlFor); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM enumeration_shards WHERE run_id = $1
	`, run.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("restart created duplicate shard set: %d shards", count)
	}
}

func TestSeedEnumerationRepairIsDurableContiguousAndIdempotent(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	run, err := database.EnsureMainRun(
		ctx, "https://api.github.com/users?since=0&per_page=100",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.InitializeLiveTail(
		ctx, 1_000, "https://api.github.com/users?since=1000&per_page=100",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool.Exec(ctx, `
		UPDATE crawl_runs SET enumeration_complete=true WHERE id=$1
	`, run.ID); err != nil {
		t.Fatal(err)
	}
	urlFor := func(since int64) string {
		return "https://api.github.com/users?since=" + strconv.FormatInt(since, 10)
	}
	inserted, err := database.SeedEnumerationRepair(ctx, 100, 900, 4, urlFor)
	if err != nil || inserted != 4 {
		t.Fatalf("seed repair: inserted=%d err=%v", inserted, err)
	}
	inserted, err = database.SeedEnumerationRepair(ctx, 100, 900, 4, urlFor)
	if err != nil || inserted != 0 {
		t.Fatalf("idempotent repair seed: inserted=%d err=%v", inserted, err)
	}

	rows, err := database.Pool.Query(ctx, `
		SELECT purpose, lower_id, upper_id, next_since_id, next_url
		FROM enumeration_shards WHERE run_id=$1 ORDER BY lower_id
	`, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ranges [][2]int64
	for rows.Next() {
		var lower, upper, nextSince int64
		var purpose, nextURL string
		if err := rows.Scan(&purpose, &lower, &upper, &nextSince, &nextURL); err != nil {
			t.Fatal(err)
		}
		if purpose != "repair" {
			t.Fatalf("seeded shard purpose=%q, want repair", purpose)
		}
		if nextSince != lower || nextURL != urlFor(lower) {
			t.Fatalf("repair checkpoint was not initialized at lower bound: %d %q", nextSince, nextURL)
		}
		ranges = append(ranges, [2]int64{lower, upper})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 4 || ranges[0][0] != 100 || ranges[3][1] != 900 {
		t.Fatalf("unexpected repair ranges: %#v", ranges)
	}
	for index := 1; index < len(ranges); index++ {
		if ranges[index-1][1] != ranges[index][0] {
			t.Fatalf("repair ranges contain a gap: %#v", ranges)
		}
	}
	var complete bool
	if err := database.Pool.QueryRow(ctx, `
		SELECT enumeration_complete FROM crawl_runs WHERE id=$1
	`, run.ID).Scan(&complete); err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("repair seed left the active run marked complete")
	}
}

func TestClaimEnumerationShardPrioritizesHistoricalRepair(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	run, err := database.EnsureMainRun(
		ctx, "https://api.github.com/users?since=0&per_page=100",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.InitializeLiveTail(
		ctx, 1_000, "https://api.github.com/users?since=1000&per_page=100",
	); err != nil {
		t.Fatal(err)
	}
	run, err = database.ActiveMainRun(ctx)
	if err != nil {
		t.Fatal(err)
	}
	urlFor := func(since int64) string {
		return "https://api.github.com/users?since=" + strconv.FormatInt(since, 10)
	}
	if err := database.EnsureEnumerationShards(ctx, run, 2, urlFor); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SeedEnumerationRepair(ctx, 101, 901, 2, urlFor); err != nil {
		t.Fatal(err)
	}
	claimed, err := database.ClaimEnumerationShard(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Purpose != "repair" || claimed.LowerID != 101 {
		t.Fatalf("claimed %#v, want earliest historical repair shard", claimed)
	}
}

func TestOwnedEnumerationShardRebalancesIdleWorkersWithoutGaps(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	run, err := database.EnsureMainRun(
		ctx, "https://api.github.com/users?since=0&per_page=100",
	)
	if err != nil {
		t.Fatal(err)
	}
	cutoff := int64(1_000)
	run.CutoffUserID = &cutoff
	urlFor := func(since int64) string {
		return "https://api.github.com/users?since=" + strconv.FormatInt(since, 10)
	}
	if err := database.EnsureEnumerationShards(ctx, run, 2, urlFor); err != nil {
		t.Fatal(err)
	}
	owned, err := database.ClaimEnumerationShard(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	newUpper, err := database.RebalanceOwnedEnumerationShard(
		ctx, owned, 4, urlFor,
	)
	if err != nil {
		t.Fatal(err)
	}
	if newUpper <= owned.NextSinceID || newUpper >= owned.UpperID {
		t.Fatalf("owned range was not shortened: %d", newUpper)
	}

	rows, err := database.Pool.Query(ctx, `
		SELECT lower_id, upper_id
		FROM enumeration_shards
		WHERE run_id = $1 AND status <> 'completed'
		ORDER BY lower_id
	`, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ranges [][2]int64
	for rows.Next() {
		var lower, upper int64
		if err := rows.Scan(&lower, &upper); err != nil {
			t.Fatal(err)
		}
		ranges = append(ranges, [2]int64{lower, upper})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 4 {
		t.Fatalf("active ranges = %d, want 4: %#v", len(ranges), ranges)
	}
	if ranges[0][0] != 0 || ranges[len(ranges)-1][1] != cutoff {
		t.Fatalf("coverage endpoints changed: %#v", ranges)
	}
	for index := 1; index < len(ranges); index++ {
		if ranges[index-1][1] != ranges[index][0] {
			t.Fatalf("gap or overlap between ranges: %#v", ranges)
		}
	}
}

func TestZeroKeyOnboardingLadderFindsAndRetainsLaterKey(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	ownerSchedule := []time.Duration{time.Hour, 2 * time.Hour}
	recheckAges := []time.Duration{
		time.Hour, 2 * time.Hour, 3 * time.Hour, 4 * time.Hour,
	}
	candidate := model.Candidate{
		GitHubID: 501, NodeID: "U_501", Login: "late-key-owner",
	}
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimScheduledAccounts(ctx, 100, "live")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CompleteAccountsScheduled(
		ctx, jobs, []*model.UserResult{{
			NodeID: candidate.NodeID, GitHubID: candidate.GitHubID,
			Login: candidate.Login,
		}}, ownerSchedule, recheckAges,
	); err != nil {
		t.Fatal(err)
	}
	var stage int
	if err := database.Pool.QueryRow(ctx, `
		SELECT stage FROM zero_key_rechecks WHERE github_id = $1
	`, candidate.GitHubID).Scan(&stage); err != nil {
		t.Fatal(err)
	}
	if stage != 0 {
		t.Fatalf("initial zero-key stage = %d", stage)
	}
	if _, err := database.Pool.Exec(ctx, `
		UPDATE zero_key_rechecks SET next_scan_at = now() - interval '1 second'
		WHERE github_id = $1
	`, candidate.GitHubID); err != nil {
		t.Fatal(err)
	}
	if inserted, err := database.EnqueueDueZeroKeyRechecks(ctx, 100); err != nil {
		t.Fatal(err)
	} else if inserted != 1 {
		t.Fatalf("due zero-key jobs inserted = %d", inserted)
	}
	jobs, err = database.ClaimScheduledAccounts(ctx, 100, "live")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Source != "onboarding" {
		t.Fatalf("unexpected onboarding jobs: %#v", jobs)
	}
	key := parsedTestKey(t, 11)
	if err := database.CompleteAccountsScheduled(
		ctx, jobs, []*model.UserResult{{
			NodeID: candidate.NodeID, GitHubID: candidate.GitHubID,
			Login: candidate.Login, Keys: []model.PublicKey{key},
		}}, ownerSchedule, recheckAges,
	); err != nil {
		t.Fatal(err)
	}
	var tracked int
	if err := database.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM zero_key_rechecks WHERE github_id = $1
	`, candidate.GitHubID).Scan(&tracked); err != nil {
		t.Fatal(err)
	}
	if tracked != 0 {
		t.Fatalf("key owner remained in zero-key ladder: %d", tracked)
	}

	if _, err := database.Enqueue(ctx, "priority", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err = database.ClaimScheduledAccounts(ctx, 100, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CompleteAccountsScheduled(
		ctx, jobs, []*model.UserResult{{
			NodeID: candidate.NodeID, GitHubID: candidate.GitHubID,
			Login: candidate.Login,
		}}, ownerSchedule, recheckAges,
	); err != nil {
		t.Fatal(err)
	}
	matches, err := database.Lookup(ctx, key.Text)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0].CurrentlyPresent || matches[0].RemovedAt == nil {
		t.Fatalf("deleted key was not retained historically: %#v", matches)
	}
}

func TestAdaptiveOwnerRefreshResetsWhenKeySetChanges(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	schedule := []time.Duration{time.Hour, 2 * time.Hour, 3 * time.Hour}
	candidate := model.Candidate{GitHubID: 601, NodeID: "U_601", Login: "adaptive"}
	key := parsedTestKey(t, 12)
	observe := func(keys []model.PublicKey) {
		t.Helper()
		if _, err := database.Enqueue(
			ctx, "priority", []model.Candidate{candidate},
		); err != nil {
			t.Fatal(err)
		}
		jobs, err := database.ClaimScheduledAccounts(ctx, 100, "owner")
		if err != nil {
			t.Fatal(err)
		}
		if err := database.CompleteAccountsScheduled(
			ctx, jobs, []*model.UserResult{{
				NodeID: candidate.NodeID, GitHubID: candidate.GitHubID,
				Login: candidate.Login, Keys: keys,
			}}, schedule, nil,
		); err != nil {
			t.Fatal(err)
		}
	}
	observe([]model.PublicKey{key})
	observe([]model.PublicKey{key})
	var stage int
	if err := database.Pool.QueryRow(ctx, `
		SELECT refresh_stage FROM github_owners WHERE github_id = $1
	`, candidate.GitHubID).Scan(&stage); err != nil {
		t.Fatal(err)
	}
	if stage != 1 {
		t.Fatalf("stable owner did not back off: stage=%d", stage)
	}
	observe(nil)
	if err := database.Pool.QueryRow(ctx, `
		SELECT refresh_stage FROM github_owners WHERE github_id = $1
	`, candidate.GitHubID).Scan(&stage); err != nil {
		t.Fatal(err)
	}
	if stage != 0 {
		t.Fatalf("changed owner did not reset: stage=%d", stage)
	}
}

func TestCrawlerAdvisoryLockIsExclusive(t *testing.T) {
	database := integrationStore(t)
	ctx := context.Background()
	release, err := database.AcquireCrawlerLock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AcquireCrawlerLock(ctx); err == nil {
		t.Fatal("second crawler acquired singleton lock")
	}
	release()
	secondRelease, err := database.AcquireCrawlerLock(ctx)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	secondRelease()
}
