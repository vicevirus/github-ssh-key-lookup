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
		Keys: []model.PublicKey{firstKey}, HasMoreKeys: true, NextCursor: "cursor-100",
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
	candidate := model.Candidate{GitHubID: 99, NodeID: "U_99", Login: "retry-user"}
	if _, err := database.Enqueue(ctx, "tail", []model.Candidate{candidate}); err != nil {
		t.Fatal(err)
	}
	jobs, err := database.ClaimAccounts(ctx, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RequeueAccounts(ctx, jobs, errors.New("temporary test failure")); err != nil {
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
		  enumeration_complete, enumerated_users, processed_users, started_at
		) VALUES (
		  'initial', 2000, 1000, 'https://api.github.com/users?since=1000',
		  false, 800, 500, now() - interval '1 hour'
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
		) VALUES
		  ('graphql-0', 'SSH key batch worker', 'running', 'working', 400,
		   now(), now() - interval '1 hour', now()),
		  ('rest-enumerator-0', 'parallel global account enumeration',
		   'running', 'working', 400, now(), now() - interval '1 hour', now())
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
