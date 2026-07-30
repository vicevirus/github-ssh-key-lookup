package store

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
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
		TRUNCATE crawler_workers, overflow_queue, account_queue, github_owner_keys,
		         ssh_keys, github_owner_logins, github_owners,
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
	users, err := database.ListIndexedUsers(ctx, 0, 100)
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
	first, err := database.ListIndexedUsers(ctx, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].GitHubID != 10 || first[1].GitHubID != 20 {
		t.Fatalf("unexpected first page: %#v", first)
	}
	second, err := database.ListIndexedUsers(ctx, first[1].GitHubID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].GitHubID != 30 {
		t.Fatalf("unexpected second page: %#v", second)
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
