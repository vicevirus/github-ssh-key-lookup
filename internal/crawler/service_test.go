package crawler

import (
	"errors"
	"testing"
	"time"

	"github.com/local/github-ssh-index/internal/githubapi"
	"github.com/local/github-ssh-index/internal/model"
	"github.com/local/github-ssh-index/internal/sshkey"
)

func TestNormalizeUsersRejectsReorderedNodes(t *testing.T) {
	jobs := []model.Candidate{{GitHubID: 1, NodeID: "U_1"}}
	nodes := []*githubapi.GraphQLUser{{TypeName: "User", ID: "U_2", DatabaseID: 2}}
	results, resultErrors, err := normalizeUsers(jobs, nodes)
	if err != nil || len(results) != 1 || resultErrors[0] == nil {
		t.Fatal("accepted reordered GraphQL node")
	}
}

func TestNormalizeUsersPreservesNullNode(t *testing.T) {
	jobs := []model.Candidate{{GitHubID: 1, NodeID: "U_1"}}
	results, resultErrors, err := normalizeUsers(jobs, []*githubapi.GraphQLUser{nil})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0] != nil || resultErrors[0] != nil {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestNormalizeResourceUsersAcceptsMigratedNodeIDButChecksDatabaseID(t *testing.T) {
	jobs := []model.Candidate{{GitHubID: 1, NodeID: "legacy", Login: "old-login"}}
	nodes := []*githubapi.GraphQLUser{{
		TypeName: "User", ID: "U_new", DatabaseID: 1, Login: "new-login",
		CreatedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		PublicKeys: githubapi.KeyConnection{
			TotalCount: 0,
			PageInfo:   githubapi.PageInfo{HasNextPage: false},
		},
	}}
	results, resultErrors, err := normalizeResourceUsers(jobs, nodes)
	if err != nil || resultErrors[0] != nil || results[0] == nil ||
		results[0].NodeID != "U_new" || results[0].Login != "new-login" {
		t.Fatalf("current URL identity was not accepted: results=%#v errors=%#v err=%v",
			results, resultErrors, err)
	}
	nodes[0].DatabaseID = 2
	results, resultErrors, err = normalizeResourceUsers(jobs, nodes)
	if err != nil || results[0] != nil || resultErrors[0] == nil {
		t.Fatalf("resource identity mismatch was accepted: results=%#v errors=%#v err=%v",
			results, resultErrors, err)
	}
}

func TestRetryDelayGrowsAndCaps(t *testing.T) {
	if delay := retryDelay(errors.New("temporary"), 1); delay < 5*time.Second || delay > 10*time.Second {
		t.Fatalf("unexpected first delay: %s", delay)
	}
	if delay := retryDelay(errors.New("temporary"), 20); delay < 5*time.Hour || delay > 6*time.Hour {
		t.Fatalf("unexpected capped delay: %s", delay)
	}
	limited := &githubapi.RateLimitError{Wait: 37 * time.Second}
	if delay := retryDelay(limited, 20); delay != 37*time.Second {
		t.Fatalf("rate limit wait ignored: %s", delay)
	}
}

func TestSearchTimeSplitHasNoOverlapOrGap(t *testing.T) {
	start := time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(24*time.Hour - time.Second)
	leftStart, leftEnd, rightStart, rightEnd, ok := splitSearchTimeRange(start, end)
	if !ok || !leftStart.Equal(start) || !rightEnd.Equal(end) ||
		!rightStart.Equal(leftEnd.Add(time.Second)) {
		t.Fatalf("invalid coverage partition split: %v %v %v %v %v",
			leftStart, leftEnd, rightStart, rightEnd, ok)
	}
	if _, _, _, _, ok := splitSearchTimeRange(start, start); ok {
		t.Fatal("split a one-second creation range")
	}
}

func TestWeightedSchedulerAllocation(t *testing.T) {
	service := &Service{}
	counts := map[string]int{}
	for index := 0; index < 1_000; index++ {
		counts[service.nextQueueClass()]++
	}
	if counts["global"] != 800 || counts["live"] != 100 || counts["owner"] != 100 {
		t.Fatalf("unexpected weighted allocation: %#v", counts)
	}
}

func TestNormalizeKeysRejectsPartialSnapshot(t *testing.T) {
	if _, err := normalizeKeys([]githubapi.GraphQLKey{
		{Key: "ssh-rsa not-valid-base64"},
	}); err == nil {
		t.Fatal("accepted malformed key snapshot")
	}
	raw := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1LeQQBsiMach2TP93bSThTouh8aV9DOZABSw3qzwfb"
	parsed, err := sshkey.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := normalizeKeys([]githubapi.GraphQLKey{{Key: raw, Fingerprint: parsed.Text}})
	if err != nil || len(keys) != 1 || keys[0].Type != "ssh-ed25519" {
		t.Fatalf("valid key was rejected: %#v %v", keys, err)
	}
}

func TestRepeatedGraphQLFailuresFallbackOnlyActuallyRetriedJobs(t *testing.T) {
	jobs := []model.Candidate{
		{GitHubID: 1, Attempts: 3},
		{GitHubID: 2, Attempts: 1},
		{GitHubID: 3, Attempts: 4},
	}
	fallback, retry := splitFailedGraphQLBatch(jobs, errors.New("HTTP 504"))
	if len(fallback) != 2 || fallback[0].GitHubID != 1 || fallback[1].GitHubID != 3 {
		t.Fatalf("unexpected fallback partition: %#v", fallback)
	}
	if len(retry) != 1 || retry[0].GitHubID != 2 {
		t.Fatalf("unexpected retry partition: %#v", retry)
	}
	limited := &githubapi.RateLimitError{Wait: time.Minute}
	fallback, retry = splitFailedGraphQLBatch(jobs, limited)
	if len(fallback) != 0 || len(retry) != len(jobs) {
		t.Fatalf("rate-limited jobs escaped GraphQL pacing: fallback=%#v retry=%#v", fallback, retry)
	}
}

func TestNormalizeRESTKeysCalculatesAndDeduplicatesFingerprints(t *testing.T) {
	raw := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1LeQQBsiMach2TP93bSThTouh8aV9DOZABSw3qzwfb"
	keys, err := normalizeRESTKeys([]string{raw})
	if err != nil || len(keys) != 1 || keys[0].Text == "" {
		t.Fatalf("valid REST key was rejected: %#v %v", keys, err)
	}
	if _, err := normalizeRESTKeys([]string{raw, raw + " comment"}); err == nil {
		t.Fatal("duplicate REST fingerprint was accepted")
	}
}

func TestSameKeySetIgnoresPaginationOrderButDetectsDrift(t *testing.T) {
	left := []model.PublicKey{{Text: "SHA256:a"}, {Text: "SHA256:b"}}
	right := []model.PublicKey{{Text: "SHA256:b"}, {Text: "SHA256:a"}}
	if !sameKeySet(left, right) {
		t.Fatal("equal key sets with different order were rejected")
	}
	if sameKeySet(left, []model.PublicKey{{Text: "SHA256:a"}, {Text: "SHA256:c"}}) {
		t.Fatal("changed key set was accepted")
	}
}
