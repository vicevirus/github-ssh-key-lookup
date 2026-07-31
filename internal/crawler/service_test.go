package crawler

import (
	"errors"
	"testing"
	"time"

	"github.com/local/github-ssh-index/internal/githubapi"
	"github.com/local/github-ssh-index/internal/model"
)

func TestNormalizeUsersRejectsReorderedNodes(t *testing.T) {
	jobs := []model.Candidate{{GitHubID: 1, NodeID: "U_1"}}
	nodes := []*githubapi.GraphQLUser{{TypeName: "User", ID: "U_2", DatabaseID: 2}}
	if _, err := normalizeUsers(jobs, nodes); err == nil {
		t.Fatal("accepted reordered GraphQL node")
	}
}

func TestNormalizeUsersPreservesNullNode(t *testing.T) {
	jobs := []model.Candidate{{GitHubID: 1, NodeID: "U_1"}}
	results, err := normalizeUsers(jobs, []*githubapi.GraphQLUser{nil})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0] != nil {
		t.Fatalf("unexpected results: %#v", results)
	}
}

func TestRetryDelayGrowsAndCaps(t *testing.T) {
	if delay := retryDelay(errors.New("temporary"), 1); delay < time.Second || delay > 4*time.Second {
		t.Fatalf("unexpected first delay: %s", delay)
	}
	if delay := retryDelay(errors.New("temporary"), 20); delay < 8*time.Minute || delay > 15*time.Minute {
		t.Fatalf("unexpected capped delay: %s", delay)
	}
	limited := &githubapi.RateLimitError{Wait: 37 * time.Second}
	if delay := retryDelay(limited, 20); delay != 37*time.Second {
		t.Fatalf("rate limit wait ignored: %s", delay)
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
