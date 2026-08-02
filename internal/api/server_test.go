package api

import (
	"encoding/base64"
	"encoding/binary"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/local/github-ssh-index/internal/store"
)

func TestCompactStatusSnapshotOmitsInternalDetails(t *testing.T) {
	finish := time.Now().Add(24 * time.Hour)
	snapshot := map[string]any{
		"index": map[string]int64{"owners": 12, "keys": 34, "associations": 56},
		"progress": map[string]any{
			"phase": "initial_scan", "enumerated_users": int64(1000),
			"processed_users": int64(700), "processing_backlog": int64(300),
			"enumeration_complete": false, "remaining_id_positions": int64(500),
			"current_enumeration_users_per_hour": 400.0,
			"estimated_completion": map[string]any{
				"rate_users_per_hour":    390.0,
				"estimated_finish_early": finish,
				"estimated_finish_late":  finish.Add(time.Hour),
				"basis":                  "active shard ranges and observed user density",
			},
		},
		"crawler": map[string]any{
			"online": true, "active_workers": 9,
			"last_heartbeat_at": time.Now(),
		},
		"coverage": map[string]any{"initial_complete": false},
		"recovery": map[string]any{"retrying_jobs": int64(0)},
		"runs":     []store.Run{{ErrorUsers: 2}},
		"workers":  []store.WorkerStatus{{Name: "internal-worker"}},
		"pacing":   map[string]any{"graphql": "internal"},
	}

	result := compactStatusSnapshot(snapshot)
	for _, internal := range []string{"workers", "runs", "pacing", "scheduler", "enumeration", "recovery"} {
		if _, exists := result[internal]; exists {
			t.Fatalf("compact status exposed %q", internal)
		}
	}
	if result["status"] != "running" {
		t.Fatalf("unexpected status: %#v", result)
	}
	progress := result["progress"].(map[string]any)
	if progress["queued_users"] != int64(300) || progress["estimate_basis"] == nil {
		t.Fatalf("missing compact progress: %#v", progress)
	}
	errors := result["errors"].(map[string]any)
	if errors["run_errors"] != int64(2) {
		t.Fatalf("missing run errors: %#v", errors)
	}
}

func TestParsePaginationDefaultsAndBounds(t *testing.T) {
	page, err := parsePagination(url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if page.AfterID != 0 || page.Limit != 100 || !page.Snapshot.IsZero() {
		t.Fatalf("unexpected defaults: %#v", page)
	}
	page, err = parsePagination(url.Values{
		"after_id": {"42"},
		"limit":    {"200"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.AfterID != 42 || page.Limit != 200 {
		t.Fatalf("unexpected pagination: %#v", page)
	}
}

func TestParsePaginationRejectsInvalidValues(t *testing.T) {
	for _, values := range []url.Values{
		{"limit": {"0"}},
		{"limit": {"201"}},
		{"limit": {"wat"}},
		{"after_id": {"-1"}},
		{"after_id": {"wat"}},
		{"after_id": {"42"}, "cursor": {"anything"}},
		{"cursor": {"invalid"}},
	} {
		if _, err := parsePagination(values); err == nil {
			t.Fatalf("accepted invalid pagination: %v", values)
		}
	}
}

func TestCursorRoundTrip(t *testing.T) {
	snapshot := time.Date(2026, 7, 30, 12, 34, 56, 789000000, time.UTC)
	for _, afterID := range []int64{0, 1, 42, 1<<63 - 1} {
		cursor := encodeCursor(afterID, snapshot)
		decodedID, decodedSnapshot, err := decodeCursor(cursor)
		if err != nil {
			t.Fatal(err)
		}
		if decodedID != afterID || !decodedSnapshot.Equal(snapshot) {
			t.Fatalf(
				"round trip mismatch: got id=%d time=%s",
				decodedID, decodedSnapshot,
			)
		}
	}
}

func TestDecodeCursorRejectsInvalidPayloads(t *testing.T) {
	payload := make([]byte, cursorPayloadSize)
	payload[0] = 2
	binary.BigEndian.PutUint64(payload[9:17], uint64(time.Now().UnixMicro()))
	wrongVersion := base64.RawURLEncoding.EncodeToString(payload)

	payload[0] = 1
	binary.BigEndian.PutUint64(payload[1:9], uint64(1)<<63)
	overflowID := base64.RawURLEncoding.EncodeToString(payload)

	binary.BigEndian.PutUint64(payload[1:9], 1)
	binary.BigEndian.PutUint64(
		payload[9:17],
		uint64(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro()),
	)
	oldTimestamp := base64.RawURLEncoding.EncodeToString(payload)

	for _, cursor := range []string{"", "not-a-cursor", wrongVersion, overflowID, oldTimestamp} {
		if _, _, err := decodeCursor(cursor); err == nil {
			t.Fatalf("accepted invalid cursor %q", cursor)
		}
	}
}

func TestParsePaginationAcceptsCursor(t *testing.T) {
	snapshot := time.Date(2026, 7, 30, 1, 2, 3, 0, time.UTC)
	page, err := parsePagination(url.Values{
		"cursor": {encodeCursor(42, snapshot)},
		"limit":  {"150"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.AfterID != 42 || page.Limit != 150 || !page.Snapshot.Equal(snapshot) {
		t.Fatalf("unexpected cursor page: %#v", page)
	}
}

func TestNextPageURL(t *testing.T) {
	request := httptest.NewRequest(
		"GET",
		"http://example.test/api/v1/users?after_id=42&limit=50",
		nil,
	)
	got := nextPageURL(request, "abc_123", 50)
	want := "/api/v1/users?cursor=abc_123&limit=50"
	if got != want {
		t.Fatalf("next URL = %q, want %q", got, want)
	}
}
