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
			"phase": "initial_scan", "stage": "resource_repair_drain",
			"enumerated_users": int64(1000),
			"attempted_users":  int64(750), "processed_users": int64(700),
			"processing_backlog":           int64(300),
			"rest_fallback_users":          int64(25),
			"rolling_1h_attempts_per_hour": 390.0,
			"enumeration_complete":         false, "remaining_id_positions": int64(500),
			"current_enumeration_users_per_hour": 400.0,
			"estimated_completion": map[string]any{
				"rate_accounts_per_hour": 390.0,
				"rate_users_per_hour":    390.0,
				"estimated_finish_early": finish,
				"estimated_finish_late":  finish.Add(time.Hour),
				"basis":                  "active shard ranges and observed user density",
				"rate_is_preliminary":    true,
				"fast_scan_finish_early": finish.Add(-20 * time.Hour),
				"fast_scan_finish_late":  finish.Add(-18 * time.Hour),
			},
		},
		"crawler": map[string]any{
			"online": true, "active_workers": 9,
			"last_heartbeat_at": time.Now(),
		},
		"coverage": map[string]any{
			"initial_complete": false, "audit_status": "running",
			"audit_complete": false, "audit_days_complete": int64(12),
			"audit_days_total": int64(20), "searchable_users": int64(4567),
			"initial_enumerated_users": int64(1000),
			"searchable_user_gap":      int64(3567),
			"verification_state":       "initial_crawl_in_progress",
		},
		"recovery": map[string]any{"retrying_jobs": int64(0)},
		"passes": map[string]any{
			"first":  map[string]any{"status": "running", "complete": false},
			"second": map[string]any{"status": "waiting_for_first_pass", "complete": false},
		},
		"lookup": map[string]any{
			"usable": true, "positive_matches": "usable_immediately",
			"negative_match_coverage": "partial",
		},
		"runs":    []store.Run{{ErrorUsers: 2}},
		"workers": []store.WorkerStatus{{Name: "internal-worker"}},
		"pacing":  map[string]any{"graphql": "internal"},
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
	crawler := result["crawler"].(map[string]any)
	if crawler["stage"] != "resource_repair_drain" {
		t.Fatalf("missing phase-aware crawler stage: %#v", crawler)
	}
	progress := result["progress"].(map[string]any)
	if progress["queued_users"] != int64(300) || progress["estimate_basis"] == nil {
		t.Fatalf("missing compact progress: %#v", progress)
	}
	if progress["fast_scan_finish_early"] == nil || progress["settled_finish_early"] == nil ||
		progress["fast_scan_scope"] == nil || progress["settled_scope"] == nil {
		t.Fatalf("missing distinct fast-scan and settled estimates: %#v", progress)
	}
	if progress["attempted_users"] != int64(750) || progress["attempt_rate_per_hour"] != 390.0 {
		t.Fatalf("missing first-attempt progress: %#v", progress)
	}
	if progress["rest_fallback_users"] != int64(25) {
		t.Fatalf("missing REST fallback backlog: %#v", progress)
	}
	if progress["resource_repair_users"] != int64(25) {
		t.Fatalf("missing URL-resource repair backlog: %#v", progress)
	}
	if progress["estimate_preliminary"] != true {
		t.Fatalf("missing estimate warm-up state: %#v", progress)
	}
	passes := result["passes"].(map[string]any)
	if passes["first"] == nil || passes["second"] == nil || result["usable"] != true {
		t.Fatalf("missing pass or usability status: %#v", result)
	}
	coverage := result["coverage"].(map[string]any)
	if coverage["audit_status"] != "running" || coverage["searchable_users"] != int64(4567) ||
		coverage["verification_state"] != "initial_crawl_in_progress" {
		t.Fatalf("missing compact coverage audit: %#v", coverage)
	}
	errors := result["errors"].(map[string]any)
	if errors["run_errors"] != int64(2) {
		t.Fatalf("missing run errors: %#v", errors)
	}
}

func TestCompactStatusPrefersFederationSweepETA(t *testing.T) {
	legacyFinish := time.Now().Add(30 * 24 * time.Hour)
	fastFinish := time.Now().Add(9 * 24 * time.Hour)
	snapshot := map[string]any{
		"index": map[string]int64{"owners": 1, "keys": 1},
		"progress": map[string]any{
			"estimated_completion": map[string]any{
				"fast_scan_finish_early": legacyFinish,
				"fast_scan_finish_late":  legacyFinish,
				"estimated_finish_early": legacyFinish,
				"basis":                  "legacy REST",
			},
		},
		"federation_sweep": map[string]any{
			"status": "running", "estimated_finish": fastFinish,
			"processed_id_positions": int64(10_000), "estimate_preliminary": false,
		},
		"crawler":  map[string]any{"online": true},
		"coverage": map[string]any{}, "recovery": map[string]any{},
		"passes": map[string]any{}, "lookup": map[string]any{"usable": true},
	}
	result := compactStatusSnapshot(snapshot)
	progress := result["progress"].(map[string]any)
	if progress["estimated_finish_early"] != fastFinish ||
		progress["estimate_basis"] != "dense GraphQL federation ID sweep measured throughput" ||
		progress["fast_sweep"] == nil {
		t.Fatalf("federation ETA was not preferred: %#v", progress)
	}
}

func TestCompactStatusHidesPreliminaryFederationETA(t *testing.T) {
	finish := time.Now().Add(90 * 24 * time.Hour)
	snapshot := map[string]any{
		"progress": map[string]any{"estimated_completion": map[string]any{}},
		"federation_sweep": map[string]any{
			"status": "running", "estimated_finish": finish,
			"remaining_hours": 2160.0, "estimate_preliminary": true,
		},
		"crawler": map[string]any{"online": true}, "coverage": map[string]any{},
		"recovery": map[string]any{}, "passes": map[string]any{},
		"lookup": map[string]any{"usable": true}, "index": map[string]any{},
	}

	result := compactStatusSnapshot(snapshot)
	progress := result["progress"].(map[string]any)
	fastSweep := progress["fast_sweep"].(map[string]any)
	if progress["estimated_finish_early"] != nil || fastSweep["estimated_finish"] != nil ||
		fastSweep["remaining_hours"] != nil {
		t.Fatalf("preliminary federation ETA was exposed: %#v", progress)
	}
	if snapshot["federation_sweep"].(map[string]any)["estimated_finish"] != finish {
		t.Fatal("compact status mutated the cached internal snapshot")
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
