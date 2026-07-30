package api

import (
	"net/url"
	"testing"
)

func TestParsePaginationDefaultsAndBounds(t *testing.T) {
	afterID, limit, err := parsePagination(url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if afterID != 0 || limit != 100 {
		t.Fatalf("unexpected defaults: after=%d limit=%d", afterID, limit)
	}
	afterID, limit, err = parsePagination(url.Values{
		"after_id": {"42"},
		"limit":    {"200"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if afterID != 42 || limit != 200 {
		t.Fatalf("unexpected pagination: after=%d limit=%d", afterID, limit)
	}
}

func TestParsePaginationRejectsInvalidValues(t *testing.T) {
	for _, values := range []url.Values{
		{"limit": {"0"}},
		{"limit": {"201"}},
		{"limit": {"wat"}},
		{"after_id": {"-1"}},
		{"after_id": {"wat"}},
	} {
		if _, _, err := parsePagination(values); err == nil {
			t.Fatalf("accepted invalid pagination: %v", values)
		}
	}
}
