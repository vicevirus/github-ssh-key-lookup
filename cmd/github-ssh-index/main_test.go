package main

import (
	"io"
	"log/slog"
	"testing"
)

func TestCrawlerServiceScalesPerCredentialSettings(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "primary")
	t.Setenv("GITHUB_TOKEN_SECONDARY", "secondary")
	t.Setenv("GRAPHQL_WORKERS", "4")
	t.Setenv("REST_ENUMERATION_WORKERS", "1")
	t.Setenv("GRAPHQL_KEY_BATCH_SIZE", "225")
	t.Setenv("REST_REQUESTS_PER_HOUR", "4700")
	t.Setenv("GRAPHQL_POINTS_PER_HOUR", "4700")
	t.Setenv("SEARCH_REQUESTS_PER_HOUR", "1500")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	service := crawlerService(nil, logger)
	if service.GitHub.CredentialCount() != 2 {
		t.Fatalf("credential count=%d, want 2", service.GitHub.CredentialCount())
	}
	if service.Config.Workers != 8 || service.Config.EnumerationWorkers != 2 ||
		service.Config.KeyBatchSize != 225 || service.Config.FederationWorkers != 10 ||
		service.Config.RESTPerHour != 9400 ||
		service.Config.GraphQLPerHour != 4700 || service.Config.SearchPerHour != 3000 {
		t.Fatalf("settings were not scaled per credential: %#v", service.Config)
	}
}
