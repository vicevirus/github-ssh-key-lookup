package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/local/github-ssh-index/internal/api"
	"github.com/local/github-ssh-index/internal/crawler"
	"github.com/local/github-ssh-index/internal/githubapi"
	"github.com/local/github-ssh-index/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	command := "all"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command == "healthcheck" {
		return healthcheck()
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	database, err := store.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	switch command {
	case "migrate":
		logger.Info("database migrated")
		return nil
	case "repair-range":
		if len(os.Args) != 5 {
			return errors.New("usage: github-ssh-index repair-range LOWER_ID UPPER_ID SHARDS")
		}
		lowerID, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			return fmt.Errorf("parse repair lower ID: %w", err)
		}
		upperID, err := strconv.ParseInt(os.Args[3], 10, 64)
		if err != nil {
			return fmt.Errorf("parse repair upper ID: %w", err)
		}
		shards, err := strconv.Atoi(os.Args[4])
		if err != nil {
			return fmt.Errorf("parse repair shard count: %w", err)
		}
		restBase := strings.TrimRight(env("GITHUB_REST_BASE", "https://api.github.com"), "/")
		seeded, err := database.SeedEnumerationRepair(
			ctx, lowerID, upperID, shards,
			func(since int64) string {
				return fmt.Sprintf("%s/users?since=%d&per_page=100", restBase, since)
			},
		)
		if err != nil {
			return err
		}
		logger.Info("durable enumeration repair seeded",
			"lower_id", lowerID, "upper_id", upperID,
			"requested_shards", shards, "inserted_shards", seeded)
		return nil
	case "status":
		status, err := database.Status(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(status)
	case "api":
		return api.New(database, logger).ListenAndServe(ctx, env("HTTP_ADDR", ":8080"))
	case "crawl":
		return crawlerService(database, logger).Run(ctx)
	case "all":
		service := crawlerService(database, logger)
		errors := make(chan error, 2)
		go func() { errors <- service.Run(ctx) }()
		go func() { errors <- api.New(database, logger).ListenAndServe(ctx, env("HTTP_ADDR", ":8080")) }()
		select {
		case <-ctx.Done():
			return nil
		case err := <-errors:
			return err
		}
	default:
		return fmt.Errorf("unknown command %q (use migrate, repair-range, crawl, api, all, status, or healthcheck)", command)
	}
}

func crawlerService(database *store.Store, logger *slog.Logger) *crawler.Service {
	tokens := githubTokens()
	if len(tokens) == 0 || tokens[0] == "" {
		logger.Error("GITHUB_TOKEN is required for crawler mode")
		os.Exit(2)
	}
	client := githubapi.NewWithTokens(tokens, env("GITHUB_USER_AGENT", "github-ssh-index/1.0 (security research; contact required)"))
	credentialCount := client.CredentialCount()
	if value := os.Getenv("GITHUB_REST_BASE"); value != "" {
		client.RESTBase = value
	}
	if value := os.Getenv("GITHUB_GRAPHQL_URL"); value != "" {
		client.GraphQLURL = value
	}
	config := crawler.DefaultConfig()
	config.Workers = envInt("GRAPHQL_WORKERS", config.Workers) * credentialCount
	config.FederationWorkers = envInt(
		"FEDERATION_WORKERS", config.FederationWorkers,
	) * credentialCount
	config.FederationBatchSize = envInt(
		"FEDERATION_BATCH_SIZE", config.FederationBatchSize,
	)
	config.FederationRecrawl = envDuration(
		"FEDERATION_RECRAWL_INTERVAL", config.FederationRecrawl,
	)
	config.RESTFallbackWorkers = envInt(
		"REST_FALLBACK_WORKERS", config.RESTFallbackWorkers,
	) * credentialCount
	config.QueueMax = envInt("QUEUE_MAX_ACCOUNTS", config.QueueMax)
	config.RESTPerHour = envInt("REST_REQUESTS_PER_HOUR", config.RESTPerHour) * credentialCount
	config.GraphQLPerHour = envInt("GRAPHQL_POINTS_PER_HOUR", config.GraphQLPerHour) * credentialCount
	config.SearchPerHour = envInt("SEARCH_REQUESTS_PER_HOUR", config.SearchPerHour) * credentialCount
	config.TailPollInterval = envDuration("TAIL_POLL_INTERVAL", config.TailPollInterval)
	config.OwnerRefresh = envDuration("OWNER_REFRESH_INTERVAL", config.OwnerRefresh)
	config.OwnerSchedule = envDurations(
		"OWNER_REFRESH_SCHEDULE", config.OwnerSchedule,
	)
	config.ZeroKeyRecheckAges = envDurations(
		"ZERO_KEY_RECHECK_AGES", config.ZeroKeyRecheckAges,
	)
	config.EstimatedAccountsLow = int64(envInt(
		"ESTIMATED_ACCOUNTS_LOW", int(config.EstimatedAccountsLow),
	))
	config.EstimatedAccountsHigh = int64(envInt(
		"ESTIMATED_ACCOUNTS_HIGH", int(config.EstimatedAccountsHigh),
	))
	return crawler.New(database, client, config, logger)
}

func githubTokens() []string {
	return []string{
		strings.TrimSpace(os.Getenv("GITHUB_TOKEN")),
		strings.TrimSpace(os.Getenv("GITHUB_TOKEN_SECONDARY")),
	}
}

func healthcheck() error {
	url := env("HEALTHCHECK_URL", "http://127.0.0.1:8080/healthz")
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck returned HTTP %d", response.StatusCode)
	}
	return nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDurations(key string, fallback []time.Duration) []time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	result := make([]time.Duration, 0, len(parts))
	for _, part := range parts {
		parsed, err := time.ParseDuration(strings.TrimSpace(part))
		if err != nil || parsed <= 0 {
			return fallback
		}
		result = append(result, parsed)
	}
	return result
}
