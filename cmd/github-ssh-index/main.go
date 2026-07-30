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
		return fmt.Errorf("unknown command %q (use migrate, crawl, api, all, status, or healthcheck)", command)
	}
}

func crawlerService(database *store.Store, logger *slog.Logger) *crawler.Service {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		logger.Error("GITHUB_TOKEN is required for crawler mode")
		os.Exit(2)
	}
	client := githubapi.New(token, env("GITHUB_USER_AGENT", "github-ssh-index/1.0 (security research; contact required)"))
	if value := os.Getenv("GITHUB_REST_BASE"); value != "" {
		client.RESTBase = value
	}
	if value := os.Getenv("GITHUB_GRAPHQL_URL"); value != "" {
		client.GraphQLURL = value
	}
	config := crawler.DefaultConfig()
	config.Workers = envInt("GRAPHQL_WORKERS", config.Workers)
	config.QueueMax = envInt("QUEUE_MAX_ACCOUNTS", config.QueueMax)
	config.RESTPerHour = envInt("REST_REQUESTS_PER_HOUR", config.RESTPerHour)
	config.GraphQLPerHour = envInt("GRAPHQL_POINTS_PER_HOUR", config.GraphQLPerHour)
	config.TailPollInterval = envDuration("TAIL_POLL_INTERVAL", config.TailPollInterval)
	config.OwnerRefresh = envDuration("OWNER_REFRESH_INTERVAL", config.OwnerRefresh)
	config.EstimatedAccountsLow = int64(envInt(
		"ESTIMATED_ACCOUNTS_LOW", int(config.EstimatedAccountsLow),
	))
	config.EstimatedAccountsHigh = int64(envInt(
		"ESTIMATED_ACCOUNTS_HIGH", int(config.EstimatedAccountsHigh),
	))
	return crawler.New(database, client, config, logger)
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
