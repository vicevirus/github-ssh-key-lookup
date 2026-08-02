package crawler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/local/github-ssh-index/internal/githubapi"
	"github.com/local/github-ssh-index/internal/model"
	"github.com/local/github-ssh-index/internal/ratelimit"
	"github.com/local/github-ssh-index/internal/sshkey"
	"github.com/local/github-ssh-index/internal/store"
)

type Config struct {
	Workers               int
	QueueMax              int
	RESTPerHour           int
	GraphQLPerHour        int
	SearchPerHour         int
	RESTReserve           int
	GraphQLReserve        int
	SearchReserve         int
	TailPollInterval      time.Duration
	OwnerRefresh          time.Duration
	OwnerSchedule         []time.Duration
	ZeroKeyRecheckAges    []time.Duration
	PriorityFillInterval  time.Duration
	EstimatedAccountsLow  int64
	EstimatedAccountsHigh int64
}

func DefaultConfig() Config {
	return Config{
		Workers:          4,
		QueueMax:         10_000,
		RESTPerHour:      4_700,
		GraphQLPerHour:   3_600,
		SearchPerHour:    1_500,
		RESTReserve:      150,
		GraphQLReserve:   200,
		SearchReserve:    2,
		TailPollInterval: time.Minute,
		OwnerRefresh:     7 * 24 * time.Hour,
		OwnerSchedule: []time.Duration{
			6 * time.Hour,
			18 * time.Hour,
			2 * 24 * time.Hour,
			4 * 24 * time.Hour,
			7 * 24 * time.Hour,
			16 * 24 * time.Hour,
			30 * 24 * time.Hour,
		},
		ZeroKeyRecheckAges: []time.Duration{
			6 * time.Hour,
			24 * time.Hour,
			7 * 24 * time.Hour,
			30 * 24 * time.Hour,
		},
		PriorityFillInterval:  10 * time.Second,
		EstimatedAccountsLow:  190_000_000,
		EstimatedAccountsHigh: 220_000_000,
	}
}

type Service struct {
	Store   *store.Store
	GitHub  *githubapi.Client
	Config  Config
	Logger  *slog.Logger
	rest    *ratelimit.Pacer
	graphql *ratelimit.Pacer
	search  *ratelimit.Pacer

	scheduleMu     sync.Mutex
	scheduleCursor int
	globalPaused   atomic.Bool
}

func New(database *store.Store, github *githubapi.Client, config Config, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if config.Workers < 1 {
		config.Workers = 1
	}
	if config.Workers > 10 {
		config.Workers = 10
	}
	if config.QueueMax < 100 {
		config.QueueMax = 100
	}
	if config.SearchPerHour < 1 {
		config.SearchPerHour = 1_500
	}
	if config.EstimatedAccountsLow <= 0 {
		config.EstimatedAccountsLow = 190_000_000
	}
	if config.EstimatedAccountsHigh < config.EstimatedAccountsLow {
		config.EstimatedAccountsHigh = config.EstimatedAccountsLow
	}
	if len(config.OwnerSchedule) == 0 {
		config.OwnerSchedule = []time.Duration{config.OwnerRefresh}
	}
	if len(config.ZeroKeyRecheckAges) == 0 {
		config.ZeroKeyRecheckAges = []time.Duration{
			6 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour, 30 * 24 * time.Hour,
		}
	}
	return &Service{
		Store: database, GitHub: github, Config: config, Logger: logger,
		rest:    ratelimit.New(config.RESTPerHour, config.RESTReserve),
		graphql: ratelimit.New(config.GraphQLPerHour, config.GraphQLReserve),
		search:  ratelimit.New(config.SearchPerHour, config.SearchReserve),
	}
}

func (s *Service) Run(ctx context.Context) error {
	release, err := s.Store.AcquireCrawlerLock(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := s.Store.Recover(ctx); err != nil {
		return err
	}
	for key, value := range map[string]string{
		"estimated_accounts_low":  strconv.FormatInt(s.Config.EstimatedAccountsLow, 10),
		"estimated_accounts_high": strconv.FormatInt(s.Config.EstimatedAccountsHigh, 10),
		"scheduler_allocation":    "global=80%,live=10%,owner=10%; unused capacity is borrowed",
		"owner_refresh_schedule":  durationList(s.Config.OwnerSchedule),
		"zero_key_retry_ages":     durationList(s.Config.ZeroKeyRecheckAges),
	} {
		if err := s.Store.SetState(ctx, key, value); err != nil {
			return err
		}
	}
	s.recordPacer(ctx, "rest", s.rest)
	s.recordPacer(ctx, "graphql", s.graphql)
	s.recordPacer(ctx, "search", s.search)
	if _, err := s.Store.EnsureMainRun(ctx, s.GitHub.UsersURL(0)); err != nil {
		return err
	}
	s.workerActivity(ctx, "scheduler", "scheduler", "running", "crawler started")
	defer s.Store.StopWorker(context.Background(), "scheduler", "scheduler")
	group, groupCtx := withCancelGroup(ctx)
	// Enumeration workers are permanent. They wait while a run drains and then
	// initialize and process the next reconciliation run without requiring a
	// crawler restart.
	for worker := 0; worker < s.Config.Workers; worker++ {
		workerID := worker
		group.Go(func() error { return s.enumerateShardWorker(groupCtx, workerID) })
	}

	// Let REST build several full batches so the first GraphQL requests do not
	// waste points on partially filled batches.
	s.prefill(groupCtx)

	for worker := 0; worker < s.Config.Workers; worker++ {
		workerID := worker
		group.Go(func() error {
			return s.keyWorker(groupCtx, workerID)
		})
	}
	group.Go(func() error { return s.tail(groupCtx) })
	group.Go(func() error { return s.priorityOwners(groupCtx) })
	group.Go(func() error { return s.zeroKeyRechecks(groupCtx) })
	group.Go(func() error { return s.retryAnomalies(groupCtx) })
	group.Go(func() error { return s.coverageAudit(groupCtx) })
	group.Go(func() error { return s.monitorRuns(groupCtx) })
	return group.Wait()
}

func (s *Service) enumerateShardWorker(ctx context.Context, workerID int) error {
	worker := fmt.Sprintf("rest-enumerator-%d", workerID)
	role := "parallel global account enumeration"
	s.workerActivity(ctx, worker, role, "running", "waiting for ID range")
	defer s.Store.StopWorker(context.Background(), worker, role)
	for ctx.Err() == nil {
		run, err := s.Store.ActiveMainRun(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := sleep(ctx, 250*time.Millisecond); err != nil {
				return nil
			}
			continue
		}
		if err != nil {
			return err
		}
		if run.EnumerationComplete || run.CutoffUserID == nil {
			s.workerActivity(ctx, worker, role, "waiting", "waiting for next ID range")
			if err := sleep(ctx, 250*time.Millisecond); err != nil {
				return nil
			}
			continue
		}
		if err := s.waitForGlobalCapacity(ctx, worker, role, run.ID); err != nil {
			return nil
		}
		if err := s.Store.EnsureEnumerationShards(
			ctx, run, s.Config.Workers, s.GitHub.UsersURL,
		); err != nil {
			return err
		}
		shard, err := s.Store.ClaimEnumerationShard(ctx, run.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := sleep(ctx, 250*time.Millisecond); err != nil {
				return nil
			}
			continue
		}
		if err != nil {
			return err
		}
		for ctx.Err() == nil {
			if err := s.waitForGlobalCapacity(ctx, worker, role, run.ID); err != nil {
				return nil
			}
			if err := s.rest.Wait(ctx); err != nil {
				return nil
			}
			page, err := s.GitHub.ListUsers(ctx, shard.NextURL, "")
			if err != nil {
				s.workerError(ctx, worker, role, "REST shard request failed", err)
				s.handleRateError(ctx, err, s.rest, "rest")
				_ = s.Store.RequeueEnumerationShard(context.Background(), shard, err)
				break
			}
			s.rest.Observe(page.Rate)
			candidates := make([]model.Candidate, 0, len(page.Objects))
			nextSince := shard.NextSinceID
			reached := len(page.Objects) == 0 || page.NextURL == ""
			for _, object := range page.Objects {
				if object.ID > nextSince {
					nextSince = object.ID
				}
				if object.ID > shard.UpperID {
					reached = true
					continue
				}
				if object.Type == "User" && object.NodeID != "" {
					candidates = append(candidates, model.Candidate{GitHubID: object.ID, NodeID: object.NodeID, Login: object.Login})
				}
			}
			if reached {
				nextSince = shard.UpperID
			}
			nextURL := page.NextURL
			if reached {
				nextURL = s.GitHub.UsersURL(shard.UpperID)
			}
			if err := s.Store.ApplyEnumerationShardPage(ctx, shard, candidates, nextSince, nextURL, reached); err != nil {
				return err
			}
			if !reached {
				previousUpper := shard.UpperID
				newUpper, err := s.Store.RebalanceOwnedEnumerationShard(
					ctx, shard, s.Config.Workers, s.GitHub.UsersURL,
				)
				if err != nil {
					return err
				}
				shard.UpperID = newUpper
				if newUpper != previousUpper {
					s.Logger.Info("split remaining enumeration range",
						"worker", workerID, "shard", shard.ID,
						"next_since", nextSince, "old_upper", previousUpper,
						"new_upper", newUpper)
				}
			}
			s.workerRequest(ctx, worker, role, "enumerated ID range", page.Rate, len(candidates), 0)
			if reached {
				break
			}
			shard.NextSinceID, shard.NextURL = nextSince, nextURL
		}
	}
	return nil
}

func (s *Service) waitForGlobalCapacity(
	ctx context.Context, worker, role string, runID int64,
) error {
	high := int64(max(100, s.Config.QueueMax*8/10))
	low := int64(max(50, s.Config.QueueMax*4/10))
	for ctx.Err() == nil {
		backlog, err := s.Store.GlobalBacklog(ctx, runID)
		if err != nil {
			return err
		}
		repairDepth, err := s.Store.QueueDepthByClassCapped(ctx, "reconcile", int(high))
		if err != nil {
			return err
		}
		combined := backlog + int64(repairDepth)
		paused := s.globalPaused.Load()
		if paused && combined <= low {
			s.globalPaused.Store(false)
			paused = false
		}
		if !paused && combined >= high {
			s.globalPaused.Store(true)
			paused = true
		}
		if !paused {
			return nil
		}
		s.workerActivity(ctx, worker, role, "waiting",
			fmt.Sprintf("backpressure draining %d global/repair accounts", combined))
		if err := sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *Service) prefill(ctx context.Context) {
	deadline := time.NewTimer(15 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-ticker.C:
			run, err := s.Store.ActiveMainRun(ctx)
			if err == nil {
				if run.EnumerationComplete {
					return
				}
				backlog, backlogErr := s.Store.GlobalBacklog(ctx, run.ID)
				if backlogErr == nil && backlog >= 500 {
					return
				}
			}
		}
	}
}

func (s *Service) enumerateMain(ctx context.Context) error {
	const worker = "rest-enumerator"
	const role = "global account enumeration"
	s.workerActivity(ctx, worker, role, "starting", "starting account enumeration")
	defer s.Store.StopWorker(context.Background(), worker, role)
	failures := 0
	for ctx.Err() == nil {
		run, err := s.Store.EnsureMainRun(ctx, s.GitHub.UsersURL(0))
		if err != nil {
			return err
		}
		if run.EnumerationComplete {
			if err := sleep(ctx, time.Second); err != nil {
				return nil
			}
			continue
		}
		if err := s.waitForGlobalCapacity(ctx, worker, role, run.ID); err != nil {
			return nil
		}
		if err := s.rest.Wait(ctx); err != nil {
			return nil
		}
		page, err := s.GitHub.ListUsers(ctx, run.NextURL, "")
		if err != nil {
			failures++
			s.workerError(ctx, worker, role, "REST enumeration request failed", err)
			if isAuthenticationError(err) {
				return err
			}
			s.handleRateError(ctx, err, s.rest, "rest")
			s.Logger.Warn("REST enumeration failed", "run", run.ID, "error", err)
			if err := sleep(ctx, retryDelay(err, failures)); err != nil {
				return nil
			}
			continue
		}
		failures = 0
		s.rest.Observe(page.Rate)
		maxSeen := run.NextSinceID
		reachedCutoff := false
		candidates := make([]model.Candidate, 0, len(page.Objects))
		for _, object := range page.Objects {
			if object.ID > maxSeen {
				maxSeen = object.ID
			}
			if run.CutoffUserID != nil && object.ID > *run.CutoffUserID {
				reachedCutoff = true
				continue
			}
			if object.Type != "User" || object.NodeID == "" {
				continue
			}
			candidates = append(candidates, model.Candidate{
				GitHubID: object.ID, NodeID: object.NodeID, Login: object.Login,
			})
		}
		complete := len(page.Objects) == 0 || page.NextURL == "" || reachedCutoff
		if run.CutoffUserID != nil && maxSeen >= *run.CutoffUserID {
			complete = true
		}
		nextURL := page.NextURL
		if nextURL == "" {
			nextURL = s.GitHub.UsersURL(maxSeen)
		}
		if err := s.Store.ApplyEnumerationPage(
			ctx, run, candidates, maxSeen, nextURL, complete,
		); err != nil {
			return err
		}
		s.workerRequest(
			ctx, worker, role, "enumerated account page", page.Rate,
			len(candidates), 0,
		)
		s.Logger.Info("enumerated GitHub accounts",
			"run", run.ID, "objects", len(page.Objects), "users", len(candidates),
			"since", maxSeen, "complete", complete,
			"remaining", page.Rate.Remaining, "latency", page.Elapsed)
	}
	return nil
}

func (s *Service) keyWorker(ctx context.Context, workerID int) error {
	worker := fmt.Sprintf("graphql-%d", workerID)
	role := "SSH key batch worker"
	s.workerActivity(ctx, worker, role, "starting", "waiting for account batch")
	defer s.Store.StopWorker(context.Background(), worker, role)
	for ctx.Err() == nil {
		overflow, err := s.Store.ClaimOverflow(ctx)
		if err == nil {
			if err := s.processOverflow(ctx, workerID, *overflow); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		preferredClass := s.nextQueueClass()
		jobs, err := s.Store.ClaimScheduledAccounts(ctx, 100, preferredClass)
		if err != nil {
			return err
		}
		if len(jobs) == 0 {
			if err := sleep(ctx, 250*time.Millisecond); err != nil {
				return nil
			}
			continue
		}
		// Repeated batch failures are isolated so one unusual account cannot
		// poison 99 healthy neighbors forever.
		if len(jobs) > 1 && maxJobAttempts(jobs) >= 3 {
			rest := append([]model.Candidate(nil), jobs[1:]...)
			_ = s.Store.RequeueAccountsAfter(
				context.Background(), rest,
				errors.New("isolating repeatedly failing GraphQL account"), time.Second,
			)
			jobs = jobs[:1]
		}
		ids := make([]string, len(jobs))
		for index := range jobs {
			ids[index] = jobs[index].NodeID
		}
		if err := s.graphql.Wait(ctx); err != nil {
			_ = s.Store.RequeueAccountsAfter(
				context.Background(), jobs, err, retryDelay(err, maxJobAttempts(jobs)),
			)
			return nil
		}
		response, err := s.GitHub.FetchUsers(ctx, ids)
		if err != nil {
			s.workerError(ctx, worker, role, "GraphQL account batch failed", err)
			s.handleRateError(ctx, err, s.graphql, "graphql")
			_ = s.Store.RequeueAccountsAfter(
				context.Background(), jobs, err, retryDelay(err, maxJobAttempts(jobs)),
			)
			if isAuthenticationError(err) {
				return err
			}
			s.Logger.Warn("GraphQL batch failed", "worker", workerID, "users", len(jobs), "error", err)
			continue
		}
		s.graphql.Observe(response.Rate)
		s.graphql.ExtraCost(response.Rate.Cost)
		results, err := normalizeUsers(jobs, response.Nodes)
		if err != nil {
			_ = s.Store.RequeueAccountsAfter(
				context.Background(), jobs, err, retryDelay(err, maxJobAttempts(jobs)),
			)
			s.Logger.Error("invalid GitHub key response", "error", err)
			continue
		}
		validJobs := make([]model.Candidate, 0, len(jobs))
		validResults := make([]*model.UserResult, 0, len(jobs))
		missingJobs := make([]model.Candidate, 0)
		for index, result := range results {
			if result == nil {
				missingJobs = append(missingJobs, jobs[index])
				continue
			}
			validJobs = append(validJobs, jobs[index])
			validResults = append(validResults, result)
		}
		if err := s.Store.CompleteAccountsScheduled(
			ctx, validJobs, validResults,
			s.Config.OwnerSchedule, s.Config.ZeroKeyRecheckAges,
		); err != nil {
			_ = s.Store.RequeueAccountsAfter(
				context.Background(), validJobs, err,
				retryDelay(err, maxJobAttempts(validJobs)),
			)
			return err
		}
		if err := s.handleMissingAccounts(ctx, missingJobs); err != nil {
			return err
		}
		keyCount := 0
		for _, result := range results {
			if result != nil {
				keyCount += len(result.Keys)
			}
		}
		s.workerRequest(
			ctx, worker, role, "indexed SSH key batch", response.Rate,
			len(validJobs), keyCount,
		)
		s.Logger.Info("indexed GraphQL batch",
			"worker", workerID, "users", len(validJobs), "keys", keyCount,
			"cost", response.Rate.Cost, "remaining", response.Rate.Remaining,
			"latency", response.Elapsed)
	}
	return nil
}

func (s *Service) handleMissingAccounts(
	ctx context.Context, jobs []model.Candidate,
) error {
	for _, job := range jobs {
		notFound := fmt.Errorf("GitHub GraphQL returned null for account %d", job.GitHubID)
		if job.Attempts < 3 && job.Source != "anomaly" {
			delay := time.Hour
			if job.Attempts >= 2 {
				delay = 24 * time.Hour
			}
			if err := s.Store.RequeueAccountsAfter(
				context.Background(), []model.Candidate{job}, notFound, delay,
			); err != nil {
				return err
			}
			continue
		}
		if err := s.rest.Wait(ctx); err != nil {
			return err
		}
		user, rate, err := s.GitHub.GetUserByID(ctx, job.GitHubID)
		if err != nil {
			s.handleRateError(ctx, err, s.rest, "rest")
			if requeueErr := s.Store.RequeueAccountsAfter(
				context.Background(), []model.Candidate{job}, err,
				retryDelay(err, job.Attempts),
			); requeueErr != nil {
				return requeueErr
			}
			if isAuthenticationError(err) {
				return err
			}
			continue
		}
		s.rest.Observe(rate)
		if user == nil {
			if err := s.Store.CompleteInaccessible(ctx, job); err != nil {
				return err
			}
			continue
		}
		if err := s.Store.RefreshClaimIdentity(
			ctx, job, user.NodeID, user.Login,
		); err != nil {
			return err
		}
		job.NodeID, job.Login = user.NodeID, user.Login
		if err := s.Store.RequeueAccountsAfter(
			context.Background(), []model.Candidate{job}, notFound, 6*time.Hour,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) nextQueueClass() string {
	// Interleaving the slots avoids long bursts while preserving an 80/10/10
	// request allocation. ClaimScheduledAccounts borrows from another class
	// whenever the selected class cannot fill a batch.
	slots := [...]string{
		"global", "global", "global", "global", "live",
		"global", "global", "global", "global", "owner",
	}
	s.scheduleMu.Lock()
	class := slots[s.scheduleCursor%len(slots)]
	s.scheduleCursor++
	s.scheduleMu.Unlock()
	return class
}

func (s *Service) processOverflow(ctx context.Context, workerID int, job model.OverflowJob) error {
	worker := fmt.Sprintf("graphql-%d", workerID)
	role := "SSH key batch worker"
	if err := s.graphql.Wait(ctx); err != nil {
		_ = s.Store.RequeueOverflow(context.Background(), job, err)
		return nil
	}
	var user *githubapi.GraphQLUser
	var rate model.Rate
	var err error
	if job.Cursor == "" {
		var response githubapi.UsersAndKeys
		response, err = s.GitHub.FetchUsers(ctx, []string{job.NodeID})
		if err == nil {
			rate = response.Rate
			if len(response.Nodes) == 1 {
				user = response.Nodes[0]
			}
		}
	} else {
		user, rate, err = s.GitHub.MoreKeys(ctx, job.NodeID, job.Cursor)
	}
	if err != nil {
		s.workerError(ctx, worker, role, "GraphQL overflow page failed", err)
		s.handleRateError(ctx, err, s.graphql, "graphql")
		_ = s.Store.RequeueOverflow(context.Background(), job, err)
		if isAuthenticationError(err) {
			return err
		}
		_ = sleep(ctx, retryDelay(err, job.Attempts))
		return nil
	}
	s.graphql.Observe(rate)
	s.graphql.ExtraCost(rate.Cost)
	if user == nil {
		err = fmt.Errorf("overflow user %d became inaccessible", job.GitHubID)
		_ = s.Store.RequeueOverflow(context.Background(), job, err)
		return nil
	}
	if user.ID != job.NodeID || user.DatabaseID != job.GitHubID {
		err = fmt.Errorf(
			"overflow identity mismatch: expected %s/%d, received %s/%d",
			job.NodeID, job.GitHubID, user.ID, user.DatabaseID,
		)
		_ = s.Store.RequeueOverflowAfter(
			context.Background(), job, err, retryDelay(err, job.Attempts),
		)
		return nil
	}
	keys, normalizeErr := normalizeKeys(user.PublicKeys.Nodes)
	if normalizeErr != nil {
		_ = s.Store.RequeueOverflowAfter(
			context.Background(), job, normalizeErr,
			retryDelay(normalizeErr, job.Attempts),
		)
		return nil
	}
	if job.ExpectedKeyCount >= 0 && user.PublicKeys.TotalCount != job.ExpectedKeyCount {
		reason := fmt.Sprintf(
			"overflow total changed from %d to %d",
			job.ExpectedKeyCount, user.PublicKeys.TotalCount,
		)
		if err := s.Store.RestartOverflowScan(ctx, job, reason); err != nil {
			return err
		}
		return nil
	}
	if user.PublicKeys.TotalCount < len(keys) ||
		(user.PublicKeys.PageInfo.HasNextPage && user.PublicKeys.PageInfo.EndCursor == "") {
		err := fmt.Errorf(
			"overflow connection inconsistent: total=%d nodes=%d has_more=%t",
			user.PublicKeys.TotalCount, len(keys), user.PublicKeys.PageInfo.HasNextPage,
		)
		_ = s.Store.RequeueOverflowAfter(
			context.Background(), job, err, retryDelay(err, job.Attempts),
		)
		return nil
	}
	s.workerRequest(
		ctx, worker, role, "indexed overflow SSH key page", rate, 0, len(keys),
	)
	err = s.Store.CompleteOverflowPageScheduled(
		ctx, job, keys, user.PublicKeys.PageInfo.HasNextPage,
		user.PublicKeys.PageInfo.EndCursor, user.PublicKeys.TotalCount,
		s.Config.OwnerSchedule,
	)
	if err != nil {
		_ = s.Store.RequeueOverflow(context.Background(), job, err)
		return nil
	}
	s.Logger.Info("indexed overflow key page",
		"worker", workerID, "github_id", job.GitHubID,
		"keys", len(keys), "has_more", user.PublicKeys.PageInfo.HasNextPage)
	return nil
}

func normalizeUsers(jobs []model.Candidate, nodes []*githubapi.GraphQLUser) ([]*model.UserResult, error) {
	if len(jobs) != len(nodes) {
		return nil, errors.New("GraphQL response cardinality mismatch")
	}
	results := make([]*model.UserResult, len(nodes))
	for index, user := range nodes {
		if user == nil || user.TypeName != "User" {
			continue
		}
		if user.ID != jobs[index].NodeID || user.DatabaseID != jobs[index].GitHubID {
			return nil, fmt.Errorf(
				"GraphQL identity mismatch: expected %s/%d, received %s/%d",
				jobs[index].NodeID, jobs[index].GitHubID, user.ID, user.DatabaseID,
			)
		}
		if user.CreatedAt.IsZero() {
			return nil, fmt.Errorf("GraphQL account %d has no createdAt", user.DatabaseID)
		}
		keys, err := normalizeKeys(user.PublicKeys.Nodes)
		if err != nil {
			return nil, fmt.Errorf("GraphQL account %d key snapshot: %w", user.DatabaseID, err)
		}
		if user.PublicKeys.TotalCount < len(keys) ||
			(!user.PublicKeys.PageInfo.HasNextPage && user.PublicKeys.TotalCount != len(keys)) ||
			(user.PublicKeys.PageInfo.HasNextPage &&
				(user.PublicKeys.TotalCount <= len(keys) || user.PublicKeys.PageInfo.EndCursor == "")) {
			return nil, fmt.Errorf(
				"GraphQL account %d inconsistent key connection: total=%d nodes=%d has_more=%t",
				user.DatabaseID, user.PublicKeys.TotalCount, len(keys),
				user.PublicKeys.PageInfo.HasNextPage,
			)
		}
		results[index] = &model.UserResult{
			NodeID: user.ID, GitHubID: jobs[index].GitHubID, Login: user.Login,
			CreatedAt: user.CreatedAt,
			Keys:      keys, HasMoreKeys: user.PublicKeys.PageInfo.HasNextPage,
			NextCursor:    user.PublicKeys.PageInfo.EndCursor,
			TotalKeyCount: user.PublicKeys.TotalCount,
		}
	}
	return results, nil
}

func normalizeKeys(keys []githubapi.GraphQLKey) ([]model.PublicKey, error) {
	result := make([]model.PublicKey, 0, len(keys))
	seen := make(map[string]bool, len(keys))
	for _, raw := range keys {
		key, err := sshkey.Parse(raw.Key)
		if err != nil {
			return nil, err
		}
		if raw.Fingerprint == "" || raw.Fingerprint != key.Text {
			return nil, fmt.Errorf("fingerprint mismatch: GitHub=%q calculated=%q", raw.Fingerprint, key.Text)
		}
		if seen[key.Text] {
			return nil, fmt.Errorf("duplicate key fingerprint %s", key.Text)
		}
		seen[key.Text] = true
		result = append(result, key)
	}
	return result, nil
}

func (s *Service) tail(ctx context.Context) error {
	const worker = "rest-tail"
	const role = "new account tail"
	s.workerActivity(ctx, worker, role, "starting", "initializing parallel live tail")
	defer s.Store.StopWorker(context.Background(), worker, role)
	if err := s.ensureLiveTail(ctx, worker, role); err != nil {
		return err
	}
	failures := 0
	for ctx.Err() == nil {
		liveQueueLimit := max(100, s.Config.QueueMax/10)
		liveDepth, err := s.Store.QueueDepthByClassCapped(
			ctx, "live", liveQueueLimit,
		)
		if err != nil {
			return err
		}
		if liveDepth >= liveQueueLimit {
			if err := sleep(ctx, 2*time.Second); err != nil {
				return nil
			}
			continue
		}
		highwater, err := s.Store.StateInt(ctx, "tail_highwater")
		if err != nil {
			return err
		}
		requestURL, err := s.Store.State(ctx, "tail_url")
		if err != nil {
			return err
		}
		if requestURL == "" {
			requestURL = s.GitHub.UsersURL(highwater)
		}
		etag, err := s.Store.State(ctx, "tail_etag")
		if err != nil {
			return err
		}
		if err := s.rest.Wait(ctx); err != nil {
			return nil
		}
		page, err := s.GitHub.ListUsers(ctx, requestURL, etag)
		if err != nil {
			failures++
			s.workerError(ctx, worker, role, "REST tail request failed", err)
			if isAuthenticationError(err) {
				return err
			}
			s.handleRateError(ctx, err, s.rest, "rest")
			s.Logger.Warn("tail request failed", "error", err)
			_ = sleep(ctx, retryDelay(err, failures))
			continue
		}
		failures = 0
		s.rest.Observe(page.Rate)
		if page.NotModified {
			s.workerRequest(ctx, worker, role, "new-account tail is caught up", page.Rate, 0, 0)
			if err := sleep(ctx, s.Config.TailPollInterval); err != nil {
				return nil
			}
			continue
		}
		candidates := make([]model.Candidate, 0, len(page.Objects))
		for _, object := range page.Objects {
			if object.ID > highwater {
				highwater = object.ID
			}
			if object.Type == "User" && object.NodeID != "" {
				candidates = append(candidates, model.Candidate{
					GitHubID: object.ID, NodeID: object.NodeID, Login: object.Login,
				})
			}
		}
		hasNext := page.NextURL != ""
		nextURL := page.NextURL
		nextETag := ""
		if nextURL == "" {
			nextURL = s.GitHub.UsersURL(highwater)
			nextETag = page.ETag
		}
		if err := s.Store.ApplyTailPage(ctx, candidates, highwater, nextURL, nextETag); err != nil {
			return err
		}
		s.workerRequest(
			ctx, worker, role, "checked new-account tail", page.Rate,
			len(candidates), 0,
		)
		if !hasNext {
			if err := sleep(ctx, s.Config.TailPollInterval); err != nil {
				return nil
			}
		}
	}
	return nil
}

func (s *Service) coverageAudit(ctx context.Context) error {
	const worker = "coverage-auditor"
	const role = "searchable account coverage audit"
	s.workerActivity(ctx, worker, role, "running", "waiting for an auditable generation")
	defer s.Store.StopWorker(context.Background(), worker, role)
	for ctx.Err() == nil {
		generation, err := s.Store.CoverageAuditGeneration(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := sleep(ctx, time.Minute); err != nil {
				return nil
			}
			continue
		}
		if err != nil {
			return err
		}
		if err := s.Store.EnsureCoveragePartitions(ctx, generation); err != nil {
			return err
		}
		partition, err := s.Store.ClaimCoveragePartition(ctx, generation.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			finished, finalizeErr := s.Store.FinalizeCoverageGeneration(ctx, generation.ID)
			if finalizeErr != nil {
				return finalizeErr
			}
			if finished {
				s.workerActivity(ctx, worker, role, "waiting",
					fmt.Sprintf("coverage generation %d reconciled", generation.ID))
			}
			if err := sleep(ctx, time.Minute); err != nil {
				return nil
			}
			continue
		}
		if err != nil {
			return err
		}
		s.workerActivity(ctx, worker, role, "running",
			fmt.Sprintf("auditing creation range %s to %s",
				partition.Start.Format(time.RFC3339), partition.End.Format(time.RFC3339)))
		count, err := s.searchUserCount(
			ctx, worker, role, partition.Start, partition.End,
		)
		if err != nil {
			s.coverageAuditError(ctx, worker, role, err)
			_ = s.Store.RetryCoveragePartition(
				context.Background(), partition, err, retryDelay(err, partition.Attempts),
			)
			if isAuthenticationError(err) {
				return err
			}
			continue
		}
		if count.IncompleteResults || count.TotalCount > 1_000 {
			if err := s.Store.SplitCoveragePartition(
				ctx, partition, count.TotalCount, count.IncompleteResults,
			); err != nil {
				return err
			}
			continue
		}
		if partition.LocalCount != nil && *partition.LocalCount == count.TotalCount {
			if err := s.Store.MarkCoverageCountConsistent(
				ctx, partition, count.TotalCount, *partition.LocalCount,
			); err != nil {
				return err
			}
			continue
		}
		candidates, err := s.enumerateSearchPartition(
			ctx, worker, role, partition.Start, partition.End, count.TotalCount,
		)
		if err != nil {
			_ = s.Store.RetryCoveragePartition(
				context.Background(), partition, err, retryDelay(err, partition.Attempts),
			)
			continue
		}
		post, err := s.searchUserCount(ctx, worker, role, partition.Start, partition.End)
		if err != nil || post.IncompleteResults || post.TotalCount != count.TotalCount ||
			int64(len(candidates)) != count.TotalCount {
			if err == nil {
				err = fmt.Errorf(
					"unstable Search partition: pre=%d post=%d unique=%d incomplete=%t",
					count.TotalCount, post.TotalCount, len(candidates), post.IncompleteResults,
				)
			}
			_ = s.Store.RetryCoveragePartition(
				context.Background(), partition, err, retryDelay(err, partition.Attempts),
			)
			continue
		}
		if _, err := s.Store.StageCoveragePartition(
			ctx, partition, count.TotalCount, post.TotalCount, candidates,
		); err != nil {
			return err
		}
		_ = s.Store.SetState(ctx, "coverage_audit_last_success_at",
			time.Now().UTC().Format(time.RFC3339Nano))
	}
	return nil
}

func (s *Service) searchUserCount(
	ctx context.Context, worker, role string, start, end time.Time,
) (githubapi.UserSearchCount, error) {
	const timestamp = "2006-01-02T15:04:05Z"
	query := fmt.Sprintf(
		"type:user created:%s..%s",
		start.UTC().Format(timestamp), end.UTC().Format(timestamp),
	)
	if err := s.search.Wait(ctx); err != nil {
		return githubapi.UserSearchCount{}, err
	}
	result, err := s.GitHub.SearchUserCount(ctx, query)
	if err != nil {
		s.handleRateError(ctx, err, s.search, "search")
		return githubapi.UserSearchCount{}, err
	}
	s.search.Observe(result.Rate)
	s.recordPacer(ctx, "search", s.search)
	s.workerRequest(ctx, worker, role, "counted Search creation range", result.Rate, 0, 0)
	return result, nil
}

func (s *Service) enumerateSearchPartition(
	ctx context.Context,
	worker, role string,
	start, end time.Time,
	total int64,
) ([]model.Candidate, error) {
	if total < 0 || total > 1_000 {
		return nil, fmt.Errorf("Search partition total outside 0..1000: %d", total)
	}
	const timestamp = "2006-01-02T15:04:05Z"
	query := fmt.Sprintf(
		"type:user created:%s..%s",
		start.UTC().Format(timestamp), end.UTC().Format(timestamp),
	)
	unique := make(map[int64]model.Candidate, total)
	pages := int((total + 99) / 100)
	for page := 1; page <= pages; page++ {
		if err := s.search.Wait(ctx); err != nil {
			return nil, err
		}
		result, err := s.GitHub.SearchUsers(ctx, query, page)
		if err != nil {
			s.handleRateError(ctx, err, s.search, "search")
			return nil, err
		}
		s.search.Observe(result.Rate)
		if result.IncompleteResults || result.TotalCount != total {
			return nil, fmt.Errorf(
				"Search page drift: expected=%d received=%d incomplete=%t",
				total, result.TotalCount, result.IncompleteResults,
			)
		}
		for _, user := range result.Items {
			if user.Type != "User" || user.ID <= 0 || user.NodeID == "" || user.Login == "" {
				return nil, fmt.Errorf("invalid user identity in Search page %d", page)
			}
			if _, exists := unique[user.ID]; exists {
				return nil, fmt.Errorf("duplicate GitHub ID %d in Search partition", user.ID)
			}
			unique[user.ID] = model.Candidate{
				GitHubID: user.ID, NodeID: user.NodeID, Login: user.Login,
			}
		}
		s.workerRequest(ctx, worker, role, "enumerated Search repair page", result.Rate, len(result.Items), 0)
	}
	result := make([]model.Candidate, 0, len(unique))
	for _, candidate := range unique {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GitHubID < result[j].GitHubID })
	return result, nil
}

func (s *Service) coverageAuditError(
	ctx context.Context, worker, role string, err error,
) {
	message := err.Error()
	if len(message) > 2_000 {
		message = message[:2_000]
	}
	_ = s.Store.SetState(ctx, "coverage_audit_status", "retrying")
	_ = s.Store.SetState(ctx, "coverage_audit_last_error", message)
	s.workerError(ctx, worker, role, "coverage partition failed; retrying", err)
}

func (s *Service) searchUserCountRange(
	ctx context.Context,
	worker string,
	role string,
	start time.Time,
	end time.Time,
) (int64, error) {
	const timestamp = "2006-01-02T15:04:05Z"
	query := fmt.Sprintf(
		"type:user created:%s..%s",
		start.UTC().Format(timestamp), end.UTC().Format(timestamp),
	)
	if err := s.search.Wait(ctx); err != nil {
		return 0, err
	}
	result, err := s.GitHub.SearchUserCount(ctx, query)
	if err != nil {
		s.handleRateError(ctx, err, s.search, "search")
		return 0, err
	}
	s.search.Observe(result.Rate)
	s.recordPacer(ctx, "search", s.search)
	s.workerRequest(ctx, worker, role,
		fmt.Sprintf("counted created range %s to %s", start.Format(timestamp), end.Format(timestamp)),
		result.Rate, 0, 0)
	if !result.IncompleteResults {
		return result.TotalCount, nil
	}
	leftStart, leftEnd, rightStart, rightEnd, splittable := splitSearchTimeRange(start, end)
	if !splittable {
		return 0, fmt.Errorf("GitHub search remained incomplete for creation second %s", start.Format(timestamp))
	}
	left, err := s.searchUserCountRange(ctx, worker, role, leftStart, leftEnd)
	if err != nil {
		return 0, err
	}
	right, err := s.searchUserCountRange(ctx, worker, role, rightStart, rightEnd)
	if err != nil {
		return 0, err
	}
	return left + right, nil
}

func splitSearchTimeRange(start, end time.Time) (
	leftStart, leftEnd, rightStart, rightEnd time.Time, ok bool,
) {
	seconds := int64(end.Sub(start) / time.Second)
	if seconds < 1 {
		return time.Time{}, time.Time{}, time.Time{}, time.Time{}, false
	}
	midpoint := start.Add(time.Duration(seconds/2) * time.Second)
	return start, midpoint, midpoint.Add(time.Second), end, true
}

func (s *Service) ensureLiveTail(ctx context.Context, worker, role string) error {
	initialized, err := s.Store.State(ctx, "live_tail_initialized")
	if err != nil || initialized == "true" {
		return err
	}
	legacyReady, err := s.Store.State(ctx, "initial_enumerated")
	if err != nil {
		return err
	}
	highwater, err := s.Store.StateInt(ctx, "tail_highwater")
	if err != nil {
		return err
	}
	if legacyReady == "true" && highwater > 0 {
		requestURL, err := s.Store.State(ctx, "tail_url")
		if err != nil {
			return err
		}
		if requestURL == "" {
			requestURL = s.GitHub.UsersURL(highwater)
		}
		_, err = s.Store.InitializeLiveTail(ctx, highwater, requestURL)
		return err
	}
	run, err := s.Store.ActiveMainRun(ctx)
	if err != nil {
		return err
	}
	cutoff, err := s.discoverUserHighwater(ctx, worker, role, run.NextSinceID)
	if err != nil {
		return err
	}
	created, err := s.Store.InitializeLiveTail(
		ctx, cutoff, s.GitHub.UsersURL(cutoff),
	)
	if err != nil {
		return err
	}
	if created {
		s.Logger.Info("initialized parallel live account tail", "cutoff", cutoff)
		s.workerActivity(
			ctx, worker, role, "running",
			fmt.Sprintf("parallel live tail initialized at account ID %d", cutoff),
		)
	}
	return nil
}

func (s *Service) discoverUserHighwater(
	ctx context.Context,
	worker string,
	role string,
	start int64,
) (int64, error) {
	probe := func(since int64) (bool, error) {
		failures := 0
		for {
			if err := s.rest.Wait(ctx); err != nil {
				return false, err
			}
			page, err := s.GitHub.ListUsers(ctx, s.GitHub.UsersURL(since), "")
			if err == nil {
				s.rest.Observe(page.Rate)
				s.workerRequest(
					ctx, worker, role,
					fmt.Sprintf("probing live-tail boundary after ID %d", since),
					page.Rate, 0, 0,
				)
				return len(page.Objects) > 0, nil
			}
			failures++
			s.workerError(ctx, worker, role, "live-tail boundary probe failed", err)
			if isAuthenticationError(err) {
				return false, err
			}
			s.handleRateError(ctx, err, s.rest, "rest")
			if err := sleep(ctx, retryDelay(err, failures)); err != nil {
				return false, err
			}
		}
	}
	low := max(int64(0), start)
	hasAfterLow, err := probe(low)
	if err != nil {
		return 0, err
	}
	if !hasAfterLow {
		return low, nil
	}
	high := max(int64(1), low*2)
	if high <= low {
		high = low + 1
	}
	for {
		hasAfter, err := probe(high)
		if err != nil {
			return 0, err
		}
		if !hasAfter {
			break
		}
		low = high
		if high > (1<<62)-1 {
			return 0, errors.New("GitHub account ID exceeds supported range")
		}
		high *= 2
	}
	for high-low > 1 {
		middle := low + (high-low)/2
		hasAfter, err := probe(middle)
		if err != nil {
			return 0, err
		}
		if hasAfter {
			low = middle
		} else {
			high = middle
		}
	}
	return high, nil
}

func (s *Service) priorityOwners(ctx context.Context) error {
	const worker = "owner-refresh"
	const role = "known key owner refresh scheduler"
	s.workerActivity(ctx, worker, role, "starting", "scheduling adaptive owner refreshes")
	defer s.Store.StopWorker(context.Background(), worker, role)
	ticker := time.NewTicker(s.Config.PriorityFillInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ownerQueueLimit := max(100, s.Config.QueueMax/10)
			ownerDepth, err := s.Store.QueueDepthByClassCapped(
				ctx, "owner", ownerQueueLimit,
			)
			if err != nil {
				return err
			}
			if ownerDepth >= ownerQueueLimit {
				continue
			}
			limit := ownerQueueLimit - ownerDepth
			inserted, err := s.Store.EnqueueDueOwners(ctx, limit)
			if err != nil {
				s.workerError(ctx, worker, role, "failed to enqueue owner refresh", err)
				return err
			}
			activity := "known-owner refresh queue is current"
			if inserted > 0 {
				activity = fmt.Sprintf("enqueued %d known owners for refresh", inserted)
			}
			s.workerActivity(ctx, worker, role, "waiting", activity)
		}
	}
}

func (s *Service) zeroKeyRechecks(ctx context.Context) error {
	const worker = "zero-key-rechecks"
	const role = "new zero-key account retry scheduler"
	s.workerActivity(ctx, worker, role, "starting", "scheduling zero-key rechecks")
	defer s.Store.StopWorker(context.Background(), worker, role)
	ticker := time.NewTicker(s.Config.PriorityFillInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			liveQueueLimit := max(100, s.Config.QueueMax/10)
			liveDepth, err := s.Store.QueueDepthByClassCapped(
				ctx, "live", liveQueueLimit,
			)
			if err != nil {
				return err
			}
			if liveDepth >= liveQueueLimit {
				continue
			}
			limit := liveQueueLimit - liveDepth
			inserted, err := s.Store.EnqueueDueZeroKeyRechecks(ctx, limit)
			if err != nil {
				s.workerError(ctx, worker, role, "failed to enqueue zero-key rechecks", err)
				return err
			}
			activity := "zero-key retry queue is current"
			if inserted > 0 {
				activity = fmt.Sprintf("enqueued %d zero-key accounts for recheck", inserted)
			}
			s.workerActivity(ctx, worker, role, "waiting", activity)
		}
	}
}

func (s *Service) retryAnomalies(ctx context.Context) error {
	const worker = "anomaly-retries"
	const role = "persistent anomaly retry scheduler"
	s.workerActivity(ctx, worker, role, "starting", "scheduling unresolved account retries")
	defer s.Store.StopWorker(context.Background(), worker, role)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			inserted, err := s.Store.EnqueueDueAnomalies(ctx, 100)
			if err != nil {
				return err
			}
			activity := "persistent anomaly queue is current"
			if inserted > 0 {
				activity = fmt.Sprintf("enqueued %d persistent anomaly retries", inserted)
			}
			s.workerActivity(ctx, worker, role, "waiting", activity)
		}
	}
}

func (s *Service) monitorRuns(ctx context.Context) error {
	const worker = "run-monitor"
	const role = "crawl run monitor"
	s.workerActivity(ctx, worker, role, "starting", "monitoring active crawl")
	defer s.Store.StopWorker(context.Background(), worker, role)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	nextHeartbeat := time.Time{}
	nextLeaseReap := time.Time{}
	nextSnapshot := time.Time{}
	monitorStarted := time.Now()
	nextWatchdog := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if time.Now().After(nextWatchdog) {
				due, graphQLSuccess, restSuccess, err := s.Store.DueWorkHealth(ctx)
				if err != nil {
					return err
				}
				now := time.Now()
				graphqlCooldown := s.graphql.Snapshot().CooldownUntil
				if due && graphqlCooldown == nil && now.Sub(monitorStarted) > 10*time.Minute &&
					(graphQLSuccess == nil || now.Sub(*graphQLSuccess) > 10*time.Minute) {
					return errors.New("GraphQL watchdog: due work made no progress for 10 minutes")
				}
				run, runErr := s.Store.ActiveMainRun(ctx)
				if runErr == nil && !run.EnumerationComplete {
					backlog := run.EnumeratedUsers - run.ProcessedUsers
					restCooldown := s.rest.Snapshot().CooldownUntil
					if backlog < int64(max(50, s.Config.QueueMax*4/10)) &&
						restCooldown == nil && now.Sub(monitorStarted) > 10*time.Minute &&
						(restSuccess == nil || now.Sub(*restSuccess) > 10*time.Minute) {
						return errors.New("REST watchdog: unfinished enumeration made no progress for 10 minutes")
					}
				}
				nextWatchdog = now.Add(30 * time.Second)
			}
			if time.Now().After(nextSnapshot) {
				if err := s.Store.SaveRateSample(ctx); err != nil {
					return err
				}
				if err := s.Store.SaveStatusSnapshot(ctx); err != nil {
					s.Logger.Warn("persist status snapshot failed", "error", err)
				}
				nextSnapshot = time.Now().Add(time.Minute)
			}
			if time.Now().After(nextLeaseReap) {
				if _, err := s.Store.ReapExpiredLeases(ctx); err != nil {
					return err
				}
				nextLeaseReap = time.Now().Add(time.Minute)
			}
			if time.Now().After(nextHeartbeat) {
				s.workerActivity(ctx, worker, role, "running", "monitoring active crawl")
				nextHeartbeat = time.Now().Add(30 * time.Second)
			}
			completed, err := s.Store.MaybeCompleteMain(ctx)
			if err != nil {
				s.workerError(ctx, worker, role, "failed to monitor crawl run", err)
				return err
			}
			if completed {
				run, err := s.Store.EnsureMainRun(ctx, s.GitHub.UsersURL(0))
				if err != nil {
					return err
				}
				s.Logger.Info("started reconciliation cycle",
					"run", run.ID, "kind", run.Kind, "cutoff", run.CutoffUserID)
				s.workerActivity(
					ctx, worker, role, "running",
					fmt.Sprintf("started %s run %d", run.Kind, run.ID),
				)
			}
		}
	}
}

func (s *Service) workerActivity(
	ctx context.Context,
	name, role, state, activity string,
) {
	_ = s.Store.UpdateWorker(ctx, store.WorkerUpdate{
		Name: name, Role: role, State: state, Activity: activity,
	})
}

func (s *Service) workerError(
	ctx context.Context,
	name, role, activity string,
	err error,
) {
	_ = s.Store.UpdateWorker(ctx, store.WorkerUpdate{
		Name: name, Role: role, State: "error", Activity: activity, Error: err,
	})
}

func (s *Service) workerRequest(
	ctx context.Context,
	name, role, activity string,
	rate model.Rate,
	users, keys int,
) {
	remaining, limit, resetAt := rate.Remaining, rate.Limit, rate.ResetAt
	_ = s.Store.UpdateWorker(ctx, store.WorkerUpdate{
		Name: name, Role: role, State: "running", Activity: activity,
		ProcessedUsers: users, ProcessedKeys: keys, Request: true,
		RateRemaining: &remaining, RateLimit: &limit, RateResetAt: &resetAt,
		Success: true,
	})
}

func (s *Service) handleRateError(
	ctx context.Context,
	err error,
	pacer *ratelimit.Pacer,
	resource string,
) {
	var limited *githubapi.RateLimitError
	if errors.As(err, &limited) {
		if limited.Secondary {
			pacer.SecondaryLimit(limited.Wait)
		} else {
			pacer.Cooldown(limited.Wait)
		}
		s.recordPacer(ctx, resource, pacer)
	}
}

func (s *Service) recordPacer(
	ctx context.Context,
	resource string,
	pacer *ratelimit.Pacer,
) {
	_ = s.Store.SetState(ctx, resource+"_pacer", store.JSON(pacer.Snapshot()))
}

func retryDelay(err error, attempt int) time.Duration {
	var limited *githubapi.RateLimitError
	if errors.As(err, &limited) {
		return limited.Wait
	}
	if attempt < 1 {
		attempt = 1
	}
	exponent := min(attempt-1, 12)
	delay := time.Duration(1<<exponent)*5*time.Second +
		time.Duration(rand.Intn(6))*time.Second
	return min(delay, 6*time.Hour)
}

func maxJobAttempts(jobs []model.Candidate) int {
	maximum := 1
	for _, job := range jobs {
		if job.Attempts > maximum {
			maximum = job.Attempts
		}
	}
	return maximum
}

func isAuthenticationError(err error) bool {
	var authentication *githubapi.AuthenticationError
	return errors.As(err, &authentication)
}

func sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func durationList(values []time.Duration) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, value.String())
	}
	return strings.Join(parts, ",")
}

type cancelGroup struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
	err    error
}

func withCancelGroup(parent context.Context) (*cancelGroup, context.Context) {
	ctx, cancel := context.WithCancel(parent)
	return &cancelGroup{ctx: ctx, cancel: cancel}, ctx
}

func (g *cancelGroup) Go(function func() error) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		if err := function(); err != nil && !errors.Is(err, context.Canceled) {
			g.once.Do(func() {
				g.err = err
				g.cancel()
			})
		}
	}()
}

func (g *cancelGroup) Wait() error {
	g.wg.Wait()
	g.cancel()
	return g.err
}

func ParseIntEnvironment(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
