package crawler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"strconv"
	"strings"
	"sync"
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
	RESTReserve           int
	GraphQLReserve        int
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
		RESTReserve:      150,
		GraphQLReserve:   200,
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

	scheduleMu     sync.Mutex
	scheduleCursor int
}

func New(database *store.Store, github *githubapi.Client, config Config, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if config.Workers < 1 {
		config.Workers = 1
	}
	if config.Workers > 5 {
		config.Workers = 5
	}
	if config.QueueMax < 100 {
		config.QueueMax = 100
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
	if _, err := s.Store.EnsureMainRun(ctx, s.GitHub.UsersURL(0)); err != nil {
		return err
	}
	s.workerActivity(ctx, "scheduler", "scheduler", "running", "crawler started")
	defer s.Store.StopWorker(context.Background(), "scheduler", "scheduler")
	group, groupCtx := withCancelGroup(ctx)
	activeRun, err := s.Store.ActiveMainRun(groupCtx)
	if err != nil {
		return err
	}
	sharded := activeRun.CutoffUserID != nil && !activeRun.EnumerationComplete
	if sharded {
		if err := s.Store.EnsureEnumerationShards(groupCtx, activeRun, s.Config.Workers, s.GitHub.UsersURL); err != nil {
			return err
		}
		for worker := 0; worker < s.Config.Workers; worker++ {
			workerID := worker
			group.Go(func() error { return s.enumerateShardWorker(groupCtx, workerID) })
		}
	} else {
		group.Go(func() error { return s.enumerateMain(groupCtx) })
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
		if err != nil {
			return err
		}
		shard, err := s.Store.ClaimEnumerationShard(ctx, run.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			if run.EnumerationComplete {
				return nil
			}
			if err := sleep(ctx, 250*time.Millisecond); err != nil {
				return nil
			}
			continue
		}
		if err != nil {
			return err
		}
		for ctx.Err() == nil {
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
			s.workerRequest(ctx, worker, role, "enumerated ID range", page.Rate, len(candidates), 0)
			if reached {
				break
			}
			shard.NextSinceID, shard.NextURL = nextSince, nextURL
		}
	}
	return nil
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
			depth, err := s.Store.QueueDepth(ctx)
			if err == nil && depth >= 500 {
				return
			}
			run, err := s.Store.ActiveMainRun(ctx)
			if err == nil && run.EnumerationComplete {
				return
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
		depth, err := s.Store.QueueDepth(ctx)
		if err != nil {
			return err
		}
		globalDepth, err := s.Store.QueueDepthByClass(ctx, "global")
		if err != nil {
			return err
		}
		globalQueueLimit := max(100, s.Config.QueueMax*8/10)
		if depth >= s.Config.QueueMax || globalDepth >= globalQueueLimit {
			if err := sleep(ctx, 500*time.Millisecond); err != nil {
				return nil
			}
			continue
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
		ids := make([]string, len(jobs))
		for index := range jobs {
			ids[index] = jobs[index].NodeID
		}
		if err := s.graphql.Wait(ctx); err != nil {
			_ = s.Store.RequeueAccounts(context.Background(), jobs, err)
			return nil
		}
		response, err := s.GitHub.FetchUsers(ctx, ids)
		if err != nil {
			s.workerError(ctx, worker, role, "GraphQL account batch failed", err)
			s.handleRateError(ctx, err, s.graphql, "graphql")
			_ = s.Store.RequeueAccounts(context.Background(), jobs, err)
			if isAuthenticationError(err) {
				return err
			}
			s.Logger.Warn("GraphQL batch failed", "worker", workerID, "users", len(jobs), "error", err)
			_ = sleep(ctx, retryDelay(err, maxJobAttempts(jobs)))
			continue
		}
		s.graphql.Observe(response.Rate)
		s.graphql.ExtraCost(response.Rate.Cost)
		results, err := normalizeUsers(jobs, response.Nodes)
		if err != nil {
			_ = s.Store.RequeueAccounts(context.Background(), jobs, err)
			s.Logger.Error("invalid GitHub key response", "error", err)
			_ = sleep(ctx, retryDelay(err, maxJobAttempts(jobs)))
			continue
		}
		if err := s.Store.CompleteAccountsScheduled(
			ctx, jobs, results,
			s.Config.OwnerSchedule, s.Config.ZeroKeyRecheckAges,
		); err != nil {
			_ = s.Store.RequeueAccounts(context.Background(), jobs, err)
			return err
		}
		keyCount := 0
		invalidKeyCount := 0
		for _, result := range results {
			if result != nil {
				keyCount += len(result.Keys)
				invalidKeyCount += result.InvalidKeys
				if result.InvalidKeys > 0 {
					s.Logger.Warn("skipped malformed GitHub public key",
						"login", result.Login, "github_id", result.GitHubID,
						"count", result.InvalidKeys)
				}
			}
		}
		s.workerRequest(
			ctx, worker, role, "indexed SSH key batch", response.Rate,
			len(jobs), keyCount,
		)
		s.Logger.Info("indexed GraphQL batch",
			"worker", workerID, "users", len(jobs), "keys", keyCount,
			"invalid_keys", invalidKeyCount,
			"cost", response.Rate.Cost, "remaining", response.Rate.Remaining,
			"latency", response.Elapsed)
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
	user, rate, err := s.GitHub.MoreKeys(ctx, job.NodeID, job.Cursor)
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
	keys, invalidKeys := normalizeKeys(user.PublicKeys.Nodes)
	if invalidKeys > 0 {
		s.Logger.Warn("skipped malformed GitHub overflow public key",
			"login", user.Login, "github_id", job.GitHubID,
			"count", invalidKeys)
	}
	s.workerRequest(
		ctx, worker, role, "indexed overflow SSH key page", rate, 0, len(keys),
	)
	err = s.Store.CompleteOverflowScheduled(
		ctx, job, keys, user.PublicKeys.PageInfo.HasNextPage,
		user.PublicKeys.PageInfo.EndCursor, s.Config.OwnerSchedule,
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
		if user.DatabaseID != 0 && user.DatabaseID != jobs[index].GitHubID {
			return nil, fmt.Errorf(
				"GraphQL response order mismatch: expected %d, received %d",
				jobs[index].GitHubID, user.DatabaseID,
			)
		}
		keys, invalidKeys := normalizeKeys(user.PublicKeys.Nodes)
		results[index] = &model.UserResult{
			NodeID: user.ID, GitHubID: jobs[index].GitHubID, Login: user.Login,
			Keys: keys, HasMoreKeys: user.PublicKeys.PageInfo.HasNextPage,
			NextCursor:    user.PublicKeys.PageInfo.EndCursor,
			TotalKeyCount: user.PublicKeys.TotalCount,
			InvalidKeys:   invalidKeys,
		}
	}
	return results, nil
}

func normalizeKeys(keys []githubapi.GraphQLKey) ([]model.PublicKey, int) {
	result := make([]model.PublicKey, 0, len(keys))
	invalid := 0
	for _, raw := range keys {
		key, err := sshkey.Parse(raw.Key)
		if err != nil {
			invalid++
			continue
		}
		if strings.HasPrefix(raw.Fingerprint, "SHA256:") && raw.Fingerprint != key.Text {
			invalid++
			continue
		}
		result = append(result, key)
	}
	return result, invalid
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
		depth, err := s.Store.QueueDepth(ctx)
		if err != nil {
			return err
		}
		liveDepth, err := s.Store.QueueDepthByClass(ctx, "live")
		if err != nil {
			return err
		}
		liveQueueLimit := max(100, s.Config.QueueMax/10)
		if depth >= s.Config.QueueMax || liveDepth >= liveQueueLimit {
			if err := sleep(ctx, 250*time.Millisecond); err != nil {
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
			depth, err := s.Store.QueueDepth(ctx)
			if err != nil {
				return err
			}
			ownerDepth, err := s.Store.QueueDepthByClass(ctx, "owner")
			if err != nil {
				return err
			}
			ownerQueueLimit := max(100, s.Config.QueueMax/10)
			if depth >= s.Config.QueueMax || ownerDepth >= ownerQueueLimit {
				continue
			}
			limit := min(
				ownerQueueLimit-ownerDepth,
				s.Config.QueueMax-depth,
			)
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
			depth, err := s.Store.QueueDepth(ctx)
			if err != nil {
				return err
			}
			liveDepth, err := s.Store.QueueDepthByClass(ctx, "live")
			if err != nil {
				return err
			}
			liveQueueLimit := max(100, s.Config.QueueMax/10)
			if depth >= s.Config.QueueMax || liveDepth >= liveQueueLimit {
				continue
			}
			limit := min(
				liveQueueLimit-liveDepth,
				s.Config.QueueMax-depth,
			)
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

func (s *Service) monitorRuns(ctx context.Context) error {
	const worker = "run-monitor"
	const role = "crawl run monitor"
	s.workerActivity(ctx, worker, role, "starting", "monitoring active crawl")
	defer s.Store.StopWorker(context.Background(), worker, role)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	nextHeartbeat := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
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
	exponent := min(attempt-1, 9)
	delay := time.Duration(1<<exponent)*time.Second +
		time.Duration(rand.Intn(4))*time.Second
	return min(delay, 15*time.Minute)
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
