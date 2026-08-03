package api

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/local/github-ssh-index/internal/sshkey"
	"github.com/local/github-ssh-index/internal/store"
)

type Server struct {
	Store  *store.Store
	Logger *slog.Logger
	limit  *ipLimiter

	statusMu       sync.Mutex
	statusRefresh  sync.Mutex
	statusSnapshot map[string]any
	statusFetched  time.Time
}

const statusCacheTTL = time.Minute

func New(database *store.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		Store: database, Logger: logger,
		limit: newIPLimiter(120, time.Minute),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("GET /api/v1/users", s.users)
	mux.HandleFunc("GET /api/v1/lookup", s.lookupGET)
	mux.HandleFunc("POST /api/v1/lookup", s.lookupPOST)
	return s.securityHeaders(s.rateLimit(mux))
}

func (s *Server) ListenAndServe(ctx context.Context, address string) error {
	server := &http.Server{
		Addr:              address,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	s.Logger.Info("lookup API listening", "address", address)
	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) health(response http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Pool.Ping(ctx); err != nil {
		writeJSON(response, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy"})
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) status(response http.ResponseWriter, request *http.Request) {
	now := time.Now()
	s.statusMu.Lock()
	snapshot, fetched := s.statusSnapshot, s.statusFetched
	s.statusMu.Unlock()
	if snapshot == nil {
		ctx, cancel := context.WithTimeout(request.Context(), 500*time.Millisecond)
		persisted, persistedAt, err := s.Store.LoadStatusSnapshot(ctx)
		cancel()
		if err == nil {
			snapshot, fetched = persisted, persistedAt
			s.statusMu.Lock()
			s.statusSnapshot, s.statusFetched = persisted, persistedAt
			s.statusMu.Unlock()
		}
	}
	if snapshot != nil && now.Sub(fetched) < statusCacheTTL {
		s.writeStatusSnapshot(response, snapshot, fetched, false)
		return
	}

	// Status performs several full-table counts. Never make an HTTP caller wait
	// for those counts: one goroutine refreshes in the background and callers
	// receive the last snapshot (or a fast warming response on first boot).
	if s.statusRefresh.TryLock() {
		go s.refreshStatus()
	}
	if snapshot != nil {
		s.writeStatusSnapshot(response, snapshot, fetched, true)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"status": "warming",
		"status_cache": map[string]any{
			"stale":   true,
			"message": "status snapshot is being prepared; use /healthz for liveness",
		},
	})
}

func (s *Server) refreshStatus() {
	defer s.statusRefresh.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fresh, err := s.Store.Status(ctx)
	if err != nil {
		s.Logger.Warn("status snapshot refresh failed", "error", err)
		return
	}
	s.statusMu.Lock()
	s.statusSnapshot = fresh
	s.statusFetched = time.Now()
	s.statusMu.Unlock()
}

func (s *Server) writeStatusSnapshot(
	response http.ResponseWriter,
	snapshot map[string]any,
	fetched time.Time,
	stale bool,
) {
	body := compactStatusSnapshot(snapshot)
	age := time.Since(fetched)
	if age < 0 {
		age = 0
	}
	body["status_cache"] = map[string]any{
		"fetched_at":  fetched.UTC().Format(time.RFC3339Nano),
		"age_seconds": age.Seconds(),
		"ttl_seconds": statusCacheTTL.Seconds(),
		"stale":       stale || age >= statusCacheTTL,
	}
	response.Header().Set(
		"Cache-Control",
		fmt.Sprintf("public, max-age=%d", int(statusCacheTTL.Seconds())),
	)
	response.Header().Set("X-Status-Snapshot-At", fetched.UTC().Format(time.RFC3339Nano))
	writeJSON(response, http.StatusOK, body)
}

func compactStatusSnapshot(snapshot map[string]any) map[string]any {
	index := anyMap(snapshot["index"])
	progress := anyMap(snapshot["progress"])
	crawler := anyMap(snapshot["crawler"])
	coverage := anyMap(snapshot["coverage"])
	recovery := anyMap(snapshot["recovery"])
	passes := anyMap(snapshot["passes"])
	lookup := anyMap(snapshot["lookup"])
	estimate := anyMap(progress["estimated_completion"])

	state := "offline"
	if online, _ := crawler["online"].(bool); online {
		state = "running"
	}
	var runErrors int64
	if runs, ok := snapshot["runs"].([]store.Run); ok && len(runs) > 0 {
		runErrors = runs[0].ErrorUsers
	} else if runs, ok := snapshot["runs"].([]any); ok && len(runs) > 0 {
		if run := anyMap(runs[0]); run != nil {
			runErrors = int64(anyNumber(run["error_users"]))
		}
	}
	return map[string]any{
		"status": state,
		"usable": lookup["usable"],
		"crawler": map[string]any{
			"online":            crawler["online"],
			"phase":             progress["phase"],
			"stage":             progress["stage"],
			"active_workers":    crawler["active_workers"],
			"last_heartbeat_at": crawler["last_heartbeat_at"],
		},
		"index": map[string]any{
			"owners": index["owners"],
			"keys":   index["keys"],
		},
		"progress": map[string]any{
			"enumerated_users":           progress["enumerated_users"],
			"attempted_users":            progress["attempted_users"],
			"processed_users":            progress["processed_users"],
			"queued_users":               progress["processing_backlog"],
			"rest_fallback_users":        progress["rest_fallback_users"],
			"enumeration_complete":       progress["enumeration_complete"],
			"remaining_id_positions":     progress["remaining_id_positions"],
			"processing_users_per_hour":  estimate["rate_users_per_hour"],
			"attempt_rate_per_hour":      progress["rolling_1h_attempts_per_hour"],
			"enumeration_users_per_hour": progress["current_enumeration_users_per_hour"],
			"estimated_finish_early":     estimate["estimated_finish_early"],
			"estimated_finish_late":      estimate["estimated_finish_late"],
			"estimate_basis":             estimate["basis"],
			"estimate_preliminary":       estimate["rate_is_preliminary"],
			"estimate_scope":             "first pass: discovery plus settled GraphQL/REST key coverage",
		},
		"passes": passes,
		"lookup": lookup,
		"coverage": map[string]any{
			"initial_complete":         coverage["initial_complete"],
			"generation_id":            coverage["generation_id"],
			"generation_status":        coverage["generation_status"],
			"settled_cutoff":           coverage["settled_cutoff"],
			"discovered_accounts":      coverage["discovered_accounts"],
			"successful_accounts":      coverage["successful_accounts"],
			"inaccessible_accounts":    coverage["inaccessible_accounts"],
			"unresolved_accounts":      coverage["unresolved_accounts"],
			"missing_accounts":         coverage["missing_accounts"],
			"audit_status":             coverage["audit_status"],
			"audit_complete":           coverage["audit_complete"],
			"audit_days_complete":      coverage["audit_days_complete"],
			"audit_days_total":         coverage["audit_days_total"],
			"audited_through":          coverage["audited_through"],
			"searchable_users":         coverage["searchable_users"],
			"initial_enumerated_users": coverage["initial_enumerated_users"],
			"searchable_user_gap":      coverage["searchable_user_gap"],
			"verification_state":       coverage["verification_state"],
			"confidence":               coverage["confidence"],
			"identity_proven":          false,
			"audit_last_error":         coverage["audit_last_error"],
			"audit_last_success_at":    coverage["audit_last_success_at"],
		},
		"errors": map[string]any{
			"run_errors":    runErrors,
			"retrying_jobs": recovery["retrying_jobs"],
		},
	}
}

func anyMap(value any) map[string]any {
	if result, ok := value.(map[string]any); ok {
		return result
	}
	if integers, ok := value.(map[string]int64); ok {
		result := make(map[string]any, len(integers))
		for key, item := range integers {
			result[key] = item
		}
		return result
	}
	return map[string]any{}
}

func anyNumber(value any) float64 {
	switch number := value.(type) {
	case float64:
		return number
	case int64:
		return float64(number)
	case int:
		return float64(number)
	default:
		return 0
	}
}

func (s *Server) users(response http.ResponseWriter, request *http.Request) {
	page, err := parsePagination(request.URL.Query())
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if page.Snapshot.IsZero() {
		page.Snapshot, err = s.Store.SnapshotTime(request.Context())
		if err != nil {
			s.internalError(response, err)
			return
		}
	}
	users, err := s.Store.ListIndexedUsers(
		request.Context(), page.AfterID, page.Snapshot, page.Limit+1,
	)
	if err != nil {
		s.internalError(response, err)
		return
	}
	hasMore := len(users) > page.Limit
	if hasMore {
		users = users[:page.Limit]
	}
	var nextAfterID *int64
	var nextCursor, nextURL *string
	if hasMore && len(users) > 0 {
		nextAfterID = &users[len(users)-1].GitHubID
		cursor := encodeCursor(*nextAfterID, page.Snapshot)
		nextCursor = &cursor
		target := nextPageURL(request, cursor, page.Limit)
		nextURL = &target
		response.Header().Set("Link", "<"+target+">; rel=\"next\"")
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"users":         users,
		"count":         len(users),
		"limit":         page.Limit,
		"after_id":      page.AfterID,
		"has_more":      hasMore,
		"next_after_id": nextAfterID,
		"next_cursor":   nextCursor,
		"next_url":      nextURL,
		"pagination": map[string]any{
			"count":       len(users),
			"limit":       page.Limit,
			"has_more":    hasMore,
			"next_cursor": nextCursor,
			"next_url":    nextURL,
		},
	})
}

type paginationRequest struct {
	AfterID  int64
	Limit    int
	Snapshot time.Time
}

func parsePagination(values url.Values) (paginationRequest, error) {
	const (
		defaultLimit = 100
		maxLimit     = 200
	)
	page := paginationRequest{Limit: defaultLimit}
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxLimit {
			return paginationRequest{}, fmt.Errorf("limit must be between 1 and %d", maxLimit)
		}
		page.Limit = parsed
	}
	rawCursor, rawAfterID := values.Get("cursor"), values.Get("after_id")
	if rawCursor != "" && rawAfterID != "" {
		return paginationRequest{}, errors.New("cursor and after_id cannot be used together")
	}
	if rawCursor != "" {
		afterID, snapshot, err := decodeCursor(rawCursor)
		if err != nil {
			return paginationRequest{}, err
		}
		page.AfterID = afterID
		page.Snapshot = snapshot
	} else if rawAfterID != "" {
		parsed, err := strconv.ParseInt(rawAfterID, 10, 64)
		if err != nil || parsed < 0 {
			return paginationRequest{}, errors.New("after_id must be a non-negative integer")
		}
		page.AfterID = parsed
	}
	return page, nil
}

const cursorPayloadSize = 17

func encodeCursor(afterID int64, snapshot time.Time) string {
	payload := make([]byte, cursorPayloadSize)
	payload[0] = 1
	binary.BigEndian.PutUint64(payload[1:9], uint64(afterID))
	binary.BigEndian.PutUint64(payload[9:17], uint64(snapshot.UnixMicro()))
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeCursor(raw string) (int64, time.Time, error) {
	if len(raw) != base64.RawURLEncoding.EncodedLen(cursorPayloadSize) {
		return 0, time.Time{}, errors.New("invalid cursor")
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(payload) != cursorPayloadSize || payload[0] != 1 {
		return 0, time.Time{}, errors.New("invalid cursor")
	}
	rawAfterID := binary.BigEndian.Uint64(payload[1:9])
	if rawAfterID > uint64(1<<63-1) {
		return 0, time.Time{}, errors.New("invalid cursor")
	}
	snapshot := time.UnixMicro(int64(binary.BigEndian.Uint64(payload[9:17]))).UTC()
	earliest := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	latest := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
	if snapshot.Before(earliest) || !snapshot.Before(latest) {
		return 0, time.Time{}, errors.New("invalid cursor")
	}
	return int64(rawAfterID), snapshot, nil
}

func nextPageURL(request *http.Request, cursor string, limit int) string {
	values := request.URL.Query()
	values.Del("after_id")
	values.Set("cursor", cursor)
	values.Set("limit", strconv.Itoa(limit))
	return request.URL.Path + "?" + values.Encode()
}

func (s *Server) lookupGET(response http.ResponseWriter, request *http.Request) {
	s.lookup(response, request, request.URL.Query().Get("value"))
}

func (s *Server) lookupPOST(response http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	var input struct {
		Value string `json:"value"`
	}
	decoder := json.NewDecoder(request.Body)
	if err := decoder.Decode(&input); err != nil {
		if err == io.EOF {
			writeJSON(response, http.StatusBadRequest, map[string]string{"error": "missing JSON body"})
		} else {
			writeJSON(response, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		}
		return
	}
	s.lookup(response, request, input.Value)
}

func (s *Server) lookup(response http.ResponseWriter, request *http.Request, value string) {
	if strings.TrimSpace(value) == "" {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": "value is required"})
		return
	}
	fingerprint, err := sshkey.NormalizeFingerprint(value)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	matches, err := s.Store.Lookup(request.Context(), fingerprint)
	if err != nil {
		s.internalError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"fingerprint":    fingerprint,
		"matches":        matches,
		"count":          len(matches),
		"interpretation": "A match is a public GitHub key association observed by this index, not proof of a person's identity or activity.",
	})
}

func (s *Server) internalError(response http.ResponseWriter, err error) {
	s.Logger.Error("API request failed", "error", err)
	writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(response, request)
	})
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil {
			host = request.RemoteAddr
		}
		if !s.limit.allow(host) {
			response.Header().Set("Retry-After", "60")
			writeJSON(response, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			return
		}
		next.ServeHTTP(response, request)
	})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

type ipWindow struct {
	start time.Time
	count int
}

type ipLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	items  map[string]ipWindow
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{limit: limit, window: window, items: make(map[string]ipWindow)}
}

func (l *ipLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	item := l.items[key]
	if item.start.IsZero() || now.Sub(item.start) >= l.window {
		item = ipWindow{start: now}
	}
	item.count++
	l.items[key] = item
	if len(l.items) > 10_000 {
		for candidate, value := range l.items {
			if now.Sub(value.start) >= l.window {
				delete(l.items, candidate)
			}
		}
	}
	return item.count <= l.limit
}
