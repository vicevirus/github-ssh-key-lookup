package api

import (
	"context"
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
}

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
	status, err := s.Store.Status(request.Context())
	if err != nil {
		s.internalError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, status)
}

func (s *Server) users(response http.ResponseWriter, request *http.Request) {
	afterID, limit, err := parsePagination(request.URL.Query())
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	users, err := s.Store.ListIndexedUsers(request.Context(), afterID, limit+1)
	if err != nil {
		s.internalError(response, err)
		return
	}
	hasMore := len(users) > limit
	if hasMore {
		users = users[:limit]
	}
	var nextAfterID *int64
	if hasMore && len(users) > 0 {
		nextAfterID = &users[len(users)-1].GitHubID
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"users":         users,
		"count":         len(users),
		"limit":         limit,
		"after_id":      afterID,
		"has_more":      hasMore,
		"next_after_id": nextAfterID,
	})
}

func parsePagination(values url.Values) (int64, int, error) {
	const (
		defaultLimit = 100
		maxLimit     = 200
	)
	limit := defaultLimit
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxLimit {
			return 0, 0, fmt.Errorf("limit must be between 1 and %d", maxLimit)
		}
		limit = parsed
	}
	var afterID int64
	if raw := values.Get("after_id"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < 0 {
			return 0, 0, errors.New("after_id must be a non-negative integer")
		}
		afterID = parsed
	}
	return afterID, limit, nil
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
