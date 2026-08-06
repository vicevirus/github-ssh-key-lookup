package githubapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/local/github-ssh-index/internal/model"
)

const usersAndKeysQuery = `
query UsersAndKeys($ids: [ID!]!) {
  nodes(ids: $ids) {
    __typename
    ... on User {
      id
      databaseId
      login
	  createdAt
      publicKeys(first: 100) {
        totalCount
        pageInfo { hasNextPage endCursor }
        nodes { key fingerprint }
      }
    }
  }
  rateLimit { cost limit remaining used resetAt }
}`

const usersByDatabaseIDQuery = `
query UsersByDatabaseID($representations: [_Any!]!) {
  _entities(representations: $representations) {
    __typename
    ... on User {
      id
      databaseId
      login
      createdAt
      publicKeys(first: 100) {
        totalCount
        pageInfo { hasNextPage endCursor }
        nodes { key fingerprint }
      }
    }
  }
  rateLimit { cost limit remaining used resetAt }
}`

const moreKeysQuery = `
query MoreKeys($id: ID!, $after: String!) {
  node(id: $id) {
    ... on User {
      id
      databaseId
      login
	  createdAt
      publicKeys(first: 100, after: $after) {
        totalCount
        pageInfo { hasNextPage endCursor }
        nodes { key fingerprint }
      }
    }
  }
  rateLimit { cost limit remaining used resetAt }
}`

const resourceUserFields = `
    __typename
    ... on User {
      id
      databaseId
      login
      createdAt
      publicKeys(first: 100) {
        totalCount
        pageInfo { hasNextPage endCursor }
        nodes { key fingerprint }
      }
    }`

type Client struct {
	Token      string
	RESTBase   string
	GraphQLURL string
	UserAgent  string
	APIVersion string
	HTTP       *http.Client

	credentialsMu sync.RWMutex
	credentials   []credential
	restNext      atomic.Uint64
	graphqlNext   atomic.Uint64
	searchNext    atomic.Uint64
}

type credential struct {
	token    string
	disabled bool
}

type RESTUser struct {
	Login     string    `json:"login"`
	ID        int64     `json:"id"`
	NodeID    string    `json:"node_id"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

type UsersPage struct {
	Objects     []RESTUser
	NextURL     string
	ETag        string
	NotModified bool
	Rate        model.Rate
	Elapsed     time.Duration
}

type PublicKeysPage struct {
	Keys     []string
	NextURL  string
	NotFound bool
	Rate     model.Rate
	Elapsed  time.Duration
}

type UserSearchCount struct {
	TotalCount        int64
	IncompleteResults bool
	Rate              model.Rate
	Elapsed           time.Duration
}

type UserSearchPage struct {
	Items             []RESTUser
	TotalCount        int64
	IncompleteResults bool
	Rate              model.Rate
	Elapsed           time.Duration
}

type GraphQLKey struct {
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

type PageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

type KeyConnection struct {
	TotalCount int          `json:"totalCount"`
	PageInfo   PageInfo     `json:"pageInfo"`
	Nodes      []GraphQLKey `json:"nodes"`
}

type GraphQLUser struct {
	TypeName   string        `json:"__typename"`
	ID         string        `json:"id"`
	DatabaseID int64         `json:"databaseId"`
	Login      string        `json:"login"`
	CreatedAt  time.Time     `json:"createdAt"`
	PublicKeys KeyConnection `json:"publicKeys"`
}

type UsersAndKeys struct {
	Nodes   []*GraphQLUser
	Rate    model.Rate
	Elapsed time.Duration
}

type RateLimitError struct {
	Status    int
	Wait      time.Duration
	Body      string
	Secondary bool
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("GitHub rate limited request (HTTP %d, retry in %s): %s", e.Status, e.Wait, e.Body)
}

type AuthenticationError struct {
	Status int
	Body   string
}

type HTTPError struct {
	Operation string
	Status    int
	Body      string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("GitHub %s HTTP %d: %s", e.Operation, e.Status, e.Body)
}

func IsGatewayTimeout(err error) bool {
	var request *HTTPError
	return errors.As(err, &request) &&
		(request.Status == http.StatusBadGateway || request.Status == http.StatusGatewayTimeout)
}

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("GitHub authentication failed (HTTP %d): %s", e.Status, e.Body)
}

func New(token, userAgent string) *Client {
	return NewWithTokens([]string{token}, userAgent)
}

// NewWithTokens creates one client with independent GitHub credentials. Each
// API resource is distributed round-robin so its per-user quota remains
// balanced. A credential returning HTTP 401 is disabled for the lifetime of
// the process and the request is transparently retried with another token.
func NewWithTokens(tokens []string, userAgent string) *Client {
	unique := make([]credential, 0, len(tokens))
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if _, exists := seen[token]; exists {
			continue
		}
		seen[token] = struct{}{}
		unique = append(unique, credential{token: token})
	}
	primary := ""
	if len(unique) != 0 {
		primary = unique[0].token
	}
	return &Client{
		Token:       primary,
		RESTBase:    "https://api.github.com",
		GraphQLURL:  "https://api.github.com/graphql",
		UserAgent:   userAgent,
		APIVersion:  "2026-03-10",
		credentials: unique,
		HTTP: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (c *Client) CredentialCount() int {
	c.credentialsMu.RLock()
	defer c.credentialsMu.RUnlock()
	return len(c.credentials)
}

func (c *Client) ActiveCredentialCount() int {
	c.credentialsMu.RLock()
	defer c.credentialsMu.RUnlock()
	active := 0
	for _, item := range c.credentials {
		if !item.disabled {
			active++
		}
	}
	return active
}

func (c *Client) UsersURL(since int64) string {
	return fmt.Sprintf("%s/users?since=%d&per_page=100", strings.TrimRight(c.RESTBase, "/"), since)
}

func (c *Client) ListUsers(ctx context.Context, requestURL, etag string) (UsersPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return UsersPage{}, err
	}
	c.headers(req)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	started := time.Now()
	resp, err := c.do(req)
	if err != nil {
		return UsersPage{}, err
	}
	defer resp.Body.Close()
	page := UsersPage{
		ETag:    resp.Header.Get("ETag"),
		Rate:    rateFromHeaders(resp.Header),
		Elapsed: time.Since(started),
	}
	if resp.StatusCode == http.StatusNotModified {
		page.NotModified = true
		return page, nil
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return UsersPage{}, rateError(resp)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return UsersPage{}, &AuthenticationError{Status: resp.StatusCode, Body: string(body)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return UsersPage{}, fmt.Errorf("GitHub REST HTTP %d: %s", resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(&page.Objects); err != nil {
		return UsersPage{}, fmt.Errorf("decode GitHub users: %w", err)
	}
	page.NextURL = nextLink(resp.Header.Get("Link"))
	return page, nil
}

// SearchUserCount returns only the count for a user-search partition. Callers
// must reject or subdivide incomplete results before treating the count as a
// coverage measurement.
func (c *Client) SearchUserCount(ctx context.Context, query string) (UserSearchCount, error) {
	endpoint := strings.TrimRight(c.RESTBase, "/") + "/search/users"
	values := url.Values{"q": {query}, "per_page": {"1"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+values.Encode(), nil)
	if err != nil {
		return UserSearchCount{}, err
	}
	c.headers(req)
	started := time.Now()
	resp, err := c.do(req)
	if err != nil {
		return UserSearchCount{}, err
	}
	defer resp.Body.Close()
	result := UserSearchCount{
		Rate: rateFromHeaders(resp.Header), Elapsed: time.Since(started),
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return UserSearchCount{}, rateError(resp)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return UserSearchCount{}, &AuthenticationError{Status: resp.StatusCode, Body: string(body)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return UserSearchCount{}, fmt.Errorf("GitHub user search HTTP %d: %s", resp.StatusCode, body)
	}
	var body struct {
		TotalCount        int64 `json:"total_count"`
		IncompleteResults bool  `json:"incomplete_results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return UserSearchCount{}, fmt.Errorf("decode GitHub user search: %w", err)
	}
	result.TotalCount = body.TotalCount
	result.IncompleteResults = body.IncompleteResults
	return result, nil
}

// SearchUsers enumerates one stable user-search page. Callers must enforce the
// 1,000-result search ceiling, deduplicate IDs, and compare pre/post counts.
func (c *Client) SearchUsers(ctx context.Context, query string, page int) (UserSearchPage, error) {
	if page < 1 || page > 10 {
		return UserSearchPage{}, fmt.Errorf("GitHub user search page outside 1..10: %d", page)
	}
	endpoint := strings.TrimRight(c.RESTBase, "/") + "/search/users"
	values := url.Values{
		"q": {query}, "per_page": {"100"}, "page": {strconv.Itoa(page)},
		"sort": {"joined"}, "order": {"asc"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+values.Encode(), nil)
	if err != nil {
		return UserSearchPage{}, err
	}
	c.headers(req)
	started := time.Now()
	resp, err := c.do(req)
	if err != nil {
		return UserSearchPage{}, err
	}
	defer resp.Body.Close()
	result := UserSearchPage{Rate: rateFromHeaders(resp.Header), Elapsed: time.Since(started)}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return UserSearchPage{}, rateError(resp)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return UserSearchPage{}, &AuthenticationError{Status: resp.StatusCode, Body: string(body)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return UserSearchPage{}, fmt.Errorf("GitHub user search HTTP %d: %s", resp.StatusCode, body)
	}
	var body struct {
		TotalCount        int64      `json:"total_count"`
		IncompleteResults bool       `json:"incomplete_results"`
		Items             []RESTUser `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return UserSearchPage{}, fmt.Errorf("decode GitHub user search page: %w", err)
	}
	result.TotalCount = body.TotalCount
	result.IncompleteResults = body.IncompleteResults
	result.Items = body.Items
	return result, nil
}

// GetUserByID verifies an immutable account ID after repeated GraphQL nulls.
// A nil user with no error is a confirmed public-API 404.
func (c *Client) GetUserByID(ctx context.Context, githubID int64) (*RESTUser, model.Rate, error) {
	endpoint := fmt.Sprintf("%s/user/%d", strings.TrimRight(c.RESTBase, "/"), githubID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, model.Rate{}, err
	}
	c.headers(req)
	resp, err := c.do(req)
	if err != nil {
		return nil, model.Rate{}, err
	}
	defer resp.Body.Close()
	rate := rateFromHeaders(resp.Header)
	if resp.StatusCode == http.StatusNotFound {
		return nil, rate, nil
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, rate, rateError(resp)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, rate, &AuthenticationError{Status: resp.StatusCode, Body: string(body)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, rate, fmt.Errorf("GitHub user-by-ID HTTP %d: %s", resp.StatusCode, body)
	}
	var user RESTUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, rate, fmt.Errorf("decode GitHub user by ID: %w", err)
	}
	if user.ID != githubID {
		return nil, rate, fmt.Errorf("GitHub user-by-ID mismatch: requested %d, received %d", githubID, user.ID)
	}
	return &user, rate, nil
}

func (c *Client) PublicKeysURL(login string) string {
	return fmt.Sprintf(
		"%s/users/%s/keys?per_page=100",
		strings.TrimRight(c.RESTBase, "/"), url.PathEscape(login),
	)
}

// ListPublicKeys fetches one page of a user's verified public Git SSH
// authentication keys. Signing-only keys intentionally use a different API.
func (c *Client) ListPublicKeys(ctx context.Context, requestURL string) (PublicKeysPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return PublicKeysPage{}, err
	}
	c.headers(req)
	started := time.Now()
	resp, err := c.do(req)
	if err != nil {
		return PublicKeysPage{}, err
	}
	defer resp.Body.Close()
	page := PublicKeysPage{
		Rate: rateFromHeaders(resp.Header), Elapsed: time.Since(started),
	}
	if resp.StatusCode == http.StatusNotFound {
		page.NotFound = true
		return page, nil
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return PublicKeysPage{}, rateError(resp)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return PublicKeysPage{}, &AuthenticationError{Status: resp.StatusCode, Body: string(body)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return PublicKeysPage{}, fmt.Errorf("GitHub public-keys HTTP %d: %s", resp.StatusCode, body)
	}
	var body []struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return PublicKeysPage{}, fmt.Errorf("decode GitHub public keys: %w", err)
	}
	page.Keys = make([]string, len(body))
	for index := range body {
		page.Keys[index] = body[index].Key
	}
	page.NextURL = nextLink(resp.Header.Get("Link"))
	return page, nil
}

func (c *Client) FetchUsers(ctx context.Context, ids []string) (UsersAndKeys, error) {
	if len(ids) == 0 {
		return UsersAndKeys{}, errors.New("GraphQL node batch is empty")
	}
	if len(ids) > 100 {
		return UsersAndKeys{}, fmt.Errorf("GraphQL node batch exceeds verified GitHub limit: %d > 100", len(ids))
	}
	var envelope struct {
		Data struct {
			Nodes     []*GraphQLUser `json:"nodes"`
			RateLimit graphQLRate    `json:"rateLimit"`
		} `json:"data"`
		Errors []graphQLError `json:"errors"`
	}
	elapsed, err := c.graphql(ctx, usersAndKeysQuery, map[string]any{"ids": ids}, &envelope)
	if err != nil {
		return UsersAndKeys{}, err
	}
	if limited := graphQLRateError(envelope.Errors, envelope.Data.RateLimit); limited != nil {
		return UsersAndKeys{}, limited
	}
	if len(envelope.Errors) != 0 && !onlyNotFound(envelope.Errors) {
		return UsersAndKeys{}, fmt.Errorf("GitHub GraphQL errors: %v", envelope.Errors)
	}
	if len(envelope.Data.Nodes) != len(ids) {
		return UsersAndKeys{}, fmt.Errorf("GitHub returned %d nodes for %d IDs", len(envelope.Data.Nodes), len(ids))
	}
	return UsersAndKeys{
		Nodes:   envelope.Data.Nodes,
		Rate:    envelope.Data.RateLimit.model(),
		Elapsed: elapsed,
	}, nil
}

// FetchUsersByDatabaseIDs uses GitHub's federation entity resolver to resolve
// a dense numeric account-ID range and fetch the first 100 SSH keys in the
// same one-point query. Live probes established 250 as the largest operational
// batch worth accepting; production callers use a lower adaptive target to
// stay clear of GitHub's gateway timeout.
func (c *Client) FetchUsersByDatabaseIDs(
	ctx context.Context, databaseIDs []int64,
) (UsersAndKeys, error) {
	if len(databaseIDs) == 0 {
		return UsersAndKeys{}, errors.New("GraphQL federation batch is empty")
	}
	if len(databaseIDs) > 250 {
		return UsersAndKeys{}, fmt.Errorf(
			"GraphQL federation batch exceeds verified operational limit: %d > 250",
			len(databaseIDs),
		)
	}
	representations := make([]map[string]any, len(databaseIDs))
	for index, databaseID := range databaseIDs {
		if databaseID <= 0 {
			return UsersAndKeys{}, fmt.Errorf(
				"invalid GitHub database ID at index %d: %d", index, databaseID,
			)
		}
		// A string avoids JSON number precision issues if GitHub's allocator ever
		// grows beyond JavaScript's exact integer range.
		representations[index] = map[string]any{
			"__typename": "User",
			"databaseId": strconv.FormatInt(databaseID, 10),
		}
	}
	var envelope struct {
		Data struct {
			Entities  []*GraphQLUser `json:"_entities"`
			RateLimit graphQLRate    `json:"rateLimit"`
		} `json:"data"`
		Errors []graphQLError `json:"errors"`
	}
	elapsed, err := c.graphql(
		ctx, usersByDatabaseIDQuery,
		map[string]any{"representations": representations}, &envelope,
	)
	if err != nil {
		return UsersAndKeys{}, err
	}
	if limited := graphQLRateError(envelope.Errors, envelope.Data.RateLimit); limited != nil {
		return UsersAndKeys{}, limited
	}
	if len(envelope.Data.Entities) != len(databaseIDs) {
		return UsersAndKeys{}, fmt.Errorf(
			"GitHub returned %d federation entities for %d database IDs",
			len(envelope.Data.Entities), len(databaseIDs),
		)
	}
	notFound, err := federationNotFoundPositions(envelope.Errors, len(databaseIDs))
	if err != nil {
		return UsersAndKeys{}, err
	}
	for index, entity := range envelope.Data.Entities {
		if entity != nil && notFound[index] {
			return UsersAndKeys{}, fmt.Errorf(
				"GitHub federation entity %d was returned with NOT_FOUND", index,
			)
		}
	}
	return UsersAndKeys{
		Nodes: envelope.Data.Entities, Rate: envelope.Data.RateLimit.model(), Elapsed: elapsed,
	}, nil
}

func federationNotFoundPositions(errors []graphQLError, size int) (map[int]bool, error) {
	positions := make(map[int]bool, len(errors))
	for _, item := range errors {
		if item.Type != "NOT_FOUND" || len(item.Path) < 2 || item.Path[0] != "_entities" {
			return nil, fmt.Errorf("GitHub GraphQL federation errors: %v", errors)
		}
		value, ok := item.Path[1].(float64)
		index := int(value)
		if !ok || value != float64(index) || index < 0 || index >= size {
			return nil, fmt.Errorf("invalid federation NOT_FOUND path: %v", item.Path)
		}
		positions[index] = true
	}
	return positions, nil
}

// FetchUsersByResources resolves profile URLs through GitHub's documented
// UniformResourceLocatable query. This is deliberately separate from
// FetchUsers: GitHub can resolve a public profile URL even when both node(id:)
// and user(login:) return null. Results retain input order and callers must
// verify the immutable databaseId before accepting a snapshot.
func (c *Client) FetchUsersByResources(
	ctx context.Context, logins []string,
) (UsersAndKeys, error) {
	if len(logins) == 0 {
		return UsersAndKeys{}, errors.New("GraphQL resource batch is empty")
	}
	if len(logins) > 100 {
		return UsersAndKeys{}, fmt.Errorf(
			"GraphQL resource batch exceeds verified GitHub limit: %d > 100", len(logins),
		)
	}
	query, variables := resourceUsersQuery(logins)
	var envelope struct {
		Data   map[string]json.RawMessage `json:"data"`
		Errors []graphQLError             `json:"errors"`
	}
	elapsed, err := c.graphqlNextGlobalID(ctx, query, variables, &envelope)
	if err != nil {
		return UsersAndKeys{}, err
	}
	var rate graphQLRate
	if raw, exists := envelope.Data["rateLimit"]; exists {
		if err := json.Unmarshal(raw, &rate); err != nil {
			return UsersAndKeys{}, fmt.Errorf("decode GitHub GraphQL resource rate: %w", err)
		}
	}
	if limited := graphQLRateError(envelope.Errors, rate); limited != nil {
		return UsersAndKeys{}, limited
	}
	if len(envelope.Errors) != 0 && !onlyNotFound(envelope.Errors) {
		return UsersAndKeys{}, fmt.Errorf("GitHub GraphQL resource errors: %v", envelope.Errors)
	}
	nodes := make([]*GraphQLUser, len(logins))
	for index := range logins {
		alias := fmt.Sprintf("resource%d", index)
		raw, exists := envelope.Data[alias]
		if !exists {
			return UsersAndKeys{}, fmt.Errorf("GitHub GraphQL resource response omitted %s", alias)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			continue
		}
		var user GraphQLUser
		if err := json.Unmarshal(raw, &user); err != nil {
			return UsersAndKeys{}, fmt.Errorf("decode GitHub GraphQL %s: %w", alias, err)
		}
		nodes[index] = &user
	}
	return UsersAndKeys{Nodes: nodes, Rate: rate.model(), Elapsed: elapsed}, nil
}

func resourceUsersQuery(logins []string) (string, map[string]any) {
	var query strings.Builder
	query.WriteString("query ResourceUsers(")
	variables := make(map[string]any, len(logins))
	for index, login := range logins {
		if index > 0 {
			query.WriteString(", ")
		}
		name := fmt.Sprintf("url%d", index)
		fmt.Fprintf(&query, "$%s: URI!", name)
		variables[name] = "https://github.com/" + url.PathEscape(login)
	}
	query.WriteString(") {\n")
	for index := range logins {
		fmt.Fprintf(
			&query, "  resource%d: resource(url: $url%d) {%s\n  }\n",
			index, index, resourceUserFields,
		)
	}
	query.WriteString("  rateLimit { cost limit remaining used resetAt }\n}")
	return query.String(), variables
}

func onlyNotFound(errors []graphQLError) bool {
	if len(errors) == 0 {
		return false
	}
	for _, item := range errors {
		if item.Type != "NOT_FOUND" {
			return false
		}
	}
	return true
}

func (c *Client) MoreKeys(ctx context.Context, nodeID, cursor string) (*GraphQLUser, model.Rate, error) {
	if cursor == "" {
		return nil, model.Rate{}, errors.New("overflow cursor is empty")
	}
	var envelope struct {
		Data struct {
			Node      *GraphQLUser `json:"node"`
			RateLimit graphQLRate  `json:"rateLimit"`
		} `json:"data"`
		Errors []graphQLError `json:"errors"`
	}
	_, err := c.graphql(ctx, moreKeysQuery, map[string]any{"id": nodeID, "after": cursor}, &envelope)
	if err != nil {
		return nil, model.Rate{}, err
	}
	if limited := graphQLRateError(envelope.Errors, envelope.Data.RateLimit); limited != nil {
		return nil, model.Rate{}, limited
	}
	if len(envelope.Errors) != 0 {
		return nil, model.Rate{}, fmt.Errorf("GitHub GraphQL errors: %v", envelope.Errors)
	}
	return envelope.Data.Node, envelope.Data.RateLimit.model(), nil
}

func (c *Client) graphql(ctx context.Context, query string, variables map[string]any, target any) (time.Duration, error) {
	return c.graphqlRequest(ctx, query, variables, target, false)
}

func (c *Client) graphqlNextGlobalID(
	ctx context.Context, query string, variables map[string]any, target any,
) (time.Duration, error) {
	return c.graphqlRequest(ctx, query, variables, target, true)
}

func (c *Client) graphqlRequest(
	ctx context.Context,
	query string,
	variables map[string]any,
	target any,
	nextGlobalID bool,
) (time.Duration, error) {
	payload, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.GraphQLURL, bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	c.headers(req)
	req.Header.Set("Content-Type", "application/json")
	if nextGlobalID {
		req.Header.Set("X-Github-Next-Global-ID", "1")
	}
	started := time.Now()
	resp, err := c.do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	elapsed := time.Since(started)
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return elapsed, rateError(resp)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return elapsed, &AuthenticationError{Status: resp.StatusCode, Body: string(body)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return elapsed, &HTTPError{
			Operation: "GraphQL", Status: resp.StatusCode, Body: string(body),
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return elapsed, fmt.Errorf("decode GitHub GraphQL response: %w", err)
	}
	return elapsed, nil
}

func (c *Client) headers(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-GitHub-Api-Version", c.APIVersion)
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	start := c.nextCredential(req)
	count := c.CredentialCount()
	if count == 0 {
		return nil, errors.New("GitHub credential pool is empty")
	}
	var lastUnauthorized *http.Response
	for offset := 0; offset < count; offset++ {
		index := (start + offset) % count
		token, active := c.credential(index)
		if !active {
			continue
		}
		attempt, err := replayRequest(req)
		if err != nil {
			return nil, err
		}
		attempt.Header.Set("Authorization", "Bearer "+token)
		response, err := c.HTTP.Do(attempt)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusUnauthorized {
			if lastUnauthorized != nil {
				lastUnauthorized.Body.Close()
			}
			return response, nil
		}
		if lastUnauthorized != nil {
			lastUnauthorized.Body.Close()
		}
		lastUnauthorized = response
		c.disableCredential(index)
	}
	if lastUnauthorized != nil {
		return lastUnauthorized, nil
	}
	return nil, errors.New("all GitHub credentials are disabled")
}

func (c *Client) nextCredential(req *http.Request) int {
	var next *atomic.Uint64
	switch {
	case strings.HasSuffix(req.URL.Path, "/graphql"):
		next = &c.graphqlNext
	case strings.Contains(req.URL.Path, "/search/"):
		next = &c.searchNext
	default:
		next = &c.restNext
	}
	return int(next.Add(1) - 1)
}

func (c *Client) credential(index int) (string, bool) {
	c.credentialsMu.RLock()
	defer c.credentialsMu.RUnlock()
	if index < 0 || index >= len(c.credentials) || c.credentials[index].disabled {
		return "", false
	}
	return c.credentials[index].token, true
}

func (c *Client) disableCredential(index int) {
	c.credentialsMu.Lock()
	defer c.credentialsMu.Unlock()
	if index >= 0 && index < len(c.credentials) {
		c.credentials[index].disabled = true
	}
}

func replayRequest(req *http.Request) (*http.Request, error) {
	attempt := req.Clone(req.Context())
	if req.Body == nil {
		return attempt, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("GitHub request body cannot be replayed for credential failover")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("replay GitHub request body: %w", err)
	}
	attempt.Body = body
	return attempt, nil
}

type graphQLError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Path    []any  `json:"path"`
}

func (e graphQLError) String() string {
	if e.Type == "" {
		return e.Message
	}
	return e.Type + ": " + e.Message
}

type graphQLRate struct {
	Cost      int       `json:"cost"`
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	Used      int       `json:"used"`
	ResetAt   time.Time `json:"resetAt"`
}

func (r graphQLRate) model() model.Rate {
	return model.Rate{
		Cost: r.Cost, Limit: r.Limit, Remaining: r.Remaining,
		Used: r.Used, ResetAt: r.ResetAt, Resource: "graphql",
	}
}

func graphQLRateError(errors []graphQLError, rate graphQLRate) error {
	limited := rate.Limit > 0 && rate.Remaining == 0
	for _, item := range errors {
		if item.Type == "RATE_LIMITED" ||
			strings.Contains(strings.ToLower(item.Message), "rate limit") {
			limited = true
			break
		}
	}
	if !limited {
		return nil
	}
	wait := time.Minute
	if !rate.ResetAt.IsZero() {
		if candidate := time.Until(rate.ResetAt) + time.Second; candidate > 0 {
			wait = candidate
		}
	}
	return &RateLimitError{
		Status: http.StatusOK,
		Wait:   wait,
		Body:   "GraphQL primary or secondary rate limit reached",
	}
}

func rateFromHeaders(header http.Header) model.Rate {
	return model.Rate{
		Limit:     headerInt(header, "X-RateLimit-Limit"),
		Remaining: headerInt(header, "X-RateLimit-Remaining"),
		Used:      headerInt(header, "X-RateLimit-Used"),
		ResetAt:   time.Unix(int64(headerInt(header, "X-RateLimit-Reset")), 0).UTC(),
		Resource:  header.Get("X-RateLimit-Resource"),
	}
}

func headerInt(header http.Header, name string) int {
	value, _ := strconv.Atoi(header.Get(name))
	return value
}

func rateError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	bodyText := string(body)
	wait := time.Minute
	if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
		wait = time.Duration(seconds) * time.Second
	} else if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		if candidate := time.Until(time.Unix(reset, 0)) + time.Second; candidate > 0 {
			wait = candidate
		}
	}
	return &RateLimitError{
		Status: resp.StatusCode, Wait: wait, Body: bodyText,
		Secondary: strings.Contains(strings.ToLower(bodyText), "secondary rate limit"),
	}
}

func nextLink(value string) string {
	for _, part := range strings.Split(value, ",") {
		sections := strings.Split(strings.TrimSpace(part), ";")
		if len(sections) < 2 || !strings.Contains(sections[1], `rel="next"`) {
			continue
		}
		raw := strings.Trim(strings.TrimSpace(sections[0]), "<>")
		if parsed, err := url.Parse(raw); err == nil && parsed.Scheme == "https" {
			return parsed.String()
		}
	}
	return ""
}
