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
      publicKeys(first: 100, after: $after) {
        totalCount
        pageInfo { hasNextPage endCursor }
        nodes { key fingerprint }
      }
    }
  }
  rateLimit { cost limit remaining used resetAt }
}`

type Client struct {
	Token      string
	RESTBase   string
	GraphQLURL string
	UserAgent  string
	APIVersion string
	HTTP       *http.Client
}

type RESTUser struct {
	Login  string `json:"login"`
	ID     int64  `json:"id"`
	NodeID string `json:"node_id"`
	Type   string `json:"type"`
}

type UsersPage struct {
	Objects     []RESTUser
	NextURL     string
	ETag        string
	NotModified bool
	Rate        model.Rate
	Elapsed     time.Duration
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

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("GitHub authentication failed (HTTP %d): %s", e.Status, e.Body)
}

func New(token, userAgent string) *Client {
	return &Client{
		Token:      token,
		RESTBase:   "https://api.github.com",
		GraphQLURL: "https://api.github.com/graphql",
		UserAgent:  userAgent,
		APIVersion: "2026-03-10",
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
	resp, err := c.HTTP.Do(req)
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
	started := time.Now()
	resp, err := c.HTTP.Do(req)
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
		return elapsed, fmt.Errorf("GitHub GraphQL HTTP %d: %s", resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return elapsed, fmt.Errorf("decode GitHub GraphQL response: %w", err)
	}
	return elapsed, nil
}

func (c *Client) headers(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-GitHub-Api-Version", c.APIVersion)
}

type graphQLError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
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
