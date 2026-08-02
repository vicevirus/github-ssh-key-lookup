package githubapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestListUsersAndRateHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-RateLimit-Limit", "5000")
		response.Header().Set("X-RateLimit-Remaining", "4999")
		response.Header().Set("X-RateLimit-Resource", "core")
		response.Header().Set("Link", `<https://api.github.com/users?since=2&per_page=100>; rel="next"`)
		_, _ = response.Write([]byte(`[{"login":"alice","id":1,"node_id":"U_1","type":"User"},{"login":"org","id":2,"node_id":"O_2","type":"Organization"}]`))
	}))
	defer server.Close()
	client := New("token", "test")
	client.RESTBase = server.URL
	client.HTTP = server.Client()
	page, err := client.ListUsers(context.Background(), client.UsersURL(0), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Objects) != 2 || page.Objects[0].Login != "alice" {
		t.Fatalf("unexpected page: %#v", page)
	}
	if page.Rate.Limit != 5000 || page.Rate.Resource != "core" {
		t.Fatalf("unexpected rate: %#v", page.Rate)
	}
	if page.NextURL != "https://api.github.com/users?since=2&per_page=100" {
		t.Fatalf("unexpected next URL %q", page.NextURL)
	}
}

func TestSearchUserCountPreservesIncompleteFlagAndQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/search/users" ||
			request.URL.Query().Get("q") != "type:user created:2026-08-01" ||
			request.URL.Query().Get("per_page") != "1" {
			t.Fatalf("unexpected search request: %s", request.URL.String())
		}
		response.Header().Set("X-RateLimit-Limit", "30")
		response.Header().Set("X-RateLimit-Remaining", "29")
		response.Header().Set("X-RateLimit-Resource", "search")
		_, _ = response.Write([]byte(`{"total_count":12345,"incomplete_results":true,"items":[]}`))
	}))
	defer server.Close()
	client := New("token", "test")
	client.RESTBase = server.URL
	client.HTTP = server.Client()
	result, err := client.SearchUserCount(context.Background(), "type:user created:2026-08-01")
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalCount != 12345 || !result.IncompleteResults ||
		result.Rate.Resource != "search" || result.Rate.Remaining != 29 {
		t.Fatalf("unexpected search count: %#v", result)
	}
}

func TestFetchUsersEnforcesVerifiedHundredIDLimitAndCost(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		var body struct {
			Variables struct {
				IDs []string `json:"ids"`
			} `json:"variables"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		nodes := make([]string, len(body.Variables.IDs))
		for index := range nodes {
			nodes[index] = fmt.Sprintf(`{"__typename":"User","id":"%s","databaseId":%d,"login":"u%d","publicKeys":{"totalCount":0,"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]}}`, body.Variables.IDs[index], index+1, index+1)
		}
		_, _ = fmt.Fprintf(response, `{"data":{"nodes":[%s],"rateLimit":{"cost":1,"limit":5000,"remaining":4999,"used":1,"resetAt":"2026-07-30T08:00:00Z"}}}`, strings.Join(nodes, ","))
	}))
	defer server.Close()
	client := New("token", "test")
	client.GraphQLURL = server.URL
	client.HTTP = server.Client()
	ids := make([]string, 100)
	for index := range ids {
		ids[index] = fmt.Sprintf("U_%d", index+1)
	}
	result, err := client.FetchUsers(context.Background(), ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 100 || result.Rate.Cost != 1 {
		t.Fatalf("unexpected result: nodes=%d rate=%#v", len(result.Nodes), result.Rate)
	}
	if _, err := client.FetchUsers(context.Background(), append(ids, "U_101")); err == nil {
		t.Fatal("accepted more than 100 IDs")
	}
	if calls.Load() != 1 {
		t.Fatalf("invalid batch reached server; calls=%d", calls.Load())
	}
}

func TestFetchUsersAcceptsNotFoundAsInaccessibleNode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte(`{"data":{"nodes":[null],"rateLimit":{"cost":1,"limit":5000,"remaining":4999,"used":1,"resetAt":"2026-07-30T08:00:00Z"}},"errors":[{"type":"NOT_FOUND","message":"gone"}]}`))
	}))
	defer server.Close()
	client := New("token", "test")
	client.GraphQLURL = server.URL
	client.HTTP = server.Client()
	result, err := client.FetchUsers(context.Background(), []string{"U_1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 || result.Nodes[0] != nil {
		t.Fatalf("unexpected nodes: %#v", result.Nodes)
	}
}

func TestFetchUsersRejectsOtherPartialGraphQLErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte(`{"data":{"nodes":[null]},"errors":[{"type":"SOMETHING","message":"partial failure"}]}`))
	}))
	defer server.Close()
	client := New("token", "test")
	client.GraphQLURL = server.URL
	client.HTTP = server.Client()
	if _, err := client.FetchUsers(context.Background(), []string{"U_1"}); err == nil {
		t.Fatal("accepted non-NOT_FOUND partial GraphQL errors")
	}
}

func TestFetchUsersRecognizesGraphQLRateLimitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte(`{"data":{"nodes":null,"rateLimit":{"cost":1,"limit":5000,"remaining":0,"used":5000,"resetAt":"2099-07-30T08:00:00Z"}},"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`))
	}))
	defer server.Close()
	client := New("token", "test")
	client.GraphQLURL = server.URL
	client.HTTP = server.Client()
	_, err := client.FetchUsers(context.Background(), []string{"U_1"})
	var limited *RateLimitError
	if !errors.As(err, &limited) || limited.Wait <= 0 {
		t.Fatalf("rate limit was not classified with a wait: %v", err)
	}
}

func TestFetchUsersRecognizesAuthenticationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()
	client := New("bad-token", "test")
	client.GraphQLURL = server.URL
	client.HTTP = server.Client()
	_, err := client.FetchUsers(context.Background(), []string{"U_1"})
	var authentication *AuthenticationError
	if !errors.As(err, &authentication) {
		t.Fatalf("authentication failure was not classified: %v", err)
	}
}

func TestCredentialPoolBalancesEachAPIResource(t *testing.T) {
	var restHeaders []string
	var searchHeaders []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		if request.URL.Path == "/search/users" {
			searchHeaders = append(searchHeaders, authorization)
			_, _ = response.Write([]byte(`{"total_count":0,"incomplete_results":false,"items":[]}`))
			return
		}
		restHeaders = append(restHeaders, authorization)
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()
	client := NewWithTokens([]string{"token-a", "token-b"}, "test")
	client.RESTBase = server.URL
	client.HTTP = server.Client()
	for range 2 {
		if _, err := client.ListUsers(context.Background(), client.UsersURL(0), ""); err != nil {
			t.Fatal(err)
		}
		if _, err := client.SearchUserCount(context.Background(), "type:user"); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"Bearer token-a", "Bearer token-b"}
	if fmt.Sprint(restHeaders) != fmt.Sprint(want) {
		t.Fatalf("REST credentials were not balanced: got %v want %v", restHeaders, want)
	}
	if fmt.Sprint(searchHeaders) != fmt.Sprint(want) {
		t.Fatalf("Search credentials were not balanced independently: got %v want %v", searchHeaders, want)
	}
}

func TestCredentialPoolReplaysGraphQLAndDisablesUnauthorizedToken(t *testing.T) {
	var badCalls atomic.Int32
	var goodCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Variables struct {
				IDs []string `json:"ids"`
			} `json:"variables"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Variables.IDs) != 1 || body.Variables.IDs[0] != "U_1" {
			t.Fatalf("request body was not replayed: %#v", body)
		}
		if request.Header.Get("Authorization") == "Bearer bad-token" {
			badCalls.Add(1)
			response.WriteHeader(http.StatusUnauthorized)
			_, _ = response.Write([]byte(`{"message":"Bad credentials"}`))
			return
		}
		goodCalls.Add(1)
		_, _ = response.Write([]byte(`{"data":{"nodes":[{"__typename":"User","id":"U_1","databaseId":1,"login":"alice","publicKeys":{"totalCount":0,"pageInfo":{"hasNextPage":false,"endCursor":null},"nodes":[]}}],"rateLimit":{"cost":1,"limit":5000,"remaining":4999,"used":1,"resetAt":"2026-08-02T09:00:00Z"}}}`))
	}))
	defer server.Close()
	client := NewWithTokens([]string{"bad-token", "good-token"}, "test")
	client.GraphQLURL = server.URL + "/graphql"
	client.HTTP = server.Client()
	for range 2 {
		result, err := client.FetchUsers(context.Background(), []string{"U_1"})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Nodes) != 1 || result.Nodes[0].Login != "alice" {
			t.Fatalf("unexpected failover result: %#v", result)
		}
	}
	if badCalls.Load() != 1 || goodCalls.Load() != 2 {
		t.Fatalf("unexpected credential calls: bad=%d good=%d", badCalls.Load(), goodCalls.Load())
	}
	if client.ActiveCredentialCount() != 1 {
		t.Fatalf("unauthorized credential remained active: %d", client.ActiveCredentialCount())
	}
}

func TestCredentialPoolIgnoresEmptyAndDuplicateTokens(t *testing.T) {
	client := NewWithTokens([]string{" token ", "", "token"}, "test")
	if client.CredentialCount() != 1 || client.Token != "token" {
		t.Fatalf("credentials were not normalized: count=%d primary=%q", client.CredentialCount(), client.Token)
	}
}

func TestFetchUsersClassifiesSecondaryRateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusForbidden)
		_, _ = response.Write([]byte(`{"message":"You have exceeded a secondary rate limit."}`))
	}))
	defer server.Close()
	client := New("token", "test")
	client.GraphQLURL = server.URL
	client.HTTP = server.Client()
	_, err := client.FetchUsers(context.Background(), []string{"U_1"})
	var limited *RateLimitError
	if !errors.As(err, &limited) || !limited.Secondary {
		t.Fatalf("secondary limit was not classified: %v", err)
	}
}

func TestListPublicKeysPaginatesAndPreservesRawKeys(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("per_page") != "100" {
			t.Fatalf("missing maximum page size: %s", request.URL.String())
		}
		response.Header().Set("X-RateLimit-Resource", "core")
		response.Header().Set("X-RateLimit-Remaining", "4999")
		if request.URL.Query().Get("page") == "2" {
			_, _ = response.Write([]byte(`[{"key":"ssh-ed25519 SECOND"}]`))
			return
		}
		response.Header().Set("Link", fmt.Sprintf(`<%s/users/alice/keys?per_page=100&page=2>; rel="next"`, server.URL))
		_, _ = response.Write([]byte(`[{"key":"ssh-ed25519 FIRST"}]`))
	}))
	defer server.Close()
	client := New("token", "test")
	client.RESTBase = server.URL
	client.HTTP = server.Client()
	page, err := client.ListPublicKeys(context.Background(), client.PublicKeysURL("alice"))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Keys) != 1 || page.Keys[0] != "ssh-ed25519 FIRST" || page.NextURL == "" {
		t.Fatalf("unexpected first page: %#v", page)
	}
	page, err = client.ListPublicKeys(context.Background(), page.NextURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Keys) != 1 || page.Keys[0] != "ssh-ed25519 SECOND" || page.NextURL != "" {
		t.Fatalf("unexpected second page: %#v", page)
	}
}

func TestListPublicKeysReturnsExplicitNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := New("token", "test")
	client.RESTBase = server.URL
	client.HTTP = server.Client()
	page, err := client.ListPublicKeys(context.Background(), client.PublicKeysURL("gone"))
	if err != nil || !page.NotFound {
		t.Fatalf("404 was not preserved: page=%#v err=%v", page, err)
	}
}
