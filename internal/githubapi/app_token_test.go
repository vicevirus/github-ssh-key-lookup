package githubapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInstallationTokenSourceCachesAndRefreshes(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemValue := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	var requests atomic.Int32
	var failRefresh atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/app/installations/42/access_tokens" {
			t.Fatalf("unexpected token request: %s %s", request.Method, request.URL.Path)
		}
		verifyAppJWT(t, strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "), privateKey, 7)
		sequence := requests.Add(1)
		if failRefresh.Load() {
			response.WriteHeader(http.StatusServiceUnavailable)
			_, _ = response.Write([]byte(`{"message":"temporary"}`))
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(response,
			`{"token":"installation-%d","expires_at":%q}`,
			sequence, now.Add(time.Hour).Format(time.RFC3339),
		)
	}))
	defer server.Close()

	source, err := NewInstallationTokenSource(7, 42, pemValue, "github-cli")
	if err != nil {
		t.Fatal(err)
	}
	source.apiBase, source.httpClient, source.now = server.URL, server.Client(), func() time.Time { return now }
	first, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != "installation-1" || second != first || requests.Load() != 1 {
		t.Fatalf("installation token was not cached: first=%q second=%q requests=%d", first, second, requests.Load())
	}
	now = now.Add(56 * time.Minute)
	failRefresh.Store(true)
	fallback, err := source.Token(context.Background())
	if err != nil || fallback != first || requests.Load() != 2 {
		t.Fatalf("usable cached token was not retained after refresh failure: token=%q requests=%d err=%v",
			fallback, requests.Load(), err)
	}
	failRefresh.Store(false)
	source.Invalidate()
	refreshed, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if refreshed != "installation-3" || requests.Load() != 3 {
		t.Fatalf("installation token was not refreshed: token=%q requests=%d", refreshed, requests.Load())
	}
}

func TestRefreshableCredentialRetriesUnauthorized(t *testing.T) {
	source := &rotatingCredentialSource{token: "expired"}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("Authorization") == "Bearer expired" {
			response.WriteHeader(http.StatusUnauthorized)
			_, _ = response.Write([]byte(`{"message":"expired"}`))
			return
		}
		if request.Header.Get("Authorization") != "Bearer refreshed" {
			t.Fatalf("unexpected authorization header")
		}
		_, _ = response.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := NewWithTokens(nil, "github-cli")
	client.RESTBase, client.HTTP = server.URL, server.Client()
	if err := client.AddCredentialSource(source); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListUsers(context.Background(), client.UsersURL(0), ""); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || source.invalidations != 1 || !client.CredentialActive(0) {
		t.Fatalf("refresh retry state: requests=%d invalidations=%d active=%t",
			requests.Load(), source.invalidations, client.CredentialActive(0))
	}
}

func TestLiveInstallationCredential(t *testing.T) {
	if os.Getenv("GITHUB_APP_LIVE_TEST") != "1" {
		t.Skip("set GITHUB_APP_LIVE_TEST=1 for the read-only live probe")
	}
	appID, err := strconv.ParseInt(os.Getenv("GITHUB_APP_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	installationID, err := strconv.ParseInt(os.Getenv("GITHUB_APP_INSTALLATION_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := os.ReadFile(os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewInstallationTokenSource(appID, installationID, privateKey, "github-cli")
	if err != nil {
		t.Fatal(err)
	}
	client := NewWithTokens(nil, "github-cli")
	if err := client.AddCredentialSource(source); err != nil {
		t.Fatal(err)
	}
	page, err := client.ListUsers(context.Background(), client.UsersURL(0), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Objects) != 100 || page.Rate.Limit != 5_000 {
		t.Fatalf("unexpected App REST result: users=%d rate=%#v", len(page.Objects), page.Rate)
	}
	result, err := client.FetchUsersByDatabaseIDs(context.Background(), []int64{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 || result.Nodes[0] == nil || result.Nodes[0].Login != "mojombo" ||
		result.Nodes[0].PublicKeys.TotalCount < 1 || result.Rate.Limit != 5_000 {
		t.Fatalf("unexpected App GraphQL result: %#v", result)
	}
}

type rotatingCredentialSource struct {
	mu            sync.Mutex
	token         string
	invalidations int
}

func (s *rotatingCredentialSource) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token, nil
}

func (s *rotatingCredentialSource) Invalidate() {
	s.mu.Lock()
	s.token = "refreshed"
	s.invalidations++
	s.mu.Unlock()
}

func (s *rotatingCredentialSource) DisableOnUnauthorized() bool { return false }

func verifyAppJWT(
	t *testing.T, value string, privateKey *rsa.PrivateKey, expectedIssuer int64,
) {
	t.Helper()
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT shape")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("invalid JWT signature: %v", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Issuer int64 `json:"iss"`
		Issued int64 `json:"iat"`
		Expiry int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != expectedIssuer || claims.Expiry <= claims.Issued || claims.Expiry-claims.Issued > 10*60 {
		t.Fatalf("invalid JWT claims: %#v", claims)
	}
}
