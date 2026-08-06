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
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	installationTokenRefreshMargin = 5 * time.Minute
	installationTokenExpirySafety  = 30 * time.Second
)

// CredentialSource supplies a bearer token for one independently rate-limited
// GitHub credential lane. Implementations must be safe for concurrent use.
type CredentialSource interface {
	Token(context.Context) (string, error)
	Invalidate()
	DisableOnUnauthorized() bool
}

type staticCredentialSource struct{ token string }

func (s *staticCredentialSource) Token(context.Context) (string, error) { return s.token, nil }
func (s *staticCredentialSource) Invalidate()                           {}
func (s *staticCredentialSource) DisableOnUnauthorized() bool           { return true }

// InstallationTokenSource creates and refreshes one-hour GitHub App
// installation tokens. Refreshes are serialized so concurrent workers never
// stampede the access-token endpoint.
type InstallationTokenSource struct {
	appID          int64
	installationID int64
	privateKey     *rsa.PrivateKey
	apiBase        string
	userAgent      string
	apiVersion     string
	httpClient     *http.Client
	now            func() time.Time

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

func NewInstallationTokenSource(
	appID, installationID int64,
	privateKeyPEM []byte,
	userAgent string,
) (*InstallationTokenSource, error) {
	if appID <= 0 {
		return nil, errors.New("GitHub App ID must be positive")
	}
	if installationID <= 0 {
		return nil, errors.New("GitHub App installation ID must be positive")
	}
	privateKey, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse GitHub App private key: %w", err)
	}
	return &InstallationTokenSource{
		appID: appID, installationID: installationID, privateKey: privateKey,
		apiBase: "https://api.github.com", userAgent: userAgent,
		apiVersion: "2026-03-10", now: time.Now,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *InstallationTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	if s.token != "" && now.Add(installationTokenRefreshMargin).Before(s.expiresAt) {
		return s.token, nil
	}
	token, expiresAt, err := s.refresh(ctx, now)
	if err != nil {
		// A transient refresh failure should not unnecessarily take a healthy
		// lane offline while its previous token is still safely usable.
		if s.token != "" && now.Add(installationTokenExpirySafety).Before(s.expiresAt) {
			return s.token, nil
		}
		return "", err
	}
	s.token, s.expiresAt = token, expiresAt
	return token, nil
}

func (s *InstallationTokenSource) Invalidate() {
	s.mu.Lock()
	s.token, s.expiresAt = "", time.Time{}
	s.mu.Unlock()
}

// Installation credentials are refreshable. A single 401 invalidates the
// cached token rather than permanently disabling the lane.
func (s *InstallationTokenSource) DisableOnUnauthorized() bool { return false }

func (s *InstallationTokenSource) refresh(
	ctx context.Context, now time.Time,
) (string, time.Time, error) {
	jwt, err := s.signJWT(now)
	if err != nil {
		return "", time.Time{}, err
	}
	endpoint := fmt.Sprintf(
		"%s/app/installations/%d/access_tokens",
		strings.TrimRight(s.apiBase, "/"), s.installationID,
	)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+jwt)
	request.Header.Set("User-Agent", s.userAgent)
	request.Header.Set("X-GitHub-Api-Version", s.apiVersion)
	response, err := s.httpClient.Do(request)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request GitHub App installation token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		return "", time.Time{}, fmt.Errorf(
			"GitHub App installation token HTTP %d: %s",
			response.StatusCode, strings.TrimSpace(string(body)),
		)
	}
	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("decode GitHub App installation token: %w", err)
	}
	if result.Token == "" || result.ExpiresAt.IsZero() || !result.ExpiresAt.After(now) {
		return "", time.Time{}, errors.New("GitHub returned an invalid installation token")
	}
	return result.Token, result.ExpiresAt.UTC(), nil
}

func (s *InstallationTokenSource) signJWT(now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]int64{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": s.appID,
	})
	if err != nil {
		return "", err
	}
	encode := base64.RawURLEncoding.EncodeToString
	unsigned := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign GitHub App JWT: %w", err)
	}
	return unsigned + "." + encode(signature), nil
}

func parseRSAPrivateKey(value []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(value)
	if block == nil {
		return nil, errors.New("PEM block not found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return validateRSAPrivateKey(key)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, expected RSA", parsed)
	}
	return validateRSAPrivateKey(key)
}

func validateRSAPrivateKey(key *rsa.PrivateKey) (*rsa.PrivateKey, error) {
	if key.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA private key is only %s bits", strconv.Itoa(key.N.BitLen()))
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return key, nil
}
