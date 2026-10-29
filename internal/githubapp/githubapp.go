// Package githubapp authenticates to GitHub as an installation of a GitHub
// App: it signs a short-lived JWT with the App's private key, trades it for
// an installation token and mints the next token before the current one
// expires (ADR 0013, after release-lag's ADR 0003).
package githubapp

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
	"sync"
	"time"
)

const (
	// refreshMargin is how long before expiry a token is replaced, so a
	// request never leaves with a token that expires on the way.
	refreshMargin = 5 * time.Minute
	// jwtLifetime stays under the ten minutes GitHub allows.
	jwtLifetime = 9 * time.Minute
	// clockSkew backdates the JWT, as GitHub recommends, so a clock slightly
	// ahead of GitHub's does not make it "issued in the future".
	clockSkew = time.Minute
)

// Source hands out the token to put on a request.
type Source interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a token that never changes, such as the personal access
// token in $GITHUB_TOKEN when no App is configured.
type StaticToken string

// Token returns the token itself.
func (s StaticToken) Token(context.Context) (string, error) { return string(s), nil }

// TokenSource mints installation tokens for one installation of an App.
type TokenSource struct {
	apiURL         string
	appID          int64
	installationID int64
	key            *rsa.PrivateKey
	client         *http.Client
	now            func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewTokenSource parses the App's PEM private key (PKCS#1, as GitHub hands it
// out, or PKCS#8).
func NewTokenSource(apiURL string, appID, installationID int64, privateKeyPEM []byte) (*TokenSource, error) {
	key, err := parseKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &TokenSource{
		apiURL:         apiURL,
		appID:          appID,
		installationID: installationID,
		key:            key,
		client:         &http.Client{Timeout: 30 * time.Second},
		now:            time.Now,
	}, nil
}

func parseKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("the GitHub App private key is not PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing the GitHub App private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the GitHub App private key is %T, not RSA", parsed)
	}
	return key, nil
}

// Token returns the current installation token, minting a new one when there
// is none yet or it is about to expire.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Add(refreshMargin).Before(s.expires) {
		return s.token, nil
	}
	token, expires, err := s.mint(ctx)
	if err != nil {
		return "", err
	}
	s.token, s.expires = token, expires
	return token, nil
}

func (s *TokenSource) mint(ctx context.Context) (string, time.Time, error) {
	jwt, err := s.jwt()
	if err != nil {
		return "", time.Time{}, err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", s.apiURL, s.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("minting an installation token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("minting an installation token: %s: %s", resp.Status, body)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("minting an installation token: %w", err)
	}
	if out.Token == "" {
		return "", time.Time{}, errors.New("minting an installation token: the response has no token")
	}
	return out.Token, out.ExpiresAt, nil
}

func (s *TokenSource) jwt() (string, error) {
	now := s.now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-clockSkew).Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
		"iss": strconv.FormatInt(s.appID, 10),
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("signing the App JWT: %w", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Transport puts the token from Source on every request.
type Transport struct {
	Source Source
	// Base is the transport the request goes through; nil means
	// http.DefaultTransport.
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.Source.Token(req.Context())
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+token)
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
