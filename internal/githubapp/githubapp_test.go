package githubapp

import (
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
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeGitHub issues installation tokens, each valid for an hour from the
// clock, after checking the App JWT the request carries.
type fakeGitHub struct {
	t       *testing.T
	pub     *rsa.PublicKey
	clock   *fakeClock
	mu      sync.Mutex
	minted  int
	status  int
	gotPath string
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotPath = r.Method + " " + r.URL.Path
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
		return
	}
	jwt, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		http.Error(w, "no bearer", http.StatusUnauthorized)
		return
	}
	claims, err := verify(jwt, f.pub)
	if err != nil {
		f.t.Errorf("JWT: %v", err)
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if claims.Iss != "42" {
		f.t.Errorf("iss = %q, want 42", claims.Iss)
	}
	now := f.clock.Now().Unix()
	if claims.Iat > now || claims.Exp <= now || claims.Exp-claims.Iat > 600 {
		f.t.Errorf("iat=%d exp=%d now=%d", claims.Iat, claims.Exp, now)
	}
	f.minted++
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token":      fmt.Sprintf("ghs_token%d", f.minted),
		"expires_at": f.clock.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
}

type claims struct {
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Iss string `json:"iss"`
}

func verify(jwt string, pub *rsa.PublicKey) (*claims, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%d parts", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(header), `"RS256"`) {
		return nil, fmt.Errorf("header %s", header)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return nil, err
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c claims
	return &c, json.Unmarshal(body, &c)
}

func newKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// GitHub hands out PKCS#1 keys.
	return key, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func setup(t *testing.T) (*TokenSource, *fakeGitHub, *fakeClock) {
	t.Helper()
	key, pemBytes := newKey(t)
	clock := &fakeClock{now: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)}
	fake := &fakeGitHub{t: t, pub: &key.PublicKey, clock: clock}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	ts, err := NewTokenSource(srv.URL, 42, 7, pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	ts.now = clock.Now
	return ts, fake, clock
}

func TestTokenIsMintedForTheInstallation(t *testing.T) {
	ts, fake, _ := setup(t)
	tok, err := ts.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "ghs_token1" {
		t.Errorf("token = %q", tok)
	}
	if fake.gotPath != "POST /app/installations/7/access_tokens" {
		t.Errorf("request = %q", fake.gotPath)
	}
}

func TestTokenIsReusedUntilItNearlyExpires(t *testing.T) {
	ts, fake, clock := setup(t)
	for range 3 {
		if _, err := ts.Token(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if fake.minted != 1 {
		t.Fatalf("minted %d tokens, want 1", fake.minted)
	}

	clock.Advance(50 * time.Minute)
	tok, err := ts.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if fake.minted != 1 || tok != "ghs_token1" {
		t.Fatalf("at 50m: minted %d, token %q; want the first token still", fake.minted, tok)
	}

	// Within the margin before the hour is up, a new one is minted.
	clock.Advance(6 * time.Minute)
	tok, err = ts.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if fake.minted != 2 || tok != "ghs_token2" {
		t.Fatalf("at 56m: minted %d, token %q; want a second token", fake.minted, tok)
	}
}

func TestTokenError(t *testing.T) {
	ts, fake, _ := setup(t)
	fake.status = http.StatusUnauthorized
	if _, err := ts.Token(t.Context()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want one naming the 401", err)
	}
}

func TestTransportAddsTheToken(t *testing.T) {
	ts, _, _ := setup(t)
	var got string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer api.Close()
	client := &http.Client{Transport: &Transport{Source: ts}}
	resp, err := client.Get(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got != "Bearer ghs_token1" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestStaticTokenTransport(t *testing.T) {
	var got string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
	}))
	defer api.Close()
	client := &http.Client{Transport: &Transport{Source: StaticToken("abc")}}
	resp, err := client.Get(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got != "Bearer abc" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestPKCS8KeyIsAccepted(t *testing.T) {
	key, _ := newKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := NewTokenSource("http://example.invalid", 1, 2, pemBytes); err != nil {
		t.Fatal(err)
	}
}

func TestBadKeyIsRejected(t *testing.T) {
	if _, err := NewTokenSource("http://example.invalid", 1, 2, []byte("not a key")); err == nil {
		t.Fatal("NewTokenSource succeeded")
	}
}
