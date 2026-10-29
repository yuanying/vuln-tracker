package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/vuln-tracker/internal/config"
	"github.com/yuanying/vuln-tracker/internal/githubapp"
	"github.com/yuanying/vuln-tracker/internal/responder"
)

// Requests to vuln-responder are off unless --responder-url is given
// (ADR 0009): no requester, so nothing is sent and no token is read.
func TestNewResponder(t *testing.T) {
	getenv := func(string) string { return "" }
	cfg, err := config.Parse([]string{"--namespace=x"}, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if r := newResponder(cfg, logr.Discard()); r != nil {
		t.Errorf("a requester without --responder-url: %+v", r)
	}

	cfg, err = config.Parse([]string{"--namespace=x", "--responder-url=http://vuln-responder.fraction-agents:8080/", "--responder-task-timeout=2h", "--dashboard-url=https://grafana.example/d/vuln"}, getenv)
	if err != nil {
		t.Fatal(err)
	}
	r := newResponder(cfg, logr.Discard())
	if r == nil {
		t.Fatal("no requester with --responder-url")
	}
	c, ok := r.Client.(*responder.Client)
	if !ok || c.URL != "http://vuln-responder.fraction-agents:8080/" || c.TokenFile != "/var/run/secrets/a2a/token" {
		t.Errorf("client = %+v", r.Client)
	}
	if r.Mode != "vex-only" || r.TaskTimeout != 2*time.Hour || r.DashboardURL != "https://grafana.example/d/vuln" {
		t.Errorf("requester = %+v", r)
	}
}

func writeKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "private-key.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// App ID 0 reads with $GITHUB_TOKEN as before; an App ID reads with the
// App's installation tokens, and a key that cannot be read stops the start
// (ADR 0013).
func TestNewGitHub(t *testing.T) {
	getenv := func(k string) string {
		if k == "GITHUB_TOKEN" {
			return "ghp_x"
		}
		return ""
	}
	cfg, err := config.Parse([]string{"--namespace=x"}, getenv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newGitHub(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "ghp_x" {
		t.Errorf("without an App the token is $GITHUB_TOKEN; got %q", c.Token)
	}

	key := writeKey(t)
	cfg, err = config.Parse([]string{"--namespace=x", "--github-app-id=1", "--github-app-installation-id=2", "--github-app-private-key-file=" + key}, getenv)
	if err != nil {
		t.Fatal(err)
	}
	c, err = newGitHub(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "" {
		t.Error("with an App, $GITHUB_TOKEN is not sent")
	}
	if _, ok := c.HTTP.Transport.(*githubapp.Transport); !ok {
		t.Errorf("transport = %T, want the App's", c.HTTP.Transport)
	}

	cfg, err = config.Parse([]string{"--namespace=x", "--github-app-id=1", "--github-app-installation-id=2", "--github-app-private-key-file=" + filepath.Join(t.TempDir(), "missing.pem")}, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newGitHub(cfg); err == nil {
		t.Error("a missing key was accepted")
	}
}
