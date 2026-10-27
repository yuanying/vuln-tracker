package main

import (
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/vuln-tracker/internal/config"
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
