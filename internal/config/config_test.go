package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Parse(nil, env(map[string]string{"POD_NAMESPACE": "vuln-tracker"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Namespace != "vuln-tracker" || c.StateConfigMap != "vuln-tracker-state" {
		t.Errorf("state: %q/%q", c.Namespace, c.StateConfigMap)
	}
	if c.TrivyServer != "http://trivy-service.trivy-system:4954" || c.ScanTimeout != 10*time.Minute || c.ScanInterval != time.Minute {
		t.Errorf("scan: %+v", c)
	}
	if c.FleetInfra.Name != "yuanying/fleet-infra" || c.FleetInfra.Branch != "main" {
		t.Errorf("fleet-infra: %+v", c.FleetInfra)
	}
	if len(c.Manifests) != 2 || c.Manifests[1].Name != "yuanying/k8s-manifests-fraction" || c.Manifests[1].Branch != "master" {
		t.Errorf("manifests: %+v", c.Manifests)
	}
	if !c.DetailSeverities["CRITICAL"] || !c.DetailSeverities["HIGH"] || c.DetailSeverities["MEDIUM"] {
		t.Errorf("severities: %v", c.DetailSeverities)
	}
	if c.Location.String() != "Asia/Tokyo" || c.Schedule.Weekday != time.Monday || c.Schedule.Hour != 9 {
		t.Errorf("time: %v %+v", c.Location, c.Schedule)
	}
	if c.LeaderElect {
		t.Error("leader election is off by default (ADR 0001)")
	}
	if c.GitHubToken != "" || c.SlackWebhookURL != "" {
		t.Error("no secrets by default")
	}
}

func TestFlagsAndSecrets(t *testing.T) {
	c, err := Parse([]string{
		"--namespace=ops",
		"--manifests=a/b@main,c/d@trunk",
		"--detail-severities=critical",
		"--digest-schedule=Fri 17:30",
		"--timezone=UTC",
		"--dashboard-url=https://grafana.example/d/x",
		"--leader-elect",
	}, env(map[string]string{
		"GITHUB_TOKEN":      "ghp_x",
		"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/x",
		"TRIVY_TOKEN":       "t",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Namespace != "ops" || !c.LeaderElect || c.DashboardURL != "https://grafana.example/d/x" {
		t.Errorf("got %+v", c)
	}
	if got := []string{c.Manifests[0].Name + "@" + c.Manifests[0].Branch, c.Manifests[1].Name + "@" + c.Manifests[1].Branch}; !slices.Equal(got, []string{"a/b@main", "c/d@trunk"}) {
		t.Errorf("manifests %v", got)
	}
	if !c.DetailSeverities["CRITICAL"] || len(c.DetailSeverities) != 1 {
		t.Errorf("severities %v", c.DetailSeverities)
	}
	if c.Schedule.Weekday != time.Friday || c.Schedule.Hour != 17 || c.Schedule.Minute != 30 {
		t.Errorf("schedule %+v", c.Schedule)
	}
	if c.GitHubToken != "ghp_x" || c.SlackWebhookURL != "https://hooks.slack.com/services/x" || c.TrivyToken != "t" {
		t.Error("secrets are read from the environment")
	}
}

// Secrets are never flags: a flag shows in the Pod spec and in ps.
func TestNoSecretFlags(t *testing.T) {
	for _, f := range []string{"--github-token=x", "--slack-webhook-url=x", "--trivy-token=x"} {
		if _, err := Parse([]string{f}, env(nil)); err == nil {
			t.Errorf("%s was accepted", f)
		}
	}
}

func TestInvalid(t *testing.T) {
	tests := map[string][]string{
		"no namespace":      {},
		"bad repo":          {"--namespace=x", "--manifests=nobranch"},
		"bad severity":      {"--namespace=x", "--detail-severities=urgent"},
		"bad schedule":      {"--namespace=x", "--digest-schedule=someday"},
		"bad timezone":      {"--namespace=x", "--timezone=Mars/Base"},
		"bad renovate re":   {"--namespace=x", "--renovate-author=("},
		"zero scan timeout": {"--namespace=x", "--scan-timeout=0s"},
	}
	for name, args := range tests {
		_, err := Parse(args, env(nil))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "ghp_") {
			t.Errorf("%s: error mentions a secret", name)
		}
	}
}
