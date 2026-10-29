// Package config reads the tracker's configuration. Behavior comes from
// flags; credentials come only from the environment, filled from Secrets, so
// that they appear neither in the Pod spec nor on the command line (ADR 0007).
package config

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/yuanying/vuln-tracker/internal/digest"
	"github.com/yuanying/vuln-tracker/internal/tracker"
)

// Severities are VulnerabilityReport's severities.
var Severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// Config is everything the process is started with.
type Config struct {
	Namespace      string
	StateConfigMap string

	TrivyBinary   string
	TrivyServer   string
	TrivyCacheDir string
	TrivyTempDir  string
	ScanTimeout   time.Duration
	ScanInterval  time.Duration

	FleetInfra       tracker.Repo
	Manifests        []tracker.Repo
	GitInterval      time.Duration
	SelfSourcePrefix string
	RenovateAuthor   *regexp.Regexp

	DetailSeverities map[string]bool
	Location         *time.Location
	Schedule         digest.Schedule
	DashboardURL     string
	VEXBaseURL       string

	// Requests to vuln-responder (ADR 0009). An empty URL turns them off.
	ResponderURL          string
	ResponderTokenFile    string
	ResponderMode         string
	ResponderNewWithin    time.Duration
	ResponderTaskTimeout  time.Duration
	ResponderPollInterval time.Duration

	// The GitHub App whose installation tokens read GitHub (ADR 0013). An
	// App ID of 0 reads with $GITHUB_TOKEN instead.
	GitHubAppID             int64
	GitHubAppInstallationID int64
	GitHubAppPrivateKeyFile string

	MetricsAddr string
	ProbeAddr   string
	// APIAddr is where the JSON API is served (ADR 0015); "0" turns it off.
	APIAddr     string
	LeaderElect bool

	// From the environment.
	GitHubToken     string
	SlackWebhookURL string
	TrivyToken      string
}

func parseRepo(s string) (tracker.Repo, error) {
	name, branch, ok := strings.Cut(strings.TrimSpace(s), "@")
	if !ok || name == "" || branch == "" || strings.Count(name, "/") != 1 {
		return tracker.Repo{}, fmt.Errorf("%q: want owner/name@branch", s)
	}
	return tracker.Repo{Name: name, Branch: branch}, nil
}

// Parse reads flags and the environment. extra may add flags of its own to the
// set, such as the logger's.
func Parse(args []string, getenv func(string) string, extra ...func(*flag.FlagSet)) (Config, error) {
	var c Config
	fs := flag.NewFlagSet("vuln-tracker", flag.ContinueOnError)
	fs.StringVar(&c.Namespace, "namespace", getenv("POD_NAMESPACE"), "Namespace of the state ConfigMap. Defaults to $POD_NAMESPACE.")
	fs.StringVar(&c.StateConfigMap, "state-configmap", "vuln-tracker-state", "Name of the ConfigMap the state is kept in.")
	fs.StringVar(&c.TrivyBinary, "trivy-binary", "/usr/local/bin/trivy", "Path of the trivy binary.")
	fs.StringVar(&c.TrivyServer, "trivy-server", "http://trivy-service.trivy-system:4954", "URL of the Trivy server.")
	fs.StringVar(&c.TrivyCacheDir, "trivy-cache-dir", "/work/cache", "Directory trivy keeps the Java DB in.")
	fs.StringVar(&c.TrivyTempDir, "trivy-temp-dir", "/work/tmp", "Directory trivy writes temporary files to; emptied after every scan.")
	fs.DurationVar(&c.ScanTimeout, "scan-timeout", 10*time.Minute, "Time limit of one scan.")
	fs.DurationVar(&c.ScanInterval, "scan-interval", time.Minute, "Pause after each scan.")
	fleet := fs.String("fleet-infra", "yuanying/fleet-infra@main", "Repository with security/vex and security/image-sources.yaml, as owner/name@branch.")
	mans := fs.String("manifests", "yuanying/fleet-infra@main,yuanying/k8s-manifests-fraction@master", "Comma-separated repositories whose manifests name image versions, as owner/name@branch.")
	fs.DurationVar(&c.GitInterval, "git-interval", 10*time.Minute, "How often the repositories' heads are checked.")
	fs.StringVar(&c.SelfSourcePrefix, "self-source-prefix", "https://github.com/yuanying/", "An image whose org.opencontainers.image.source starts with this is built here.")
	renovate := fs.String("renovate-author", "renovate", "Regular expression matching the login of Renovate's pull requests.")
	sev := fs.String("detail-severities", "CRITICAL,HIGH", "Comma-separated severities exported finding by finding and listed in the digest.")
	tz := fs.String("timezone", "Asia/Tokyo", "Time zone of review-by dates and the digest schedule.")
	sched := fs.String("digest-schedule", "Mon 09:00", "When the weekly digest is sent: a weekday and HH:MM.")
	fs.StringVar(&c.DashboardURL, "dashboard-url", "", "Grafana dashboard linked from the digest.")
	fs.StringVar(&c.VEXBaseURL, "vex-base-url", "https://github.com/yuanying/fleet-infra/blob/main/", "Prefix that turns a VEX document's path into a link.")
	fs.StringVar(&c.ResponderURL, "responder-url", "", "A2A endpoint of vuln-responder. Empty: nothing is asked of it.")
	fs.StringVar(&c.ResponderTokenFile, "responder-token-file", "/var/run/secrets/a2a/token", "ServiceAccount token for the a2a audience, read for every request.")
	fs.StringVar(&c.ResponderMode, "responder-mode", "vex-only", "What vuln-responder is asked for: vex-only, or fix, which also asks for version bumps.")
	fs.DurationVar(&c.ResponderNewWithin, "responder-new-within", 7*24*time.Hour, "Findings first seen this recently are asked about.")
	fs.DurationVar(&c.ResponderTaskTimeout, "responder-task-timeout", 3*time.Hour, "How long a vuln-responder task is waited for.")
	fs.DurationVar(&c.ResponderPollInterval, "responder-poll-interval", time.Minute, "How often a request is sent or its task looked at.")
	fs.Int64Var(&c.GitHubAppID, "github-app-id", 0, "ID of the GitHub App that reads GitHub. 0: read with $GITHUB_TOKEN instead.")
	fs.Int64Var(&c.GitHubAppInstallationID, "github-app-installation-id", 0, "ID of the App's installation on the owner of the repositories.")
	fs.StringVar(&c.GitHubAppPrivateKeyFile, "github-app-private-key-file", "/var/run/secrets/github-app/private-key.pem", "PEM private key of the GitHub App.")
	fs.StringVar(&c.MetricsAddr, "metrics-bind-address", ":8080", "Address /metrics is served on.")
	fs.StringVar(&c.ProbeAddr, "health-probe-bind-address", ":8081", "Address /healthz and /readyz are served on.")
	fs.StringVar(&c.APIAddr, "api-bind-address", ":8082", "Address the JSON API (/api/findings) is served on. 0: not served.")
	fs.BoolVar(&c.LeaderElect, "leader-elect", false, "Use leader election. Off: the tracker runs as one replica (ADR 0001).")
	for _, f := range extra {
		f(fs)
	}
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	var errs []error
	if c.Namespace == "" {
		errs = append(errs, errors.New("--namespace (or $POD_NAMESPACE) is required"))
	}
	if c.ScanTimeout <= 0 {
		errs = append(errs, errors.New("--scan-timeout must be positive"))
	}
	if c.ResponderURL != "" {
		if u, err := url.Parse(c.ResponderURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, fmt.Errorf("--responder-url: %q is not an http(s) URL", c.ResponderURL))
		}
	}
	if c.ResponderMode != "vex-only" && c.ResponderMode != "fix" {
		errs = append(errs, fmt.Errorf("--responder-mode: %q is not vex-only or fix", c.ResponderMode))
	}
	switch {
	case c.GitHubAppID < 0:
		errs = append(errs, errors.New("--github-app-id must not be negative"))
	case c.GitHubAppID > 0 && c.GitHubAppInstallationID <= 0:
		errs = append(errs, errors.New("--github-app-installation-id is required with --github-app-id"))
	case c.GitHubAppID > 0 && c.GitHubAppPrivateKeyFile == "":
		errs = append(errs, errors.New("--github-app-private-key-file is required with --github-app-id"))
	}
	for _, d := range []struct {
		flag string
		d    time.Duration
	}{
		{"--responder-new-within", c.ResponderNewWithin},
		{"--responder-task-timeout", c.ResponderTaskTimeout},
		{"--responder-poll-interval", c.ResponderPollInterval},
	} {
		if d.d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", d.flag))
		}
	}
	var err error
	if c.FleetInfra, err = parseRepo(*fleet); err != nil {
		errs = append(errs, fmt.Errorf("--fleet-infra: %w", err))
	}
	for _, s := range strings.Split(*mans, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		r, err := parseRepo(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("--manifests: %w", err))
			continue
		}
		c.Manifests = append(c.Manifests, r)
	}
	if c.RenovateAuthor, err = regexp.Compile(*renovate); err != nil {
		errs = append(errs, fmt.Errorf("--renovate-author: %w", err))
	}
	c.DetailSeverities = map[string]bool{}
	for _, s := range strings.Split(*sev, ",") {
		s = strings.ToUpper(strings.TrimSpace(s))
		if !slices.Contains(Severities, s) {
			errs = append(errs, fmt.Errorf("--detail-severities: %q is not one of %v", s, Severities))
			continue
		}
		c.DetailSeverities[s] = true
	}
	if c.Location, err = time.LoadLocation(*tz); err != nil {
		errs = append(errs, fmt.Errorf("--timezone: %w", err))
	} else if c.Schedule, err = digest.ParseSchedule(*sched, c.Location); err != nil {
		errs = append(errs, fmt.Errorf("--digest-schedule: %w", err))
	}

	c.GitHubToken = getenv("GITHUB_TOKEN")
	c.SlackWebhookURL = getenv("SLACK_WEBHOOK_URL")
	c.TrivyToken = getenv("TRIVY_TOKEN")
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return c, nil
}
