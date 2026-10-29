package tracker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"

	"github.com/yuanying/vuln-tracker/internal/digest"
	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/pipeline"
	"github.com/yuanying/vuln-tracker/internal/scanner"
	"github.com/yuanying/vuln-tracker/internal/stage"
	"github.com/yuanying/vuln-tracker/internal/state"
)

func TestNextScan(t *testing.T) {
	wanted := []string{"a@sha256:1", "a@sha256:2", "a@sha256:3", "a@sha256:4"}
	results := map[string]ScanResult{
		"sha256:1": {At: now.Add(-time.Hour)},                      // fresh
		"sha256:2": {At: now.Add(-25 * time.Hour)},                 // stale
		"sha256:3": {At: now.Add(-30 * time.Minute), Err: errScan}, // failed recently
	}
	// Never scanned goes first.
	if got, ok := NextScan(wanted, results, now); !ok || got != "a@sha256:4" {
		t.Errorf("NextScan = %q, %v; want the one never scanned", got, ok)
	}
	results["sha256:4"] = ScanResult{At: now}
	if got, ok := NextScan(wanted, results, now); !ok || got != "a@sha256:2" {
		t.Errorf("NextScan = %q, %v; want the stale one", got, ok)
	}
	results["sha256:2"] = ScanResult{At: now}
	if _, ok := NextScan(wanted, results, now); ok {
		t.Error("nothing is due")
	}
	// A failure is retried after an hour.
	if got, ok := NextScan(wanted, results, now.Add(31*time.Minute)); !ok || got != "a@sha256:3" {
		t.Errorf("NextScan = %q, %v; want the failed one again", got, ok)
	}
}

type fakeSource struct {
	reports []Report
	pods    []corev1.Pod
}

func (f *fakeSource) List(context.Context) ([]Report, []corev1.Pod, error) {
	return f.reports, f.pods, nil
}

type fakeScanner struct {
	results map[string]scanner.Set
	calls   []string
}

func (f *fakeScanner) Scan(_ context.Context, ref string) (scanner.Set, error) {
	f.calls = append(f.calls, ref)
	_, d, _ := strings.Cut(ref, "@")
	if s, ok := f.results[d]; ok {
		return s, nil
	}
	return nil, errScan
}

type fakeRepos struct {
	mu    sync.Mutex
	files map[string]map[string][]byte
	prs   map[string][]github.PullRequest
	// pulls are read by URL; prFiles by URL too.
	pulls   map[string]github.PullRequest
	prFiles map[string][]string
	calls   map[string]int
}

func (f *fakeRepos) count(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[call]++
}

func (f *fakeRepos) called(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[call]
}

func (f *fakeRepos) Head(_ context.Context, repo, _ string) (string, error) {
	return "sha-" + repo, nil
}

func (f *fakeRepos) Files(_ context.Context, repo, _ string) (map[string][]byte, error) {
	return f.files[repo], nil
}

func (f *fakeRepos) OpenPullRequests(_ context.Context, repo string) ([]github.PullRequest, error) {
	f.count("open " + repo)
	return f.prs[repo], nil
}

func prURL(repo string, n int) string {
	return fmt.Sprintf("https://github.com/%s/pull/%d", repo, n)
}

func (f *fakeRepos) PullRequest(_ context.Context, repo string, n int) (github.PullRequest, error) {
	f.count("pull " + prURL(repo, n))
	pr, ok := f.pulls[prURL(repo, n)]
	if !ok {
		return github.PullRequest{}, errors.New("404 Not Found")
	}
	return pr, nil
}

func (f *fakeRepos) PullRequestFiles(_ context.Context, repo string, n int) ([]string, error) {
	f.count("files " + prURL(repo, n))
	return f.prFiles[prURL(repo, n)], nil
}

type memStore struct {
	mu    sync.Mutex
	saved *state.State
	saves int
}

func (m *memStore) Load(context.Context) (*state.State, error) {
	if m.saved == nil {
		return state.New(), nil
	}
	b, _ := state.Encode(m.saved)
	return state.Decode(b)
}

func (m *memStore) Save(_ context.Context, s *state.State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := state.Encode(s)
	m.saved, _ = state.Decode(b)
	m.saves++
	return nil
}

type fakeSlack struct{ sent []string }

func (f *fakeSlack) Send(_ context.Context, text string) error {
	f.sent = append(f.sent, text)
	return nil
}

func TestTrackerPass(t *testing.T) {
	const name = "ghcr.io/yuanying/hshelf"
	reg := &fakeRegistry{
		tags:    map[string][]string{name: {"1.0.0", "main"}},
		digests: map[string]string{name + ":main": dMain},
		labels:  map[string]map[string]string{name + "@" + dRun: labels("https://github.com/yuanying/hshelf", "aaa")},
	}
	src := &fakeSource{
		reports: []Report{{
			Image:    imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: dRun},
			Workload: Workload{Namespace: "aphrael", Kind: "ReplicaSet", Name: "aphrael-1", Container: "aphrael"},
			Vulns:    []Vuln{{ID: "CVE-1", Package: "json", Severity: "CRITICAL", FixedVersion: "2.19.2"}},
		}},
		pods: []corev1.Pod{pod("aphrael", "p", name+"@"+dRun)},
	}
	sc := &fakeScanner{results: map[string]scanner.Set{dMain: {}}}
	repos := &fakeRepos{files: map[string]map[string][]byte{
		"yuanying/fleet-infra": {
			"security/vex/ghcr.io/yuanying/hshelf.openvex.json": []byte(`{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "author": "t", "timestamp": "2026-10-01T00:00:00Z", "version": 1, "statements": [
  {"vulnerability": {"name": "CVE-1"}, "timestamp": "2026-10-01T00:00:00Z", "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf"}],
   "status": "affected", "action_statement": "release this week", "status_notes": "state: in-progress\nreview-by: 2026-10-20"}]}`),
		},
	}}
	store := &memStore{}
	slack := &fakeSlack{}
	clock := now
	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	sched, _ := digest.ParseSchedule("Mon 09:00", tokyo)

	tr := &Tracker{
		Source:     src,
		Store:      store,
		Discoverer: &Discoverer{Registry: reg, SelfSourcePrefix: "https://github.com/yuanying/", RenovateAuthor: regexp.MustCompile("renovate"), Now: func() time.Time { return clock }},
		Scanner:    sc,
		GitHub:     repos,
		Slack:      slack,
		Metrics:    NewMetrics(prometheus.NewRegistry()),
		Log:        logr.Discard(),
		Now:        func() time.Time { return clock },
		Config: Config{
			FleetInfra:       Repo{Name: "yuanying/fleet-infra", Branch: "main"},
			Manifests:        []Repo{{Name: "yuanying/fleet-infra", Branch: "main"}},
			DetailSeverities: map[string]bool{"CRITICAL": true, "HIGH": true},
			Location:         tokyo,
			Schedule:         sched,
			DashboardURL:     "https://grafana.example/d/vuln",
		},
	}
	ctx := context.Background()
	if err := tr.LoadState(ctx); err != nil {
		t.Fatal(err)
	}

	// Before anything is synced, the finding is pending.
	tr.EvaluateOnce(ctx)
	snap, ok := tr.Snapshot()
	if !ok || len(snap.Findings) != 1 || snap.Findings[0].Stage != stage.Pending {
		t.Fatalf("first evaluation: %+v", snap)
	}

	tr.SyncOnce(ctx)
	if !tr.ScanOnce(ctx) {
		t.Fatal("ScanOnce found nothing to scan")
	}
	if len(sc.calls) != 1 || sc.calls[0] != name+"@"+dMain {
		t.Errorf("scanned %v", sc.calls)
	}
	if tr.ScanOnce(ctx) {
		t.Error("a second scan with nothing due")
	}
	tr.EvaluateOnce(ctx)
	snap, _ = tr.Snapshot()
	f := snap.Findings[0]
	if f.Stage != stage.FixedInMain || f.VexState() != "in-progress" || !f.VexExpired {
		t.Errorf("finding after the scan: %+v", f)
	}
	if store.saves == 0 {
		t.Error("the state was never saved")
	}

	// The digest waits for Monday 09:00 in Tokyo; it is Tuesday.
	tr.DigestOnce(ctx)
	if len(slack.sent) != 0 {
		t.Fatalf("sent before the schedule: %v", slack.sent)
	}
	clock = time.Date(2026, 11, 2, 9, 0, 1, 0, tokyo)
	tr.DigestOnce(ctx)
	if len(slack.sent) != 1 {
		t.Fatalf("sent %d digests, want 1", len(slack.sent))
	}
	if !strings.Contains(slack.sent[0], "release this week") || !strings.Contains(slack.sent[0], "https://grafana.example/d/vuln") {
		t.Errorf("digest:\n%s", slack.sent[0])
	}
	if store.saved.Digest.SentAt != clock.Unix() || store.saved.Digest.Findings[f.Key()].Stage != "fixed-in-main" {
		t.Errorf("the digest was not remembered: %+v", store.saved.Digest)
	}
	tr.DigestOnce(ctx)
	if len(slack.sent) != 1 {
		t.Error("sent twice in one week")
	}

	// A restart remembers when the digest went out.
	tr2 := &Tracker{Store: store, Log: logr.Discard()}
	if err := tr2.LoadState(ctx); err != nil {
		t.Fatal(err)
	}
	if tr2.state.Digest.SentAt != clock.Unix() {
		t.Error("the restarted tracker forgot the last digest")
	}
}

// The tracker reads the source repository's open pull requests, the state of
// vuln-responder's reply and the files of the manifest repository's pull
// requests, and links them (ADR 0014).
func TestTrackerPipeline(t *testing.T) {
	const (
		name  = "ghcr.io/yuanying/hshelf"
		src   = "yuanying/hshelf"
		fleet = "yuanying/fleet-infra"
	)
	reg := &fakeRegistry{
		tags:    map[string][]string{name: {"1.0.0", "main"}},
		digests: map[string]string{name + ":main": dMain},
		labels:  map[string]map[string]string{name + "@" + dRun: labels("https://github.com/yuanying/hshelf", "aaa")},
	}
	source := &fakeSource{
		reports: []Report{{
			Image:    imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: dRun},
			Workload: Workload{Namespace: "aphrael", Kind: "ReplicaSet", Name: "aphrael-1", Container: "aphrael"},
			Vulns:    []Vuln{{ID: "CVE-1", Package: "json", Severity: "CRITICAL", FixedVersion: "2.19.2"}},
		}},
		pods: []corev1.Pod{pod("aphrael", "p", name+"@"+dRun)},
	}
	// :main still has it.
	sc := &fakeScanner{results: map[string]scanner.Set{dMain: set(scanner.Key{VulnerabilityID: "CVE-1", Package: "json"})}}
	fix := github.PullRequest{URL: prURL(src, 3), Repository: src, Number: 3, State: github.StateOpen, Author: "yuanying", Title: "Fix CVE-1", HeadSHA: "a"}
	vex := github.PullRequest{URL: prURL(fleet, 9), Repository: fleet, Number: 9, State: github.StateOpen, Author: "fraction-vuln-responder[bot]", Title: "Annotate", HeadSHA: "b"}
	repos := &fakeRepos{
		files: map[string]map[string][]byte{fleet: {}},
		prs:   map[string][]github.PullRequest{src: {fix}, fleet: {vex}},
		pulls: map[string]github.PullRequest{vex.URL: vex},
		prFiles: map[string][]string{
			vex.URL: {"security/vex/ghcr.io/yuanying/hshelf.openvex.json"},
		},
	}
	store := &memStore{saved: state.New()}
	store.saved.Initialized = true
	store.saved.Requests["image:x"] = state.Request{TargetType: "source", Target: src, PR: vex.URL, Asked: []string{name + "|CVE-1|json"}}
	clock := now
	tr := &Tracker{
		Source:     source,
		Store:      store,
		Discoverer: &Discoverer{Registry: reg, SelfSourcePrefix: "https://github.com/yuanying/", RenovateAuthor: regexp.MustCompile("renovate"), Now: func() time.Time { return clock }},
		Scanner:    sc,
		GitHub:     repos,
		Metrics:    NewMetrics(prometheus.NewRegistry()),
		Log:        logr.Discard(),
		Now:        func() time.Time { return clock },
		Config: Config{
			FleetInfra:       Repo{Name: fleet, Branch: "main"},
			Manifests:        []Repo{{Name: fleet, Branch: "main"}},
			DetailSeverities: map[string]bool{"CRITICAL": true},
			GitInterval:      10 * time.Minute,
		},
	}
	ctx := context.Background()
	if err := tr.LoadState(ctx); err != nil {
		t.Fatal(err)
	}
	tr.EvaluateOnce(ctx)
	if snap, _ := tr.Snapshot(); snap.Synced {
		t.Error("synced before the first sync")
	}

	tr.SyncOnce(ctx)
	tr.ScanOnce(ctx)
	tr.EvaluateOnce(ctx)
	snap, _ := tr.Snapshot()
	if !snap.Synced {
		t.Error("not synced after the first sync")
	}
	p := snap.Findings[0].Pipeline
	if p.Source != pipeline.SourcePROpen || p.SourceRepository != src || len(p.SourcePRs) != 1 || p.SourcePRs[0].URL != fix.URL {
		t.Errorf("source: %+v", p)
	}
	if p.Manifest != pipeline.ManifestNoFix || len(p.ManifestPRs) != 0 || len(p.VEXPRs) != 1 || p.VEXPRs[0].Link != pipeline.LinkResponder {
		t.Errorf("manifest: %+v", p)
	}

	// Within the git interval nothing is read again.
	clock = clock.Add(time.Minute)
	tr.SyncOnce(ctx)
	if n := repos.called("open " + src); n != 1 {
		t.Errorf("source pull requests read %d times, want 1", n)
	}

	// After it, the open pull requests and the open reply are read again;
	// the files of a head already read are not.
	clock = clock.Add(10 * time.Minute)
	tr.SyncOnce(ctx)
	if n := repos.called("open " + src); n != 2 {
		t.Errorf("source pull requests read %d times, want 2", n)
	}
	if n := repos.called("pull " + vex.URL); n != 2 {
		t.Errorf("the reply read %d times, want 2", n)
	}
	if n := repos.called("files " + vex.URL); n != 1 {
		t.Errorf("the files read %d times, want 1", n)
	}

	// A merged reply is final, and the pull request it replaced gone.
	merged := vex
	merged.State = github.StateMerged
	repos.mu.Lock()
	repos.pulls[vex.URL] = merged
	repos.prs[fleet] = nil
	repos.mu.Unlock()
	clock = clock.Add(10 * time.Minute)
	tr.SyncOnce(ctx)
	clock = clock.Add(10 * time.Minute)
	tr.SyncOnce(ctx)
	if n := repos.called("pull " + vex.URL); n != 3 {
		t.Errorf("the merged reply read %d times, want 3", n)
	}
	tr.EvaluateOnce(ctx)
	snap, _ = tr.Snapshot()
	if p := snap.Findings[0].Pipeline; len(p.VEXPRs) != 1 || p.VEXPRs[0].State != github.StateMerged {
		t.Errorf("after the merge: %+v", p)
	}
}
