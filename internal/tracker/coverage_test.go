package tracker

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"

	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/responder"
)

func TestCoverageGaps(t *testing.T) {
	self := func(source string) ImageView {
		return ImageView{SelfBuilt: true, Source: source}
	}
	writable := responder.Writable{"yuanying/hshelf": true, "yuanying/natsumi-sshd": true}
	for _, tc := range []struct {
		name     string
		images   []ImageView
		writable responder.Writable
		archived map[string]bool
		want     []CoverageGap
	}{
		{
			name:     "a writable, live source is no gap",
			images:   []ImageView{self("https://github.com/yuanying/hshelf")},
			writable: writable,
			archived: map[string]bool{"yuanying/hshelf": false},
		},
		{
			name:     "a source missing from github-writer.json is not writable",
			images:   []ImageView{self("https://github.com/yuanying/penelope")},
			writable: writable,
			want:     []CoverageGap{{SourceRepository: "yuanying/penelope", Reason: GapNotWritable}},
		},
		{
			name:     "an archived source is a gap even when writable",
			images:   []ImageView{self("https://github.com/yuanying/natsumi-sshd")},
			writable: writable,
			archived: map[string]bool{"yuanying/natsumi-sshd": true},
			want:     []CoverageGap{{SourceRepository: "yuanying/natsumi-sshd", Reason: GapArchived}},
		},
		{
			name:     "both reasons are two gaps",
			images:   []ImageView{self("https://github.com/yuanying/old")},
			writable: writable,
			archived: map[string]bool{"yuanying/old": true},
			want: []CoverageGap{
				{SourceRepository: "yuanying/old", Reason: GapArchived},
				{SourceRepository: "yuanying/old", Reason: GapNotWritable},
			},
		},
		{
			name:     "several versions of one source are one gap",
			images:   []ImageView{self("https://github.com/yuanying/penelope"), self("https://github.com/yuanying/penelope.git")},
			writable: writable,
			want:     []CoverageGap{{SourceRepository: "yuanying/penelope", Reason: GapNotWritable}},
		},
		{
			name:     "an image not built here is not looked at",
			images:   []ImageView{{SelfBuilt: false, Source: "https://github.com/longhorn/longhorn-engine"}},
			writable: writable,
		},
		{
			name:     "before github-writer.json is read, nothing is not writable",
			images:   []ImageView{self("https://github.com/yuanying/penelope")},
			writable: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CoverageGaps(tc.images, tc.writable, tc.archived)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

const writerPath = "apps/fraction-agents/prod/vuln-responder/github-writer.json"

// coverageTracker runs one self-built image from yuanying/hshelf, with
// fleet-infra holding the given github-writer.json.
func coverageTracker(writerConfig string, repos *fakeRepos, clock *time.Time) *Tracker {
	const name = "ghcr.io/yuanying/hshelf"
	reg := &fakeRegistry{
		tags:   map[string][]string{name: {"1.0.0"}},
		labels: map[string]map[string]string{name + "@" + dRun: labels("https://github.com/yuanying/hshelf", "aaa")},
	}
	src := &fakeSource{
		reports: []Report{{Image: imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: dRun}}},
		pods:    []corev1.Pod{pod("aphrael", "p", name+"@"+dRun)},
	}
	return &Tracker{
		Source:     src,
		Store:      &memStore{},
		Discoverer: &Discoverer{Registry: reg, SelfSourcePrefix: "https://github.com/yuanying/", RenovateAuthor: regexp.MustCompile("renovate"), Now: func() time.Time { return *clock }},
		Scanner:    &fakeScanner{},
		GitHub:     repos,
		Metrics:    NewMetrics(prometheus.NewRegistry()),
		Log:        logr.Discard(),
		Now:        func() time.Time { return *clock },
		Config: Config{
			FleetInfra:            Repo{Name: "yuanying/fleet-infra", Branch: "main"},
			GitInterval:           10 * time.Minute,
			ResponderWriterConfig: writerConfig,
		},
	}
}

// pass evaluates, syncs, which reads the repositories and discovers the
// image, and evaluates again.
func pass(t *testing.T, tr *Tracker) []CoverageGap {
	t.Helper()
	ctx := context.Background()
	tr.EvaluateOnce(ctx)
	tr.SyncOnce(ctx)
	tr.EvaluateOnce(ctx)
	snap, _ := tr.Snapshot()
	return snap.CoverageGaps
}

// A self-built image's source missing from github-writer.json, and archived
// on GitHub, is a gap for both reasons (ADR 0016).
func TestTrackerCoverageGap(t *testing.T) {
	clock := now
	repos := &fakeRepos{
		files:    map[string]map[string][]byte{"yuanying/fleet-infra": {writerPath: []byte(`{"repositories": [{"owner": "yuanying", "name": "fleet-infra"}]}`)}},
		archived: map[string]bool{"yuanying/hshelf": true},
	}
	tr := coverageTracker(writerPath, repos, &clock)
	if err := tr.LoadState(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := pass(t, tr)
	want := []CoverageGap{
		{SourceRepository: "yuanying/hshelf", Reason: GapArchived},
		{SourceRepository: "yuanying/hshelf", Reason: GapNotWritable},
	}
	if !slices.Equal(got, want) {
		t.Errorf("gaps = %v, want %v", got, want)
	}
}

// A github-writer.json that cannot be read keeps the list read before, and
// is counted as an error of fleet-infra's files, like image-sources.
func TestTrackerBrokenWriterConfigKeepsTheList(t *testing.T) {
	clock := now
	repos := &fakeRepos{
		files:    map[string]map[string][]byte{"yuanying/fleet-infra": {writerPath: []byte(`{"repositories": [{"owner": "yuanying", "name": "hshelf"}]}`)}},
		archived: map[string]bool{"yuanying/hshelf": false},
	}
	tr := coverageTracker(writerPath, repos, &clock)
	if err := tr.LoadState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := pass(t, tr); len(got) != 0 {
		t.Fatalf("gaps with a writable source: %v", got)
	}

	repos.mu.Lock()
	repos.heads = map[string]string{"yuanying/fleet-infra": "broken"}
	repos.files["yuanying/fleet-infra"] = map[string][]byte{writerPath: []byte(`{"repositories": [`)}
	repos.mu.Unlock()
	clock = clock.Add(10 * time.Minute)
	if got := pass(t, tr); len(got) != 0 {
		t.Errorf("a broken github-writer.json dropped the list: %v", got)
	}
	if n := testutil.ToFloat64(tr.Metrics.SyncErrors.WithLabelValues("vex")); n != 1 {
		t.Errorf("vex errors = %v, want 1", n)
	}
}

// Whether a source is archived is read at most once an hour, so the check
// costs little of the rate limit (ADR 0016).
func TestTrackerArchivedIsCached(t *testing.T) {
	clock := now
	repos := &fakeRepos{
		files:    map[string]map[string][]byte{"yuanying/fleet-infra": {writerPath: []byte(`{"repositories": []}`)}},
		archived: map[string]bool{"yuanying/hshelf": false},
	}
	tr := coverageTracker(writerPath, repos, &clock)
	if err := tr.LoadState(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 6 {
		pass(t, tr)
		clock = clock.Add(10 * time.Minute)
	}
	if n := repos.called("archived yuanying/hshelf"); n != 1 {
		t.Errorf("read %d times in an hour, want 1", n)
	}
	pass(t, tr)
	if n := repos.called("archived yuanying/hshelf"); n != 2 {
		t.Errorf("read %d times after an hour, want 2", n)
	}
}

// Without --responder-writer-config nothing is checked: no gap, and no
// repository is asked whether it is archived.
func TestTrackerCoverageOff(t *testing.T) {
	clock := now
	repos := &fakeRepos{
		files:    map[string]map[string][]byte{"yuanying/fleet-infra": {}},
		archived: map[string]bool{"yuanying/hshelf": true},
	}
	tr := coverageTracker("", repos, &clock)
	if err := tr.LoadState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := pass(t, tr); len(got) != 0 {
		t.Errorf("gaps with the check off: %v", got)
	}
	if n := repos.called("archived yuanying/hshelf"); n != 0 {
		t.Errorf("archived read %d times with the check off", n)
	}
}

// Each gap is one series of value 1 (ADR 0005).
func TestCollectorCoverageGap(t *testing.T) {
	snap := Snapshot{CoverageGaps: []CoverageGap{{SourceRepository: "yuanying/penelope", Reason: GapNotWritable}}}
	c := &Collector{Snapshot: func() (Snapshot, bool) { return snap, true }}
	want := `
# HELP vuln_tracker_responder_coverage_gap A source repository of a self-built image running in production that vuln-responder cannot fix: missing from its github-writer.json (not-writable) or archived on GitHub (archived).
# TYPE vuln_tracker_responder_coverage_gap gauge
vuln_tracker_responder_coverage_gap{reason="not-writable",source_repository="yuanying/penelope"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "vuln_tracker_responder_coverage_gap"); err != nil {
		t.Error(err)
	}
}

// A source that cannot be read (404, no permission, GitHub down) is not asked
// again within the hour, so failures keep to the rate limit too.
func TestTrackerArchivedFirstFailureWaits(t *testing.T) {
	clock := now
	repos := &fakeRepos{
		files:    map[string]map[string][]byte{"yuanying/fleet-infra": {writerPath: []byte(`{"repositories": []}`)}},
		archived: map[string]bool{}, // every read is a 404
	}
	tr := coverageTracker(writerPath, repos, &clock)
	if err := tr.LoadState(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 6 {
		pass(t, tr)
		clock = clock.Add(10 * time.Minute)
	}
	if n := repos.called("archived yuanying/hshelf"); n != 1 {
		t.Errorf("a failing read tried %d times in an hour, want 1", n)
	}
	pass(t, tr)
	if n := repos.called("archived yuanying/hshelf"); n != 2 {
		t.Errorf("a failing read tried %d times after an hour, want 2", n)
	}
}

// When the hourly refresh fails, the last value stands and the refresh waits
// another hour.
func TestTrackerArchivedRefreshFailureKeepsTheValue(t *testing.T) {
	clock := now
	repos := &fakeRepos{
		files:    map[string]map[string][]byte{"yuanying/fleet-infra": {writerPath: []byte(`{"repositories": [{"owner": "yuanying", "name": "hshelf"}]}`)}},
		archived: map[string]bool{"yuanying/hshelf": true},
	}
	tr := coverageTracker(writerPath, repos, &clock)
	if err := tr.LoadState(context.Background()); err != nil {
		t.Fatal(err)
	}
	pass(t, tr)

	repos.mu.Lock()
	delete(repos.archived, "yuanying/hshelf")
	repos.mu.Unlock()
	clock = clock.Add(time.Hour)
	for range 6 {
		got := pass(t, tr)
		want := []CoverageGap{{SourceRepository: "yuanying/hshelf", Reason: GapArchived}}
		if !slices.Equal(got, want) {
			t.Fatalf("gaps after a failed refresh = %v, want %v", got, want)
		}
		clock = clock.Add(10 * time.Minute)
	}
	if n := repos.called("archived yuanying/hshelf"); n != 2 {
		t.Errorf("read %d times, want 2: the first and one failed refresh", n)
	}
}
