package tracker

import (
	"context"
	"errors"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/yuanying/vuln-tracker/internal/annotation"
	"github.com/yuanying/vuln-tracker/internal/digest"
	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/manifests"
	"github.com/yuanying/vuln-tracker/internal/responder"
	"github.com/yuanying/vuln-tracker/internal/scanner"
	"github.com/yuanying/vuln-tracker/internal/sources"
	"github.com/yuanying/vuln-tracker/internal/stage"
	"github.com/yuanying/vuln-tracker/internal/state"
)

const (
	// scanTTL is how long a scan stands before the digest is scanned again
	// against a newer vulnerability DB (ADR 0003).
	scanTTL = 24 * time.Hour
	// scanRetry is how soon a failed scan is retried.
	scanRetry = time.Hour
	// stateSaveInterval bounds how often the state ConfigMap is written
	// (ADR 0006).
	stateSaveInterval = time.Minute
	// digestRetry is how soon a digest that failed to send is retried.
	digestRetry = 10 * time.Minute
)

// Source lists what runs in the cluster.
type Source interface {
	List(ctx context.Context) ([]Report, []corev1.Pod, error)
}

// StateStore keeps the state across restarts.
type StateStore interface {
	Load(ctx context.Context) (*state.State, error)
	Save(ctx context.Context, s *state.State) error
}

// Sender posts the digest.
type Sender interface {
	Send(ctx context.Context, text string) error
}

// Repo is a GitHub repository and the branch read from it.
type Repo struct {
	Name   string
	Branch string
}

// Config is the tracker's behavior.
type Config struct {
	// FleetInfra is where the VEX documents and the image-sources table are.
	FleetInfra Repo
	// Manifests are the repositories whose manifests name image versions.
	// FleetInfra is usually one of them.
	Manifests []Repo
	// DetailSeverities are exported finding by finding and listed in the
	// digest.
	DetailSeverities map[string]bool
	// Location is the time zone of review-by dates and the digest schedule.
	Location *time.Location
	Schedule digest.Schedule
	// DashboardURL is linked from the digest.
	DashboardURL string
	// VEXBaseURL is where a VEX document's path is appended to link it.
	VEXBaseURL string
	// GitInterval is how often the repositories' heads are checked.
	GitInterval time.Duration
	// ScanInterval is the pause after each scan.
	ScanInterval time.Duration
	// LoopInterval is how often evaluation, discovery and the digest check
	// run, and how long the scan loop waits when nothing is due. Zero is a
	// minute.
	LoopInterval time.Duration
	// ResponderNewWithin is how recently a finding must have been first
	// seen to be asked about (ADR 0009).
	ResponderNewWithin time.Duration
	// ResponderPollInterval is how often a request is sent or its task
	// looked at. Zero is LoopInterval.
	ResponderPollInterval time.Duration
}

// Tracker runs the loops. It is one manager Runnable (ADR 0001).
type Tracker struct {
	Source     Source
	Store      StateStore
	Discoverer *Discoverer
	Scanner    scanner.Scanner
	GitHub     github.Repositories
	// Slack is nil when no webhook is configured: no digest is sent.
	Slack Sender
	// Responder is nil when requests to vuln-responder are off (ADR 0009).
	Responder *responder.Requester
	Metrics   *Metrics
	Log       logr.Logger
	Now       func() time.Time
	Config

	trigger chan struct{}

	mu          sync.Mutex
	started     time.Time
	inventory   *Inventory
	images      []Image
	candidates  map[string]Candidates
	scans       map[string]ScanResult
	world       World
	vex         *annotation.Set
	heads       map[string]string
	files       map[string]map[string][]byte
	repoIndexes []RepoIndex
	// The pull requests linked by the two axes (ADR 0014): open ones by
	// repository, vuln-responder's replies by URL, and what the files of
	// manifest pull requests said, by URL.
	openPRs     map[string][]github.PullRequest
	replies     map[string]github.PullRequest
	prFiles     map[string]prFiles
	synced      bool
	lastGit     time.Time
	snapshot    Snapshot
	hasSnapshot bool
	state       *state.State
	stateDirty  bool
	lastSave    time.Time
	digestNext  time.Time
}

func (t *Tracker) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Tracker) init() {
	if t.inventory == nil {
		t.inventory = NewInventory()
		t.candidates = map[string]Candidates{}
		t.scans = map[string]ScanResult{}
		t.heads = map[string]string{}
		t.files = map[string]map[string][]byte{}
		t.openPRs = map[string][]github.PullRequest{}
		t.replies = map[string]github.PullRequest{}
		t.prFiles = map[string]prFiles{}
	}
	if t.trigger == nil {
		t.trigger = make(chan struct{}, 1)
	}
}

// LoadState reads the state. A state that cannot be decoded is logged and
// started over (ADR 0006); an API error is returned.
func (t *Tracker) LoadState(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.init()
	t.started = t.now()
	st, err := t.Store.Load(ctx)
	if st == nil {
		return err
	}
	if err != nil {
		t.Log.Error(err, "the saved state could not be read; starting over")
	}
	t.state = st
	return nil
}

// Snapshot returns the latest evaluation, or false before the first.
func (t *Tracker) Snapshot() (Snapshot, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshot, t.hasSnapshot
}

// Trigger asks for an evaluation soon. It never blocks.
func (t *Tracker) Trigger() {
	t.mu.Lock()
	t.init()
	ch := t.trigger
	t.mu.Unlock()
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (t *Tracker) today(now time.Time) string {
	loc := t.Location
	if loc == nil {
		loc = time.UTC
	}
	return now.In(loc).Format(time.DateOnly)
}

// EvaluateOnce reads the cluster, decides every finding and saves the state
// if it is due.
func (t *Tracker) EvaluateOnce(ctx context.Context) {
	reports, pods, err := t.Source.List(ctx)
	if err != nil {
		t.Log.Error(err, "listing VulnerabilityReports and Pods")
		return
	}
	now := t.now()

	t.mu.Lock()
	t.init()
	t.images = t.inventory.Build(reports, RunningDigests(pods))
	vexOnly := map[string]bool{}
	for u, f := range t.prFiles {
		vexOnly[u] = f.vexOnly
	}
	var renovate *regexp.Regexp
	if t.Discoverer != nil {
		renovate = t.Discoverer.RenovateAuthor
	}
	t.snapshot = Evaluate(Input{
		Images:        t.images,
		Candidates:    t.candidates,
		Scans:         t.scans,
		VEX:           t.vex,
		State:         t.state,
		Now:           now,
		Today:         t.today(now),
		ManifestRepos: t.repoIndexes,
		PullRequests:  PullRequests{Open: t.openPRs, Replies: t.replies, VEXOnly: vexOnly, Renovate: renovate},
		Synced:        t.synced,
	})
	t.hasSnapshot = true
	t.stateDirty = true
	save := t.lastSave.IsZero() || now.Sub(t.lastSave) >= stateSaveInterval
	t.mu.Unlock()

	if save {
		t.saveState(ctx)
	}
}

func (t *Tracker) saveState(ctx context.Context) {
	t.mu.Lock()
	if !t.stateDirty {
		t.mu.Unlock()
		return
	}
	b, err := state.Encode(t.state)
	t.mu.Unlock()
	if err != nil {
		t.Log.Error(err, "encoding the state")
		return
	}
	// Save a copy, so the evaluation can go on while it is written.
	snap, err := state.Decode(b)
	if err != nil {
		t.Log.Error(err, "copying the state")
		return
	}
	if err := t.Store.Save(ctx, snap); err != nil {
		t.Log.Error(err, "saving the state")
		return
	}
	t.mu.Lock()
	t.stateDirty = false
	t.lastSave = t.now()
	t.mu.Unlock()
}

// SyncOnce reads the repositories when their interval has passed, and
// discovers the candidates of every running version. Registry reads are
// cached by the Discoverer, so running this often is cheap.
func (t *Tracker) SyncOnce(ctx context.Context) {
	now := t.now()
	t.mu.Lock()
	t.init()
	gitDue := t.lastGit.IsZero() || t.GitInterval <= 0 || now.Sub(t.lastGit) >= t.GitInterval
	images := append([]Image(nil), t.images...)
	world := t.world
	t.mu.Unlock()

	if gitDue {
		world = t.syncGit(ctx)
		t.mu.Lock()
		t.lastGit = now
		t.mu.Unlock()
	}

	cands := make(map[string]Candidates, len(images))
	names := map[string]bool{}
	failed := 0
	for _, img := range images {
		c := t.Discoverer.Discover(ctx, img, world)
		cands[img.Key()] = c
		names[img.Ref.Name()] = true
		if c.DiscoveryFailed {
			failed++
		}
	}
	t.Discoverer.Forget(names)
	if t.Metrics != nil {
		if failed > 0 {
			t.Metrics.SyncErrors.WithLabelValues("registry").Add(float64(failed))
		}
		if len(images) > failed {
			t.Metrics.SyncTimestamp.WithLabelValues("registry").SetToCurrentTime()
		}
	}

	if gitDue {
		t.syncPullRequests(ctx, images, cands)
	}

	t.mu.Lock()
	t.candidates = cands
	t.synced = true
	wanted := map[string]bool{}
	for _, c := range cands {
		for _, r := range c.List {
			wanted[r.Digest] = true
		}
	}
	for d := range t.scans {
		if !wanted[d] {
			delete(t.scans, d)
		}
	}
	t.mu.Unlock()
}

// syncGit reads every repository whose head moved, and rebuilds what
// discovery and evaluation read from them.
func (t *Tracker) syncGit(ctx context.Context) World {
	repos := append([]Repo(nil), t.Manifests...)
	if !containsRepo(repos, t.FleetInfra) && t.FleetInfra.Name != "" {
		repos = append(repos, t.FleetInfra)
	}
	for _, r := range repos {
		target := targetName(r.Name)
		sha, err := t.GitHub.Head(ctx, r.Name, r.Branch)
		if err == nil {
			t.mu.Lock()
			changed := t.heads[r.Name] != sha
			t.mu.Unlock()
			if changed {
				var files map[string][]byte
				files, err = t.GitHub.Files(ctx, r.Name, sha)
				if err == nil {
					t.mu.Lock()
					t.heads[r.Name], t.files[r.Name] = sha, files
					t.mu.Unlock()
				}
			}
		}
		if err == nil {
			var p []github.PullRequest
			if p, err = t.GitHub.OpenPullRequests(ctx, r.Name); err == nil {
				t.mu.Lock()
				t.openPRs[r.Name] = p
				t.mu.Unlock()
			}
		}
		if err != nil {
			t.Log.Error(err, "reading a repository", "repository", r.Name)
			if t.Metrics != nil {
				t.Metrics.SyncErrors.WithLabelValues(target).Inc()
			}
			continue
		}
		if t.Metrics != nil {
			t.Metrics.SyncTimestamp.WithLabelValues(target).SetToCurrentTime()
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	var idx []manifests.Index
	t.repoIndexes = nil
	var prs []github.PullRequest
	for _, r := range repos {
		// A repository that could not be read keeps its last list.
		prs = append(prs, t.openPRs[r.Name]...)
	}
	for _, r := range t.Manifests {
		ix := manifests.Build(t.files[r.Name])
		idx = append(idx, ix)
		t.repoIndexes = append(t.repoIndexes, RepoIndex{Name: r.Name, Index: ix})
	}
	w := World{Manifests: manifests.Merge(idx...), PullRequests: prs, Sources: t.world.Sources}
	fleet := t.files[t.FleetInfra.Name]
	if fleet != nil {
		if tbl, err := sources.Parse(fleet[sources.Path]); err != nil {
			t.Log.Error(err, "reading the image-sources table; keeping the previous one")
			if t.Metrics != nil {
				t.Metrics.SyncErrors.WithLabelValues("vex").Inc()
			}
		} else {
			w.Sources = tbl
		}
		set, errs := annotation.Load(fleet)
		for _, err := range errs {
			t.Log.Error(err, "leaving out a VEX statement")
		}
		if t.Metrics != nil && len(errs) > 0 {
			t.Metrics.SyncErrors.WithLabelValues("vex").Add(float64(len(errs)))
		}
		t.vex = set
	}
	t.world = w
	return w
}

// prFiles is what the files of a pull request said at one head.
type prFiles struct {
	head    string
	vexOnly bool
}

// vexOnly says whether a pull request changes only VEX documents.
func vexOnly(files []string) bool {
	if len(files) == 0 {
		return false
	}
	for _, f := range files {
		if !strings.HasPrefix(f, annotation.Dir) {
			return false
		}
	}
	return true
}

// syncPullRequests reads what the two axes link (ADR 0014): the open pull
// requests of every self-built image's source repository, the state of every
// pull request vuln-responder replied with, and the files of the manifest
// repositories' pull requests that may only annotate. A read that fails
// keeps what was read before.
func (t *Tracker) syncPullRequests(ctx context.Context, images []Image, cands map[string]Candidates) {
	sources := map[string]bool{}
	for _, img := range images {
		c, ok := cands[img.Key()]
		if !ok || c.Origin != stage.SelfBuilt {
			continue
		}
		if repo, ok := sourceRepository(c.Source); ok {
			sources[repo] = true
		}
	}
	manifestRepos := map[string]bool{t.FleetInfra.Name: true}
	for _, r := range t.Manifests {
		manifestRepos[r.Name] = true
	}
	failed := 0
	for _, repo := range slices.Sorted(maps.Keys(sources)) {
		if manifestRepos[repo] {
			continue // read with the manifests
		}
		prs, err := t.GitHub.OpenPullRequests(ctx, repo)
		if err != nil {
			t.Log.Error(err, "reading the pull requests of a source repository", "repository", repo)
			failed++
			continue
		}
		t.mu.Lock()
		t.openPRs[repo] = prs
		t.mu.Unlock()
	}

	t.mu.Lock()
	for repo := range t.openPRs {
		if !sources[repo] && !manifestRepos[repo] {
			delete(t.openPRs, repo)
		}
	}
	wantReplies := map[string]bool{}
	if t.state != nil {
		for _, rec := range t.state.Requests {
			if rec.PR != "" {
				wantReplies[rec.PR] = true
			}
		}
	}
	for u := range t.replies {
		if !wantReplies[u] {
			delete(t.replies, u)
		}
	}
	var toRead []string
	for u := range wantReplies {
		// A merged pull request stays merged.
		if t.replies[u].State != github.StateMerged {
			toRead = append(toRead, u)
		}
	}
	t.mu.Unlock()

	sort.Strings(toRead)
	for _, u := range toRead {
		repo, n, ok := github.ParsePullRequestURL(u)
		if !ok {
			continue
		}
		pr, err := t.GitHub.PullRequest(ctx, repo, n)
		if err != nil {
			t.Log.Error(err, "reading a pull request vuln-responder replied with", "url", u)
			failed++
			continue
		}
		t.mu.Lock()
		t.replies[u] = pr
		t.mu.Unlock()
	}

	// Only the pull requests that may annotate are looked into: those in a
	// manifest repository that Renovate did not open.
	t.mu.Lock()
	var renovate *regexp.Regexp
	if t.Discoverer != nil {
		renovate = t.Discoverer.RenovateAuthor
	}
	candidates := map[string]github.PullRequest{}
	for repo, prs := range t.openPRs {
		if !manifestRepos[repo] {
			continue
		}
		for _, p := range prs {
			if renovate == nil || !renovate.MatchString(p.Author) {
				candidates[p.URL] = p
			}
		}
	}
	for u, p := range t.replies {
		if manifestRepos[p.Repository] {
			candidates[u] = p
		}
	}
	for u := range t.prFiles {
		if _, ok := candidates[u]; !ok {
			delete(t.prFiles, u)
		}
	}
	var look []github.PullRequest
	for _, u := range slices.Sorted(maps.Keys(candidates)) {
		p := candidates[u]
		if f, ok := t.prFiles[u]; !ok || f.head != p.HeadSHA {
			look = append(look, p)
		}
	}
	t.mu.Unlock()

	for _, p := range look {
		files, err := t.GitHub.PullRequestFiles(ctx, p.Repository, p.Number)
		if err != nil {
			t.Log.Error(err, "reading the files of a pull request", "url", p.URL)
			failed++
			continue
		}
		t.mu.Lock()
		t.prFiles[p.URL] = prFiles{head: p.HeadSHA, vexOnly: vexOnly(files)}
		t.mu.Unlock()
	}
	if t.Metrics != nil {
		if failed > 0 {
			t.Metrics.SyncErrors.WithLabelValues(syncTargetPullRequests).Add(float64(failed))
		} else {
			t.Metrics.SyncTimestamp.WithLabelValues(syncTargetPullRequests).SetToCurrentTime()
		}
	}
}

// syncTargetPullRequests is the `target` label of the source repositories'
// and vuln-responder's pull requests (ADR 0005).
const syncTargetPullRequests = "pull-requests"

func containsRepo(rs []Repo, r Repo) bool {
	for _, x := range rs {
		if x.Name == r.Name {
			return true
		}
	}
	return false
}

// targetName is the `target` label of a repository: its name without the
// owner.
func targetName(repo string) string {
	return repo[strings.LastIndex(repo, "/")+1:]
}

// NextScan picks the candidate to scan next: one never scanned, else the one
// whose result is oldest past its time. wanted are "name@digest".
func NextScan(wanted []string, results map[string]ScanResult, now time.Time) (string, bool) {
	best, bestAt := "", time.Time{}
	for _, ref := range wanted {
		_, d, _ := strings.Cut(ref, "@")
		r, ok := results[d]
		if !ok {
			return ref, true
		}
		ttl := scanTTL
		if r.Err != nil {
			ttl = scanRetry
		}
		if now.Sub(r.At) < ttl {
			continue
		}
		if best == "" || r.At.Before(bestAt) {
			best, bestAt = ref, r.At
		}
	}
	return best, best != ""
}

// ScanOnce scans the next candidate that is due, and reports whether there
// was one.
func (t *Tracker) ScanOnce(ctx context.Context) bool {
	t.mu.Lock()
	var wanted []string
	for _, img := range t.images {
		c, ok := t.candidates[img.Key()]
		if !ok {
			continue
		}
		for _, r := range c.List {
			wanted = append(wanted, r.Ref(img.Ref.Name()))
		}
	}
	sort.Strings(wanted)
	ref, ok := NextScan(wanted, t.scans, t.now())
	t.mu.Unlock()
	if !ok {
		return false
	}

	start := time.Now()
	set, err := t.Scanner.Scan(ctx, ref)
	if errors.Is(ctx.Err(), context.Canceled) {
		return false
	}
	result := "success"
	if err != nil {
		result = "failure"
		t.Log.Error(err, "scanning a candidate", "image", ref)
	}
	if t.Metrics != nil {
		t.Metrics.Scans.WithLabelValues(result).Inc()
		t.Metrics.ScanDuration.Observe(time.Since(start).Seconds())
	}
	_, d, _ := strings.Cut(ref, "@")
	t.mu.Lock()
	t.scans[d] = ScanResult{At: t.now(), Set: set, Err: err}
	t.mu.Unlock()
	return true
}

// digestItems turns the findings of the detailed severities into digest
// items.
func (t *Tracker) digestItems(snap Snapshot) []digest.Item {
	var items []digest.Item
	for _, f := range snap.Findings {
		if !t.DetailSeverities[f.Vuln.Severity] {
			continue
		}
		it := digest.Item{
			Key:             f.Key(),
			Image:           f.Image.Name(),
			Tag:             f.Image.Tag,
			VulnerabilityID: f.Vuln.ID,
			Package:         f.Vuln.Package,
			Severity:        f.Vuln.Severity,
			Stage:           string(f.Stage),
			Fixable:         f.Fixable,
			VexState:        f.VexState(),
			VexExpired:      f.VexExpired,
			FirstSeen:       f.FirstSeen,
		}
		if f.Annotation != nil {
			it.ReviewBy, it.Reason = f.Annotation.ReviewBy, f.Annotation.Reason
		}
		items = append(items, it)
	}
	return items
}

// DigestOnce sends the weekly digest if it is due (ADR 0006).
func (t *Tracker) DigestOnce(ctx context.Context) {
	if t.Slack == nil {
		return
	}
	now := t.now()
	t.mu.Lock()
	if !t.hasSnapshot || now.Before(t.digestNext) {
		t.mu.Unlock()
		return
	}
	base := t.started
	if t.state.Digest.SentAt > 0 {
		base = time.Unix(t.state.Digest.SentAt, 0)
	}
	if now.Before(t.Schedule.Next(base)) {
		t.mu.Unlock()
		return
	}
	report := digest.Build(t.digestItems(t.snapshot), t.state.Digest)
	report.Requests = digestRequests(t.state.Requests, t.state.Digest.SentAt)
	t.mu.Unlock()

	text := digest.Render(report, digest.Options{DashboardURL: t.DashboardURL, VEXBaseURL: t.VEXBaseURL, Responder: t.Responder != nil})
	if err := t.Slack.Send(ctx, text); err != nil {
		t.Log.Error(err, "sending the weekly digest; retrying later")
		t.mu.Lock()
		t.digestNext = now.Add(digestRetry)
		t.mu.Unlock()
		return
	}
	t.Log.Info("sent the weekly digest", "new", len(report.New), "advanced", len(report.Advanced), "expired", len(report.Expired))
	t.mu.Lock()
	t.state.Digest = state.Digest{SentAt: now.Unix(), Findings: report.Snapshot()}
	t.stateDirty = true
	t.mu.Unlock()
	if t.Metrics != nil {
		t.Metrics.DigestSent.Set(float64(now.Unix()))
	}
	t.saveState(ctx)
}

// NeedLeaderElection keeps the tracker to the leader when leader election is
// turned on (ADR 0001).
func (t *Tracker) NeedLeaderElection() bool { return true }

// Start runs the loops until ctx is done. It implements manager.Runnable.
func (t *Tracker) Start(ctx context.Context) error {
	for {
		err := t.LoadState(ctx)
		if err == nil {
			break
		}
		t.Log.Error(err, "loading the state; retrying")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(30 * time.Second):
		}
	}
	if t.Slack == nil {
		t.Log.Info("no Slack webhook is configured; the weekly digest will not be sent")
	}
	if t.Responder == nil {
		t.Log.Info("no vuln-responder is configured; nothing will be asked of it")
	}

	var wg sync.WaitGroup
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}
	run(func() { t.evaluateLoop(ctx) })
	run(func() { t.every(ctx, t.loopInterval(), t.SyncOnce) })
	run(func() { t.scanLoop(ctx) })
	run(func() { t.every(ctx, t.loopInterval(), t.DigestOnce) })
	if t.Responder != nil {
		poll := t.ResponderPollInterval
		if poll <= 0 {
			poll = t.loopInterval()
		}
		run(func() { t.every(ctx, poll, t.RespondOnce) })
	}
	<-ctx.Done()
	wg.Wait()
	// One last write, so a restart loses as little as possible.
	t.saveState(context.WithoutCancel(ctx))
	return nil
}

func (t *Tracker) loopInterval() time.Duration {
	if t.LoopInterval > 0 {
		return t.LoopInterval
	}
	return time.Minute
}

func (t *Tracker) every(ctx context.Context, d time.Duration, f func(context.Context)) {
	tick := time.NewTicker(d)
	defer tick.Stop()
	for {
		f(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (t *Tracker) evaluateLoop(ctx context.Context) {
	t.mu.Lock()
	t.init()
	trigger := t.trigger
	t.mu.Unlock()
	tick := time.NewTicker(t.loopInterval())
	defer tick.Stop()
	for {
		t.EvaluateOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-trigger:
			// Reports and Pods change in bursts; let a burst settle.
			select {
			case <-ctx.Done():
				return
			case <-time.After(min(5*time.Second, t.loopInterval())):
			}
		}
	}
}

func (t *Tracker) scanLoop(ctx context.Context) {
	for {
		pause := t.loopInterval()
		if t.ScanOnce(ctx) && t.ScanInterval > 0 {
			pause = t.ScanInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
	}
}
