package responder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/vuln-tracker/internal/state"
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// fakeA2A is vuln-responder as the requester sees it: tasks it numbers itself,
// whose states the test moves along.
type fakeA2A struct {
	sent     []Message
	gets     []string
	tasks    map[string]*Task
	contexts map[string]bool
	sendErr  error
	getErr   error
	n        int
}

func newFake() *fakeA2A {
	return &fakeA2A{tasks: map[string]*Task{}, contexts: map[string]bool{}}
}

func (f *fakeA2A) Send(_ context.Context, m Message) (Task, error) {
	f.sent = append(f.sent, m)
	if f.sendErr != nil {
		return Task{}, f.sendErr
	}
	if m.ContextID != "" && !f.contexts[m.ContextID] {
		return Task{}, &RPCError{Code: -32602, Message: "Unknown contextId"}
	}
	f.n++
	ctxID := m.ContextID
	if ctxID == "" {
		ctxID = fmt.Sprintf("ctx-%d", f.n)
		f.contexts[ctxID] = true
	}
	task := &Task{ID: fmt.Sprintf("task-%d", f.n), ContextID: ctxID, State: "submitted"}
	f.tasks[task.ID] = task
	return *task, nil
}

func (f *fakeA2A) Get(_ context.Context, id string) (Task, error) {
	f.gets = append(f.gets, id)
	if f.getErr != nil {
		return Task{}, f.getErr
	}
	task, ok := f.tasks[id]
	if !ok {
		return Task{}, &RPCError{Code: -32001, Message: "Task not found"}
	}
	return *task, nil
}

func (f *fakeA2A) finish(id, state string, texts ...string) {
	f.tasks[id].State = state
	f.tasks[id].Texts = texts
}

func (f *fakeA2A) lastData(t *testing.T) Payload {
	t.Helper()
	p, ok := f.sent[len(f.sent)-1].Data.(Payload)
	if !ok {
		t.Fatalf("data part is %T", f.sent[len(f.sent)-1].Data)
	}
	return p
}

func finding(image, id, pkg, digest string) Finding {
	return Finding{
		VulnerabilityID: id, Severity: "CRITICAL", Package: pkg, InstalledVersion: "1.0", FixedVersion: "1.1",
		Stage: "unfixed", VexState: "none", Image: image, Tag: "v1", Digest: digest, Trigger: TriggerTriage,
		Workloads: []Workload{{Namespace: "ns", Kind: "ReplicaSet", Name: "app-1", Container: "app"}},
	}
}

// bumped is a finding whose stage reached a fixed version (ADR 0011).
func bumped(f Finding, st, tag, digest string, renovate ...string) Finding {
	f.Trigger, f.Stage, f.FixedInTag, f.FixedInDigest, f.RenovatePRs = TriggerBump, st, tag, digest, renovate
	return f
}

const hshelfImage = "ghcr.io/yuanying/hshelf"

func hshelfWanted(findings ...Finding) Wanted {
	return Wanted{Target: Target{Type: "source", Repository: "yuanying/hshelf"}, Findings: findings}
}

func longhornWanted(findings ...Finding) Wanted {
	return Wanted{Target: Target{Type: "image", Image: "index.docker.io/longhornio/longhorn-engine"}, Findings: findings}
}

func newRequester(f *fakeA2A) *Requester {
	return &Requester{Client: f, Mode: "vex-only", DashboardURL: "https://grafana.example/d/vuln", TaskTimeout: 3 * time.Hour, Log: logr.Discard()}
}

func TestStepNothingWanted(t *testing.T) {
	f := newFake()
	r := newRequester(f)
	recs := map[string]state.Request{}
	if r.Step(context.Background(), t0, nil, recs) {
		t.Error("changed with nothing wanted")
	}
	if len(f.sent) != 0 || len(recs) != 0 {
		t.Errorf("sent %v, records %v", f.sent, recs)
	}
}

func TestStepOneAtATimeAndDedup(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRequester(f)
	recs := map[string]state.Request{}
	cve1 := finding(hshelfImage, "CVE-1", "json", "sha256:aa")
	wanted := []Wanted{
		longhornWanted(finding("index.docker.io/longhornio/longhorn-engine", "CVE-9", "openssl", "sha256:ff")),
		hshelfWanted(cve1),
	}

	// The first target by name is sent.
	if !r.Step(ctx, t0, wanted, recs) {
		t.Fatal("no change after sending")
	}
	if len(f.sent) != 1 {
		t.Fatalf("sent %d", len(f.sent))
	}
	if p := f.lastData(t); p.Target.Image == nil || *p.Target.Image != "index.docker.io/longhornio/longhorn-engine" {
		t.Errorf("first request went to %+v", p.Target)
	}
	img := recs["image:index.docker.io/longhornio/longhorn-engine"]
	if img.TaskID != "task-1" || img.ContextID != "ctx-1" || img.State != "submitted" || img.SentAt != t0.Unix() {
		t.Errorf("record = %+v", img)
	}

	// While it runs, nothing else is sent; the task is looked at.
	f.tasks["task-1"].State = "working"
	r.Step(ctx, t0.Add(time.Minute), wanted, recs)
	if len(f.sent) != 1 || len(f.gets) != 1 {
		t.Fatalf("sent %d, got %d", len(f.sent), len(f.gets))
	}
	if recs["image:index.docker.io/longhornio/longhorn-engine"].State != "working" {
		t.Error("the state did not follow the task")
	}

	// Once it is done, the next target goes out.
	f.finish("task-1", "completed", "注釈の PR を出した: https://github.com/yuanying/fleet-infra/pull/240")
	r.Step(ctx, t0.Add(2*time.Minute), wanted, recs)
	img = recs["image:index.docker.io/longhornio/longhorn-engine"]
	if img.State != "completed" || img.PR != "https://github.com/yuanying/fleet-infra/pull/240" || !slices.Equal(img.Asked, []string{"index.docker.io/longhornio/longhorn-engine|CVE-9|openssl"}) {
		t.Errorf("completed record = %+v", img)
	}
	if img.Summary != "注釈の PR を出した: https://github.com/yuanying/fleet-infra/pull/240" {
		t.Errorf("summary = %q", img.Summary)
	}
	if len(f.sent) != 1 {
		t.Fatal("finishing a task and sending the next happen on separate steps")
	}
	r.Step(ctx, t0.Add(3*time.Minute), wanted, recs)
	if len(f.sent) != 2 {
		t.Fatalf("the second target was not sent")
	}
	f.finish("task-2", "completed", "判断できなかった。理由: ...")
	r.Step(ctx, t0.Add(4*time.Minute), wanted, recs)
	src := recs["source:yuanying/hshelf"]
	if src.State != "completed" || src.PR != "" {
		t.Errorf("record = %+v", src)
	}

	// The same findings in a new digest are not asked again.
	moved := []Wanted{hshelfWanted(finding(hshelfImage, "CVE-1", "json", "sha256:bb"))}
	for i := range 3 {
		r.Step(ctx, t0.Add(time.Duration(5+i)*time.Minute), moved, recs)
	}
	if len(f.sent) != 2 {
		t.Fatalf("asked again for the same findings: %d", len(f.sent))
	}

	// A new finding asks again, with every finding of the target, in the
	// same context.
	grown := []Wanted{hshelfWanted(cve1, finding(hshelfImage, "CVE-2", "openssl", "sha256:aa"))}
	r.Step(ctx, t0.Add(10*time.Minute), grown, recs)
	if len(f.sent) != 3 {
		t.Fatal("a new finding was not asked for")
	}
	if f.sent[2].ContextID != "ctx-2" {
		t.Errorf("contextId = %q, want the target's own", f.sent[2].ContextID)
	}
	if p := f.lastData(t); len(p.Findings) != 2 {
		t.Errorf("findings = %+v", p.Findings)
	}
	if src := recs["source:yuanying/hshelf"]; src.PR != "" || src.Summary != "" || src.State != "submitted" {
		t.Errorf("a new request starts afresh: %+v", src)
	}
}

func TestStepRetries(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.sendErr = errors.New("connection refused")
	r := newRequester(f)
	recs := map[string]state.Request{}
	wanted := []Wanted{hshelfWanted(finding(hshelfImage, "CVE-1", "json", "sha256:aa"))}
	const key = "source:yuanying/hshelf"

	clock := t0
	r.Step(ctx, clock, wanted, recs)
	rec := recs[key]
	if rec.State != "error" || rec.Attempts != 1 || rec.NextAttempt != clock.Add(10*time.Minute).Unix() {
		t.Fatalf("record = %+v", rec)
	}
	// Not before the backoff.
	r.Step(ctx, clock.Add(9*time.Minute), wanted, recs)
	if len(f.sent) != 1 {
		t.Fatal("retried before the backoff")
	}
	// The backoff doubles: 10, 20, 40, 80 minutes, and the fifth failure
	// gives up.
	for i, wait := range []time.Duration{10 * time.Minute, 20 * time.Minute, 40 * time.Minute, 80 * time.Minute} {
		clock = clock.Add(wait)
		r.Step(ctx, clock, wanted, recs)
		if len(f.sent) != i+2 {
			t.Fatalf("attempt %d was not made", i+2)
		}
	}
	rec = recs[key]
	if rec.State != "error" || rec.Attempts != 0 || !slices.Equal(rec.Asked, []string{hshelfImage + "|CVE-1|json"}) {
		t.Errorf("after giving up: %+v", rec)
	}
	f.sendErr = nil
	r.Step(ctx, clock.Add(24*time.Hour), wanted, recs)
	if len(f.sent) != 5 {
		t.Error("asked again after giving up on the same findings")
	}
}

func TestStepTaskFailures(t *testing.T) {
	ctx := context.Background()
	wanted := []Wanted{hshelfWanted(finding(hshelfImage, "CVE-1", "json", "sha256:aa"))}
	const key = "source:yuanying/hshelf"

	for _, tc := range []struct {
		state   string
		retried bool
	}{
		{"failed", true},
		{"rejected", true},
		{"canceled", false},
	} {
		t.Run(tc.state, func(t *testing.T) {
			f := newFake()
			r := newRequester(f)
			recs := map[string]state.Request{}
			r.Step(ctx, t0, wanted, recs)
			f.finish("task-1", tc.state)
			r.Step(ctx, t0.Add(time.Minute), wanted, recs)
			if got := recs[key].State; got != tc.state {
				t.Errorf("state = %q", got)
			}
			r.Step(ctx, t0.Add(time.Hour), wanted, recs)
			if retried := len(f.sent) == 2; retried != tc.retried {
				t.Errorf("retried = %v, want %v", retried, tc.retried)
			}
		})
	}
}

func TestStepTimeout(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRequester(f)
	recs := map[string]state.Request{}
	wanted := []Wanted{hshelfWanted(finding(hshelfImage, "CVE-1", "json", "sha256:aa"))}
	r.Step(ctx, t0, wanted, recs)
	f.tasks["task-1"].State = "working"
	r.Step(ctx, t0.Add(2*time.Hour), wanted, recs)
	if recs["source:yuanying/hshelf"].State != "working" {
		t.Fatal("gave up before the time limit")
	}
	r.Step(ctx, t0.Add(3*time.Hour+time.Second), wanted, recs)
	rec := recs["source:yuanying/hshelf"]
	if rec.State != "timeout" || rec.Attempts != 1 {
		t.Errorf("record = %+v", rec)
	}
}

func TestStepLostTask(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRequester(f)
	recs := map[string]state.Request{}
	wanted := []Wanted{hshelfWanted(finding(hshelfImage, "CVE-1", "json", "sha256:aa"))}
	r.Step(ctx, t0, wanted, recs)

	// A network error while looking leaves the task running.
	f.getErr = errors.New("connection reset")
	r.Step(ctx, t0.Add(time.Minute), wanted, recs)
	if recs["source:yuanying/hshelf"].State != "submitted" {
		t.Errorf("a transient error ended the task: %+v", recs["source:yuanying/hshelf"])
	}
	// The host no longer knowing the task is a failure.
	f.getErr = nil
	delete(f.tasks, "task-1")
	r.Step(ctx, t0.Add(2*time.Minute), wanted, recs)
	if rec := recs["source:yuanying/hshelf"]; rec.State != "error" || rec.Attempts != 1 {
		t.Errorf("record = %+v", rec)
	}
}

// The host numbers contexts and forgets unused ones; a context it no longer
// knows starts a new one.
func TestStepForgottenContext(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRequester(f)
	recs := map[string]state.Request{
		"source:yuanying/hshelf": {TargetType: "source", Target: "yuanying/hshelf", ContextID: "ctx-gone", State: "completed"},
	}
	r.Step(ctx, t0, []Wanted{hshelfWanted(finding(hshelfImage, "CVE-1", "json", "sha256:aa"))}, recs)
	if len(f.sent) != 2 || f.sent[0].ContextID != "ctx-gone" || f.sent[1].ContextID != "" {
		t.Fatalf("sent %+v", f.sent)
	}
	if rec := recs["source:yuanying/hshelf"]; rec.ContextID != "ctx-1" || rec.State != "submitted" {
		t.Errorf("record = %+v", rec)
	}
}

func TestStepRunningTaskOfAnotherTargetBlocks(t *testing.T) {
	// After a restart the running task is found in the records, even when its
	// target is no longer wanted.
	f := newFake()
	f.tasks["task-0"] = &Task{ID: "task-0", ContextID: "ctx-0", State: "working"}
	r := newRequester(f)
	recs := map[string]state.Request{
		"image:quay.io/x/y": {TargetType: "image", Target: "quay.io/x/y", ContextID: "ctx-0", TaskID: "task-0", State: "working", SentAt: t0.Unix()},
	}
	r.Step(context.Background(), t0.Add(time.Minute), []Wanted{hshelfWanted(finding(hshelfImage, "CVE-1", "json", "sha256:aa"))}, recs)
	if len(f.sent) != 0 || !slices.Equal(f.gets, []string{"task-0"}) {
		t.Errorf("sent %v, got %v", f.sent, f.gets)
	}
}

func TestPayloadShape(t *testing.T) {
	w := Wanted{
		Target: Target{Type: "source", Repository: "yuanying/hshelf"},
		Findings: []Finding{
			finding("ghcr.io/yuanying/tumblr-like", "CVE-2", "json", "sha256:bb"),
			finding(hshelfImage, "CVE-1", "json", "sha256:aa"),
		},
	}
	text, data := Build(w, "vex-only", "https://grafana.example/d/vuln")
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"vuln-triage/v1","mode":"vex-only",` +
		`"target":{"type":"source","repository":"yuanying/hshelf","image":null},` +
		`"findings":[` +
		`{"vulnerabilityID":"CVE-1","severity":"CRITICAL","package":"json","installedVersion":"1.0","fixedVersion":"1.1","stage":"unfixed","vexState":"none","image":"ghcr.io/yuanying/hshelf","tag":"v1","digest":"sha256:aa","trigger":"triage","workloads":[{"namespace":"ns","kind":"ReplicaSet","name":"app-1","container":"app"}]},` +
		`{"vulnerabilityID":"CVE-2","severity":"CRITICAL","package":"json","installedVersion":"1.0","fixedVersion":"1.1","stage":"unfixed","vexState":"none","image":"ghcr.io/yuanying/tumblr-like","tag":"v1","digest":"sha256:bb","trigger":"triage","workloads":[{"namespace":"ns","kind":"ReplicaSet","name":"app-1","container":"app"}]}` +
		`],"dashboard":"https://grafana.example/d/vuln","vexFile":"security/vex/ghcr.io/yuanying/hshelf.openvex.json"}`
	if string(b) != want {
		t.Errorf("payload:\n got %s\nwant %s", b, want)
	}

	for _, s := range []string{"yuanying/hshelf", "vex-only", "CVE-1", "CVE-2", "ghcr.io/yuanying/tumblr-like:v1", "json 1.0 → 1.1", "ns/ReplicaSet/app-1", "https://grafana.example/d/vuln", "PR"} {
		if !strings.Contains(text, s) {
			t.Errorf("text lacks %q:\n%s", s, text)
		}
	}

	_, data = Build(longhornWanted(finding("index.docker.io/longhornio/longhorn-engine", "CVE-9", "openssl", "sha256:ff")), "fix", "")
	b, _ = json.Marshal(data)
	for _, s := range []string{`"mode":"fix"`, `"target":{"type":"image","repository":null,"image":"index.docker.io/longhornio/longhorn-engine"}`, `"vexFile":"security/vex/index.docker.io/longhornio/longhorn-engine.openvex.json"`, `"dashboard":""`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("payload lacks %s: %s", s, b)
		}
	}
}

func TestFindingKey(t *testing.T) {
	f := finding(hshelfImage, "CVE-1", "json", "sha256:aa")
	tests := []struct {
		f    Finding
		want string
	}{
		{f, hshelfImage + "|CVE-1|json"},
		{bumped(f, "fixed-in-release", "v1.0.1", "sha256:bb"), hshelfImage + "|CVE-1|json|fixed-in-release"},
		{bumped(f, "fixed-upstream", "v1.0.1", "sha256:bb"), hshelfImage + "|CVE-1|json|fixed-upstream"},
	}
	for _, tc := range tests {
		if got := tc.f.Key(); got != tc.want {
			t.Errorf("Key(%s %s) = %q, want %q", tc.f.Trigger, tc.f.Stage, got, tc.want)
		}
	}
}

// A finding asked about as new is asked about once more when its stage
// reaches a fixed version, and only once (ADR 0011).
func TestStepBumpAfterTriage(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	r := newRequester(f)
	recs := map[string]state.Request{}
	const key = "source:yuanying/hshelf"
	cve1 := finding(hshelfImage, "CVE-1", "json", "sha256:aa")

	r.Step(ctx, t0, []Wanted{hshelfWanted(cve1)}, recs)
	f.finish("task-1", "completed", "直す PR を出した: https://github.com/yuanying/hshelf/pull/12")
	r.Step(ctx, t0.Add(time.Minute), nil, recs)

	released := []Wanted{hshelfWanted(bumped(cve1, "fixed-in-release", "v1.0.1", "sha256:bb"))}
	r.Step(ctx, t0.Add(2*time.Minute), released, recs)
	if len(f.sent) != 2 {
		t.Fatalf("the release was not asked about: sent %d", len(f.sent))
	}
	if f.sent[1].ContextID != "ctx-1" {
		t.Errorf("contextId = %q, want the target's own", f.sent[1].ContextID)
	}
	if p := f.lastData(t); p.Findings[0].Trigger != TriggerBump || p.Findings[0].FixedInTag != "v1.0.1" {
		t.Errorf("findings = %+v", p.Findings)
	}
	f.finish("task-2", "completed", "版上げの PR: https://github.com/yuanying/fleet-infra/pull/250")
	r.Step(ctx, t0.Add(3*time.Minute), released, recs)
	rec := recs[key]
	if rec.PR != "https://github.com/yuanying/fleet-infra/pull/250" ||
		!slices.Equal(rec.Asked, []string{hshelfImage + "|CVE-1|json", hshelfImage + "|CVE-1|json|fixed-in-release"}) {
		t.Errorf("record = %+v", rec)
	}

	// A newer release of the same finding is not asked about again.
	newer := []Wanted{hshelfWanted(bumped(cve1, "fixed-in-release", "v1.0.2", "sha256:cc"))}
	for i := range 3 {
		r.Step(ctx, t0.Add(time.Duration(4+i)*time.Minute), newer, recs)
	}
	if len(f.sent) != 2 {
		t.Errorf("asked again for the same stage: sent %d", len(f.sent))
	}
}

func TestBuildBump(t *testing.T) {
	longhorn := "index.docker.io/longhornio/longhorn-engine"
	old := finding(longhorn, "CVE-9", "openssl", "sha256:ff")
	old.VexState = "upstream"
	w := longhornWanted(
		bumped(old, "fixed-upstream", "v1.13.1", "sha256:11", "https://github.com/yuanying/fleet-infra/pull/245"),
		finding(longhorn, "CVE-10", "zlib", "sha256:ff"),
	)
	text, data := Build(w, "fix", "")
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`"trigger":"bump","fixedInTag":"v1.13.1","fixedInDigest":"sha256:11","renovatePRs":["https://github.com/yuanying/fleet-infra/pull/245"]`,
		`"vulnerabilityID":"CVE-10","severity":"CRITICAL","package":"zlib","installedVersion":"1.0","fixedVersion":"1.1","stage":"unfixed","vexState":"none","image":"index.docker.io/longhornio/longhorn-engine","tag":"v1","digest":"sha256:ff","trigger":"triage","workloads"`,
	} {
		if !strings.Contains(string(b), s) {
			t.Errorf("payload lacks %s:\n%s", s, b)
		}
	}
	for _, s := range []string{
		"直った版", "版を、その版に上げる PR", "v1.13.1", "sha256:11", "段階 fixed-upstream", "注釈 upstream",
		"https://github.com/yuanying/fleet-infra/pull/245", "それで足りるなら新しい PR は出さず",
		"新しく見つかった", "CVE-10",
	} {
		if !strings.Contains(text, s) {
			t.Errorf("text lacks %q:\n%s", s, text)
		}
	}

	// Only bumps: no section about new findings.
	text, _ = Build(longhornWanted(bumped(old, "fixed-upstream", "v1.13.1", "sha256:11")), "fix", "")
	if strings.Contains(text, "新しく見つかった") || strings.Contains(text, "Renovate") {
		t.Errorf("text of a bump alone:\n%s", text)
	}
}

func TestPullRequestURLAndSummary(t *testing.T) {
	tests := []struct {
		texts       []string
		pr, summary string
	}{
		{nil, "", ""},
		{[]string{"判断できなかった。\n理由は…"}, "", "判断できなかった。"},
		{[]string{"\n\nVEX を書いた\n", `{"sources":[{"url":"https://github.com/yuanying/fleet-infra/pull/7"}]}`}, "https://github.com/yuanying/fleet-infra/pull/7", "VEX を書いた"},
		{[]string{"see https://github.com/yuanying/fleet-infra/pull/240.", "https://github.com/yuanying/hshelf/pull/3"}, "https://github.com/yuanying/fleet-infra/pull/240", "see https://github.com/yuanying/fleet-infra/pull/240."},
		{[]string{strings.Repeat("あ", 300)}, "", strings.Repeat("あ", 200) + "…"},
	}
	for _, tc := range tests {
		if got := PullRequestURL(tc.texts); got != tc.pr {
			t.Errorf("PullRequestURL(%q) = %q, want %q", tc.texts, got, tc.pr)
		}
		if got := Summary(tc.texts); got != tc.summary {
			t.Errorf("Summary(%q) = %q, want %q", tc.texts, got, tc.summary)
		}
	}
}
