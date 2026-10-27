package tracker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yuanying/vuln-tracker/internal/annotation"
	"github.com/yuanying/vuln-tracker/internal/digest"
	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/responder"
	"github.com/yuanying/vuln-tracker/internal/stage"
	"github.com/yuanying/vuln-tracker/internal/state"
)

// responderSnapshot has one finding of each kind the request rule has to tell
// apart (ADR 0009).
func responderSnapshot() Snapshot {
	hshelf := imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: "sha256:aa"}
	workspace := imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/natsumi-workspace", Tag: "v2", Digest: "sha256:cc"}
	unknown := imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/nolabel", Tag: "v1", Digest: "sha256:dd"}
	longhorn := imageref.Ref{Registry: "index.docker.io", Repository: "longhornio/longhorn-engine", Tag: "v1.13.0", Digest: "sha256:ee"}
	day := int64(24 * 60 * 60)
	recent := now.Unix() - day
	crit := func(img imageref.Ref, id string, st stage.Stage, firstSeen int64) Finding {
		return Finding{Image: img, Vuln: Vuln{ID: id, Package: "json", InstalledVersion: "2.18.0", FixedVersion: "2.19.2", Severity: "CRITICAL"}, Stage: st, Fixable: true, FirstSeen: firstSeen}
	}
	annotated := crit(hshelf, "CVE-ANNOTATED", stage.Unfixed, recent)
	annotated.Annotation = &annotation.Annotation{State: "upstream"}
	high := crit(hshelf, "CVE-HIGH", stage.Unfixed, recent)
	high.Vuln.Severity = "HIGH"
	unfixable := crit(hshelf, "CVE-UNFIXABLE", stage.Unfixed, recent)
	unfixable.Fixable, unfixable.Vuln.FixedVersion = false, ""
	return Snapshot{
		At: now,
		Findings: []Finding{
			crit(hshelf, "CVE-1", stage.Unfixed, recent),
			crit(hshelf, "CVE-PENDING", stage.Pending, now.Unix()-3600),
			annotated,
			high,
			unfixable,
			crit(hshelf, "CVE-IN-MAIN", stage.FixedInMain, recent),
			crit(hshelf, "CVE-INSTALLED", stage.Unfixed, 0),
			crit(hshelf, "CVE-OLD", stage.Unfixed, now.Unix()-8*day),
			crit(workspace, "CVE-2", stage.Unscannable, recent),
			crit(unknown, "CVE-3", stage.Unfixed, recent),
			crit(longhorn, "CVE-4", stage.FixedUpstream, recent),
		},
		Images: []ImageView{
			{Ref: hshelf, SelfBuilt: true, Source: "https://github.com/yuanying/hshelf", Workloads: []Workload{
				{Namespace: "aphrael", Kind: "ReplicaSet", Name: "aphrael-1", Container: "aphrael"},
				{Namespace: "aphrael", Kind: "ReplicaSet", Name: "aphrael-1", Container: "aphrael"},
			}},
			{Ref: workspace, SelfBuilt: true, Source: "https://github.com/yuanying/natsumi.git"},
			{Ref: unknown, SelfBuilt: false},
			{Ref: longhorn, SelfBuilt: false, Source: "https://github.com/longhorn/longhorn-engine"},
		},
	}
}

func TestResponderWanted(t *testing.T) {
	got := responderWanted(responderSnapshot(), now, 7*24*time.Hour)
	type summary struct {
		target string
		vulns  []string
	}
	var sums []summary
	for _, w := range got {
		s := summary{target: w.Target.Key()}
		for _, f := range w.Findings {
			s.vulns = append(s.vulns, f.Image+"|"+f.VulnerabilityID)
		}
		sums = append(sums, s)
	}
	want := []summary{
		{"image:ghcr.io/yuanying/nolabel", []string{"ghcr.io/yuanying/nolabel|CVE-3"}},
		{"image:index.docker.io/longhornio/longhorn-engine", []string{"index.docker.io/longhornio/longhorn-engine|CVE-4"}},
		{"source:yuanying/hshelf", []string{"ghcr.io/yuanying/hshelf|CVE-1", "ghcr.io/yuanying/hshelf|CVE-PENDING"}},
		{"source:yuanying/natsumi", []string{"ghcr.io/yuanying/natsumi-workspace|CVE-2"}},
	}
	if !reflect.DeepEqual(sums, want) {
		t.Errorf("wanted:\n got %v\nwant %v", sums, want)
	}

	f := got[2].Findings[0]
	wantFinding := responder.Finding{
		VulnerabilityID: "CVE-1", Severity: "CRITICAL", Package: "json", InstalledVersion: "2.18.0", FixedVersion: "2.19.2",
		Stage: "unfixed", VexState: "none", Image: "ghcr.io/yuanying/hshelf", Tag: "1.0.0", Digest: "sha256:aa",
		Workloads: []responder.Workload{{Namespace: "aphrael", Kind: "ReplicaSet", Name: "aphrael-1", Container: "aphrael"}},
	}
	if !reflect.DeepEqual(f, wantFinding) {
		t.Errorf("finding:\n got %+v\nwant %+v", f, wantFinding)
	}
}

// fakeResponder is vuln-responder's A2A host as an HTTP server: SendMessage
// starts a task, GetTask finds it completed with a pull request.
type fakeResponder struct {
	mu       sync.Mutex
	methods  []string
	messages []map[string]any
}

func (f *fakeResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.methods = append(f.methods, req.Method)
	if r.Header.Get("Authorization") != "Bearer a2a-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var result string
	switch req.Method {
	case "SendMessage":
		f.messages = append(f.messages, req.Params["message"].(map[string]any))
		result = fmt.Sprintf(`{"task":{"id":"task-%d","contextId":"ctx-1","status":{"state":"TASK_STATE_SUBMITTED"}}}`, len(f.messages))
	case "GetTask":
		result = fmt.Sprintf(`{"id":%q,"contextId":"ctx-1","status":{"state":"TASK_STATE_COMPLETED"},"artifacts":[{"parts":[{"text":"上流待ちとして VEX を書いた。https://github.com/yuanying/fleet-infra/pull/240"}]}]}`, req.Params["id"])
	}
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, result)
}

func TestTrackerRequestsTriage(t *testing.T) {
	fake := &fakeResponder{}
	hs := httptest.NewServer(fake)
	defer hs.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("a2a-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	store := &memStore{}
	slack := &fakeSlack{}
	clock := now
	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	sched, _ := digest.ParseSchedule("Mon 09:00", tokyo)
	tr := &Tracker{
		Store: store,
		Slack: slack,
		Responder: &responder.Requester{
			Client:      &responder.Client{URL: hs.URL, TokenFile: tokenFile},
			Mode:        "vex-only",
			TaskTimeout: time.Hour,
			Log:         logr.Discard(),
		},
		Metrics: NewMetrics(prometheus.NewRegistry()),
		Log:     logr.Discard(),
		Now:     func() time.Time { return clock },
		Config: Config{
			DetailSeverities:   map[string]bool{"CRITICAL": true},
			Location:           tokyo,
			Schedule:           sched,
			ResponderNewWithin: 7 * 24 * time.Hour,
		},
	}
	ctx := context.Background()
	if err := tr.LoadState(ctx); err != nil {
		t.Fatal(err)
	}

	// Nothing is asked before the first evaluation.
	tr.RespondOnce(ctx)
	if len(fake.methods) != 0 {
		t.Fatalf("sent before any evaluation: %v", fake.methods)
	}

	snap := responderSnapshot()
	tr.mu.Lock()
	tr.snapshot, tr.hasSnapshot = snap, true
	tr.mu.Unlock()

	tr.RespondOnce(ctx)
	if len(fake.messages) != 1 {
		t.Fatalf("messages = %d", len(fake.messages))
	}
	parts := fake.messages[0]["parts"].([]any)
	data := parts[1].(map[string]any)["data"].(map[string]any)
	if data["kind"] != "vuln-triage/v1" || data["mode"] != "vex-only" || data["target"].(map[string]any)["image"] != "ghcr.io/yuanying/nolabel" {
		t.Errorf("data = %v", data)
	}
	if store.saved == nil || store.saved.Requests["image:ghcr.io/yuanying/nolabel"].TaskID != "task-1" {
		t.Fatal("the request was not saved")
	}

	clock = clock.Add(time.Minute)
	tr.RespondOnce(ctx)
	rec := store.saved.Requests["image:ghcr.io/yuanying/nolabel"]
	if rec.State != "completed" || rec.PR != "https://github.com/yuanying/fleet-infra/pull/240" {
		t.Errorf("record = %+v", rec)
	}

	c := &Collector{Snapshot: func() (Snapshot, bool) { return Snapshot{}, true }, Requests: tr.ResponderRequests}
	want := `
# HELP vuln_tracker_responder_request_info A request to vuln-responder for one target, as last seen. The value is when its state last changed (unix seconds).
# TYPE vuln_tracker_responder_request_info gauge
vuln_tracker_responder_request_info{pr="https://github.com/yuanying/fleet-infra/pull/240",state="completed",target="ghcr.io/yuanying/nolabel",target_type="image"} ` + fmt.Sprint(float64(clock.Unix())) + `
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "vuln_tracker_responder_request_info"); err != nil {
		t.Error(err)
	}

	// The digest tells what happened to the requests.
	clock = time.Date(2026, 11, 2, 9, 0, 1, 0, tokyo)
	tr.DigestOnce(ctx)
	if len(slack.sent) != 1 || !strings.Contains(slack.sent[0], "`ghcr.io/yuanying/nolabel` completed <https://github.com/yuanying/fleet-infra/pull/240|PR>") {
		t.Errorf("digest:\n%v", slack.sent)
	}
}

// Off by default: without a responder nothing is asked and nothing recorded.
func TestTrackerRequestsOff(t *testing.T) {
	store := &memStore{}
	slack := &fakeSlack{}
	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	sched, _ := digest.ParseSchedule("Mon 09:00", tokyo)
	clock := now
	tr := &Tracker{Store: store, Slack: slack, Log: logr.Discard(), Now: func() time.Time { return clock },
		Config: Config{DetailSeverities: map[string]bool{"CRITICAL": true}, Location: tokyo, Schedule: sched, ResponderNewWithin: 7 * 24 * time.Hour}}
	ctx := context.Background()
	if err := tr.LoadState(ctx); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	tr.snapshot, tr.hasSnapshot = responderSnapshot(), true
	tr.mu.Unlock()
	tr.RespondOnce(ctx)
	if n := len(tr.ResponderRequests()); n != 0 {
		t.Errorf("%d requests recorded while off", n)
	}
	clock = time.Date(2026, 11, 2, 9, 0, 1, 0, tokyo)
	tr.DigestOnce(ctx)
	if len(slack.sent) != 1 || strings.Contains(slack.sent[0], "vuln-responder") {
		t.Errorf("digest while off:\n%v", slack.sent)
	}
}

func TestCollectorRequests(t *testing.T) {
	c := &Collector{
		Snapshot: func() (Snapshot, bool) { return Snapshot{}, false },
		Requests: func() map[string]state.Request {
			return map[string]state.Request{
				"source:yuanying/hshelf": {TargetType: "source", Target: "yuanying/hshelf", State: "working", UpdatedAt: 100},
			}
		},
	}
	want := `
# HELP vuln_tracker_responder_request_info A request to vuln-responder for one target, as last seen. The value is when its state last changed (unix seconds).
# TYPE vuln_tracker_responder_request_info gauge
vuln_tracker_responder_request_info{pr="",state="working",target="yuanying/hshelf",target_type="source"} 100
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}
