package digest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yuanying/vuln-tracker/internal/state"
)

var tokyo = mustLoad("Asia/Tokyo")

func mustLoad(name string) *time.Location {
	l, err := time.LoadLocation(name)
	if err != nil {
		panic(err)
	}
	return l
}

func item(key, image, vuln, stage string, firstSeen int64) Item {
	return Item{Key: key, Image: image, Tag: "1.0.0", VulnerabilityID: vuln, Package: "pkg", Severity: "CRITICAL", Stage: stage, VexState: "none", Fixable: true, FirstSeen: firstSeen}
}

func TestBuild(t *testing.T) {
	sent := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC).Unix()
	prev := state.Digest{SentAt: sent, Findings: map[string]state.Entry{
		"a@1|CVE-1|pkg": {Stage: "unfixed", VexState: "none"},
		"a@1|CVE-2|pkg": {Stage: "fixed-in-main", VexState: "none"},
		"a@1|CVE-3|pkg": {Stage: "in-git", VexState: "none"},
		"b@1|CVE-9|pkg": {Stage: "unfixed", VexState: "none"},
		"b@1|CVE-8|pkg": {Stage: "unfixed", VexState: "none"},
	}}
	expired := item("a@1|CVE-4|pkg", "a", "CVE-4", "unfixed", 0)
	expired.VexState, expired.ReviewBy, expired.Reason, expired.VexExpired = "upstream", "2026-10-20", "waiting for the base image", true
	items := []Item{
		item("a@1|CVE-1|pkg", "a", "CVE-1", "fixed-in-release", 0), // advanced
		item("a@1|CVE-2|pkg", "a", "CVE-2", "fixed-in-main", 0),    // unchanged
		item("a@1|CVE-3|pkg", "a", "CVE-3", "fixed-in-release", 0), // went back: not listed
		item("a@1|CVE-5|pkg", "a", "CVE-5", "unfixed", sent+3600),  // new
		item("a@1|CVE-6|pkg", "a", "CVE-6", "unfixed", 0),          // there at install, not in the last digest: not new
		expired,
	}
	r := Build(items, prev)
	if len(r.New) != 1 || r.New[0].VulnerabilityID != "CVE-5" {
		t.Errorf("New = %+v", r.New)
	}
	if len(r.Advanced) != 1 || r.Advanced[0].VulnerabilityID != "CVE-1" || r.Advanced[0].PrevStage != "unfixed" {
		t.Errorf("Advanced = %+v", r.Advanced)
	}
	if len(r.Expired) != 1 || r.Expired[0].VulnerabilityID != "CVE-4" {
		t.Errorf("Expired = %+v", r.Expired)
	}
	if r.Gone["b"] != 2 || len(r.Gone) != 1 {
		t.Errorf("Gone = %v", r.Gone)
	}
	if r.Counts["unfixed"] != 3 || r.Counts["fixed-in-release"] != 2 {
		t.Errorf("Counts = %v", r.Counts)
	}
	snap := r.Snapshot()
	if len(snap) != len(items) || snap["a@1|CVE-1|pkg"].Stage != "fixed-in-release" {
		t.Errorf("Snapshot = %v", snap)
	}
}

// The first digest has nothing to compare with: what appeared since the
// tracker was installed is new, and nothing has advanced or gone.
func TestBuildFirst(t *testing.T) {
	r := Build([]Item{item("a@1|CVE-1|pkg", "a", "CVE-1", "unfixed", 0), item("a@1|CVE-2|pkg", "a", "CVE-2", "unfixed", 1000)}, state.Digest{})
	if len(r.New) != 1 || len(r.Advanced) != 0 || len(r.Gone) != 0 {
		t.Errorf("got %+v", r)
	}
}

func TestRender(t *testing.T) {
	var items []Item
	for i := range 30 {
		items = append(items, item("k"+string(rune('a'+i)), "ghcr.io/yuanying/hshelf", "CVE-"+string(rune('a'+i)), "unfixed", 1000))
	}
	expired := item("x", "index.docker.io/longhornio/longhorn-engine", "SUSE-1", "unfixed", 0)
	expired.VexState, expired.ReviewBy, expired.Reason, expired.VexExpired = "upstream", "2026-10-20", "waiting for the release", true
	items = append(items, expired)
	r := Build(items, state.Digest{})
	text := Render(r, Options{DashboardURL: "https://grafana.example/d/vuln", VEXBaseURL: "https://github.com/yuanying/fleet-infra/blob/main/", MaxItems: 10})
	for _, want := range []string{
		"https://grafana.example/d/vuln",
		"ghcr.io/yuanying/hshelf",
		"waiting for the release",
		"2026-10-20",
		"https://github.com/yuanying/fleet-infra/blob/main/security/vex/index.docker.io/longhornio/longhorn-engine.openvex.json",
		"and 20 more",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered digest lacks %q:\n%s", want, text)
		}
	}
	if len(text) > maxText {
		t.Errorf("rendered digest is %d bytes", len(text))
	}
}

func TestRenderRequests(t *testing.T) {
	r := Build(nil, state.Digest{})
	if text := Render(r, Options{}); strings.Contains(text, "vuln-responder") {
		t.Errorf("the section shows while requests are off:\n%s", text)
	}
	text := Render(r, Options{Responder: true})
	if !strings.Contains(text, "*vuln-responder への依頼*（0 件）\nなし") {
		t.Errorf("no empty section:\n%s", text)
	}
	r.Requests = []Request{
		{Target: "yuanying/hshelf", State: "completed", PR: "https://github.com/yuanying/fleet-infra/pull/240", Summary: "json は上流待ちとして VEX を書いた"},
		{Target: "index.docker.io/longhornio/longhorn-engine", State: "failed"},
	}
	text = Render(r, Options{Responder: true})
	for _, want := range []string{
		"（2 件）",
		"• `yuanying/hshelf` completed <https://github.com/yuanying/fleet-infra/pull/240|PR>\n　json は上流待ちとして VEX を書いた",
		"• `index.docker.io/longhornio/longhorn-engine` failed\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered digest lacks %q:\n%s", want, text)
		}
	}
}

func TestNextRun(t *testing.T) {
	s := Schedule{Weekday: time.Monday, Hour: 9, Minute: 0, Location: tokyo}
	tests := []struct{ after, want time.Time }{
		// Sunday evening → Monday 09:00.
		{time.Date(2026, 10, 25, 20, 0, 0, 0, tokyo), time.Date(2026, 10, 26, 9, 0, 0, 0, tokyo)},
		// Monday 09:00 exactly → the next Monday.
		{time.Date(2026, 10, 26, 9, 0, 0, 0, tokyo), time.Date(2026, 11, 2, 9, 0, 0, 0, tokyo)},
		// Monday 08:59 → the same Monday.
		{time.Date(2026, 10, 26, 8, 59, 0, 0, tokyo), time.Date(2026, 10, 26, 9, 0, 0, 0, tokyo)},
		// Given in UTC, answered in the schedule's zone.
		{time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC), time.Date(2026, 11, 2, 9, 0, 0, 0, tokyo)},
	}
	for _, tt := range tests {
		if got := s.Next(tt.after); !got.Equal(tt.want) {
			t.Errorf("Next(%v) = %v, want %v", tt.after, got, tt.want)
		}
	}
}

func TestParseSchedule(t *testing.T) {
	s, err := ParseSchedule("Mon 09:00", tokyo)
	if err != nil || s.Weekday != time.Monday || s.Hour != 9 || s.Minute != 0 {
		t.Errorf("got %+v, %v", s, err)
	}
	for _, bad := range []string{"", "Monday", "Mon 25:00", "Xyz 09:00", "Mon 9"} {
		if _, err := ParseSchedule(bad, tokyo); err == nil {
			t.Errorf("ParseSchedule(%q) succeeded", bad)
		}
	}
}

func TestSlack(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		if r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "json please", http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	s := &Slack{WebhookURL: srv.URL, HTTP: srv.Client()}
	if err := s.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "hello" {
		t.Errorf("posted %v", got)
	}

	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid_token", http.StatusForbidden)
	}))
	defer fail.Close()
	if err := (&Slack{WebhookURL: fail.URL, HTTP: fail.Client()}).Send(context.Background(), "x"); err == nil {
		t.Error("a 403 should be an error")
	}
}
