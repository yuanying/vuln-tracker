package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yuanying/vuln-tracker/internal/annotation"
	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/pipeline"
	"github.com/yuanying/vuln-tracker/internal/stage"
	"github.com/yuanying/vuln-tracker/internal/tracker"
)

const dRun = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

var at = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func snapshot() tracker.Snapshot {
	hshelf := imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "v1.2.3", Digest: dRun}
	nginx := imageref.Ref{Registry: "index.docker.io", Repository: "library/nginx", Tag: "1.30.5", Digest: dRun}
	reply := pipeline.PR{Link: pipeline.LinkResponder, PullRequest: github.PullRequest{
		URL: "https://github.com/yuanying/hshelf/pull/5", Repository: "yuanying/hshelf", Number: 5, State: github.StateMerged,
		Title: "Bump json", Author: "fraction-vuln-responder[bot]",
	}}
	return tracker.Snapshot{
		At:     at,
		Synced: true,
		Images: []tracker.ImageView{
			{Ref: hshelf, SelfBuilt: true, Source: "https://github.com/yuanying/hshelf", Workloads: []tracker.Workload{
				{Namespace: "hshelf", Kind: "Deployment", Name: "hshelf", Container: "app"},
			}},
			{Ref: nginx},
		},
		Findings: []tracker.Finding{
			{
				Image: hshelf, Stage: stage.FixedInMain, Fixable: true, FirstSeen: at.Add(-48 * time.Hour).Unix(),
				Vuln: tracker.Vuln{ID: "CVE-2026-33210", Package: "json", InstalledVersion: "2.18.0", FixedVersion: "2.18.1", Severity: "HIGH"},
				Pipeline: tracker.Pipeline{
					SourceRepository: "yuanying/hshelf", Source: pipeline.SourceMerged, SourcePRs: []pipeline.PR{reply},
					ManifestRepository: "yuanying/fleet-infra", Manifest: pipeline.ManifestNoFix,
				},
			},
			{
				Image: nginx, Stage: stage.Unfixed,
				Vuln:       tracker.Vuln{ID: "CVE-2026-1", Package: "openssl", InstalledVersion: "3.0", Severity: "CRITICAL"},
				Annotation: &annotation.Annotation{State: "upstream", Status: "affected", ReviewBy: "2026-10-01", Reason: "waiting", Path: "security/vex/index.docker.io/library/nginx.openvex.json"},
				VexExpired: true,
				// Seen at install: no time to tell.
				FirstSeen: 0,
				Pipeline:  tracker.Pipeline{Source: pipeline.SourceNotApplicable, Manifest: pipeline.ManifestNoFix},
			},
			// Not a detailed severity: left out.
			{Image: nginx, Stage: stage.Unfixed, Vuln: tracker.Vuln{ID: "CVE-2026-2", Package: "zlib", Severity: "LOW"}},
		},
	}
}

func get(t *testing.T, s *Server, path string) (*http.Response, []byte) {
	t.Helper()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func newServer(snap tracker.Snapshot, ok bool) *Server {
	return &Server{
		Snapshot:   func() (tracker.Snapshot, bool) { return snap, ok },
		Severities: []string{"CRITICAL", "HIGH"},
		VEXBaseURL: "https://github.com/yuanying/fleet-infra/blob/main/",
	}
}

// The body is the contract with the pi tool (ADR 0015).
func TestFindings(t *testing.T) {
	resp, body := get(t, newServer(snapshot(), true), "/api/findings")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%d %s: %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	want := `{
  "generatedAt": "2026-10-29T12:00:00Z",
  "severities": ["CRITICAL", "HIGH"],
  "findings": [
    {
      "image": "ghcr.io/yuanying/hshelf", "tag": "v1.2.3", "digest": "` + dRun + `",
      "vulnerabilityID": "CVE-2026-33210", "severity": "HIGH", "package": "json",
      "installedVersion": "2.18.0", "fixedVersion": "2.18.1", "fixable": true,
      "selfBuilt": true, "sourceRepository": "yuanying/hshelf", "stage": "fixed-in-main",
      "source": {"state": "merged", "pullRequests": [
        {"url": "https://github.com/yuanying/hshelf/pull/5", "repository": "yuanying/hshelf", "number": 5,
         "title": "Bump json", "state": "merged", "author": "fraction-vuln-responder[bot]", "link": "vuln-responder"}
      ]},
      "manifest": {"state": "no-fix", "repository": "yuanying/fleet-infra", "pullRequests": []},
      "vex": {"state": "none", "status": null, "reviewBy": null, "document": null, "reason": null, "expired": false, "pullRequests": []},
      "workloads": [{"namespace": "hshelf", "kind": "Deployment", "name": "hshelf", "container": "app"}],
      "firstSeenAt": "2026-10-27T12:00:00Z"
    },
    {
      "image": "index.docker.io/library/nginx", "tag": "1.30.5", "digest": "` + dRun + `",
      "vulnerabilityID": "CVE-2026-1", "severity": "CRITICAL", "package": "openssl",
      "installedVersion": "3.0", "fixedVersion": "", "fixable": false,
      "selfBuilt": false, "sourceRepository": null, "stage": "unfixed",
      "source": {"state": "not-applicable", "pullRequests": []},
      "manifest": {"state": "no-fix", "repository": null, "pullRequests": []},
      "vex": {"state": "upstream", "status": "affected", "reviewBy": "2026-10-01",
              "document": "https://github.com/yuanying/fleet-infra/blob/main/security/vex/index.docker.io/library/nginx.openvex.json",
              "reason": "waiting", "expired": true, "pullRequests": []},
      "workloads": [],
      "firstSeenAt": null
    }
  ]
}`
	var got, exp any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	if err := json.Unmarshal([]byte(want), &exp); err != nil {
		t.Fatal(err)
	}
	g, _ := json.MarshalIndent(got, "", "  ")
	w, _ := json.MarshalIndent(exp, "", "  ")
	if string(g) != string(w) {
		t.Errorf("got:\n%s\nwant:\n%s", g, w)
	}
}

// Until the repositories and registries have been read once, every finding
// is pending: the API says it is not ready rather than answer that.
func TestFindingsNotReady(t *testing.T) {
	unsynced := snapshot()
	unsynced.Synced = false
	for name, s := range map[string]*Server{
		"no snapshot": newServer(tracker.Snapshot{}, false),
		"not synced":  newServer(unsynced, true),
	} {
		resp, body := get(t, s, "/api/findings")
		var e struct {
			Error string `json:"error"`
		}
		if resp.StatusCode != http.StatusServiceUnavailable || json.Unmarshal(body, &e) != nil || e.Error == "" {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
		if resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: %s", name, resp.Header.Get("Content-Type"))
		}
	}
}

func TestOtherPaths(t *testing.T) {
	s := newServer(snapshot(), true)
	if resp, _ := get(t, s, "/api/unknown"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown path: %d", resp.StatusCode)
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/api/findings", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
}
