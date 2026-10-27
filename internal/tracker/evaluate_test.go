package tracker

import (
	"errors"
	"testing"
	"time"

	"github.com/yuanying/vuln-tracker/internal/annotation"
	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/scanner"
	"github.com/yuanying/vuln-tracker/internal/stage"
	"github.com/yuanying/vuln-tracker/internal/state"
)

const (
	dRun     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dMain    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dRelease = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	dGit     = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

var errScan = errors.New("scan failed")

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func hshelf() Image {
	return Image{
		Ref: imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: dRun},
		Vulns: []Vuln{
			{ID: "CVE-2026-33210", Package: "json", InstalledVersion: "2.18.0", FixedVersion: ">= 2.19.2", Severity: "CRITICAL", PURL: "pkg:gem/json@2.18.0"},
			{ID: "CVE-2026-0001", Package: "libssl3", InstalledVersion: "3.5.0-r0", FixedVersion: "3.5.1-r0", Severity: "HIGH"},
			{ID: "CVE-2026-0002", Package: "busybox", InstalledVersion: "1.37.0-r0", Severity: "LOW"},
		},
		Workloads: []Workload{{Namespace: "aphrael", Kind: "ReplicaSet", Name: "aphrael-1", Container: "aphrael"}},
	}
}

func set(keys ...scanner.Key) scanner.Set {
	s := scanner.Set{}
	for _, k := range keys {
		s[k] = struct{}{}
	}
	return s
}

func find(t *testing.T, snap Snapshot, vulnID string) Finding {
	t.Helper()
	for _, f := range snap.Findings {
		if f.Vuln.ID == vulnID {
			return f
		}
	}
	t.Fatalf("no finding for %s", vulnID)
	return Finding{}
}

func TestEvaluateStages(t *testing.T) {
	img := hshelf()
	cands := map[string]Candidates{
		img.Key(): {
			Origin: stage.SelfBuilt,
			Source: "https://github.com/yuanying/hshelf",
			List: []CandidateRef{
				{Kind: stage.Main, Tag: "main", Digest: dMain},
				{Kind: stage.Release, Tag: "1.1.0", Digest: dRelease},
			},
		},
	}
	scans := map[string]ScanResult{
		// main fixed libssl3 and json; the release only libssl3.
		dMain:    {At: now, Set: set(scanner.Key{VulnerabilityID: "CVE-2026-0002", Package: "busybox"})},
		dRelease: {At: now, Set: set(scanner.Key{VulnerabilityID: "CVE-2026-33210", Package: "json"}, scanner.Key{VulnerabilityID: "CVE-2026-0002", Package: "busybox"})},
	}
	snap := Evaluate(Input{Images: []Image{img}, Candidates: cands, Scans: scans, State: state.New(), Now: now, Today: "2026-10-27"})

	if got := find(t, snap, "CVE-2026-33210").Stage; got != stage.FixedInMain {
		t.Errorf("json: %q, want fixed-in-main", got)
	}
	if got := find(t, snap, "CVE-2026-0001").Stage; got != stage.FixedInRelease {
		t.Errorf("libssl3: %q, want fixed-in-release", got)
	}
	if got := find(t, snap, "CVE-2026-0002").Stage; got != stage.Unfixed {
		t.Errorf("busybox: %q, want unfixed", got)
	}
	if !find(t, snap, "CVE-2026-0001").Fixable || find(t, snap, "CVE-2026-0002").Fixable {
		t.Error("fixable follows fixedVersion")
	}
	if len(snap.Images) != 1 || !snap.Images[0].SelfBuilt || snap.Images[0].Source != "https://github.com/yuanying/hshelf" {
		t.Errorf("images: %+v", snap.Images)
	}
	if got := snap.Images[0].Candidates; len(got) != 2 || got[0].Result != stage.Scanned {
		t.Errorf("candidate views: %+v", got)
	}
}

func TestEvaluateBeforeDiscovery(t *testing.T) {
	snap := Evaluate(Input{Images: []Image{hshelf()}, Scans: map[string]ScanResult{}, State: state.New(), Now: now, Today: "2026-10-27"})
	for _, f := range snap.Findings {
		if f.Stage != stage.Pending {
			t.Errorf("%s: %q, want pending before discovery has run", f.Vuln.ID, f.Stage)
		}
	}
}

func TestEvaluateScanStates(t *testing.T) {
	img := hshelf()
	cands := map[string]Candidates{img.Key(): {
		Origin: stage.SelfBuilt,
		List:   []CandidateRef{{Kind: stage.Main, Digest: dMain}, {Kind: stage.Git, Digest: dGit}},
	}}
	scans := map[string]ScanResult{dMain: {At: now, Err: errScan}}
	snap := Evaluate(Input{Images: []Image{img}, Candidates: cands, Scans: scans, State: state.New(), Now: now, Today: "2026-10-27"})
	if got := find(t, snap, "CVE-2026-0001").Stage; got != stage.Unscannable {
		t.Errorf("%q, want unscannable", got)
	}
	views := snap.Images[0].Candidates
	if views[0].Result != stage.Failed || views[1].Result != stage.NotScanned {
		t.Errorf("views: %+v", views)
	}
}

func TestEvaluateAnnotations(t *testing.T) {
	vexDoc := []byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "author": "t",
  "timestamp": "2026-10-01T00:00:00Z", "version": 1,
  "statements": [
    {"vulnerability": {"name": "CVE-2026-33210"}, "timestamp": "2026-10-27T00:00:00Z",
     "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf", "subcomponents": [{"@id": "pkg:gem/json@2.18.0"}]}],
     "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "impact_statement": "bundled, never loaded",
     "status_notes": "state: upstream\nreview-by: 2026-10-26"},
    {"vulnerability": {"name": "CVE-2026-0001"}, "timestamp": "2026-10-27T00:00:00Z",
     "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf"}],
     "status": "affected", "action_statement": "release pending",
     "status_notes": "state: in-progress\nreview-by: 2026-12-01"}
  ]}`)
	vex, errs := annotation.Load(map[string][]byte{"security/vex/ghcr.io/yuanying/hshelf.openvex.json": vexDoc})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	snap := Evaluate(Input{Images: []Image{hshelf()}, Scans: map[string]ScanResult{}, VEX: vex, State: state.New(), Now: now, Today: "2026-10-27"})

	json := find(t, snap, "CVE-2026-33210")
	if json.VexState() != "upstream" || !json.VexExpired {
		t.Errorf("json: state %q expired %v", json.VexState(), json.VexExpired)
	}
	ssl := find(t, snap, "CVE-2026-0001")
	if ssl.VexState() != "in-progress" || ssl.VexExpired {
		t.Errorf("libssl3: state %q expired %v", ssl.VexState(), ssl.VexExpired)
	}
	bb := find(t, snap, "CVE-2026-0002")
	if bb.VexState() != "none" || bb.VexExpired {
		t.Errorf("busybox: state %q expired %v", bb.VexState(), bb.VexExpired)
	}
}

func TestEvaluateFirstSeen(t *testing.T) {
	st := state.New()
	img := hshelf()
	Evaluate(Input{Images: []Image{img}, Scans: map[string]ScanResult{}, State: st, Now: now, Today: "2026-10-27"})

	later := now.Add(time.Hour)
	img.Vulns = append(img.Vulns, Vuln{ID: "CVE-2026-9999", Package: "zlib", Severity: "CRITICAL", FixedVersion: "1.3.2"})
	// Upgrading the tag does not make what remains new.
	img.Ref.Tag, img.Ref.Digest = "1.1.0", dRelease
	snap := Evaluate(Input{Images: []Image{img}, Scans: map[string]ScanResult{}, State: st, Now: later, Today: "2026-10-27"})

	if got := find(t, snap, "CVE-2026-33210").FirstSeen; got != 0 {
		t.Errorf("what was there at install: FirstSeen %d, want 0", got)
	}
	if got := find(t, snap, "CVE-2026-9999").FirstSeen; got != later.Unix() {
		t.Errorf("new one: FirstSeen %d, want %d", got, later.Unix())
	}
}

// Two packages with the same vulnerability are two findings; the same
// package listed twice in a report is one.
func TestEvaluateDeduplicates(t *testing.T) {
	img := hshelf()
	img.Vulns = []Vuln{
		{ID: "CVE-1", Package: "a", Severity: "HIGH"},
		{ID: "CVE-1", Package: "b", Severity: "HIGH"},
		{ID: "CVE-1", Package: "a", Severity: "HIGH"},
	}
	snap := Evaluate(Input{Images: []Image{img}, Scans: map[string]ScanResult{}, State: state.New(), Now: now, Today: "2026-10-27"})
	if len(snap.Findings) != 2 {
		t.Errorf("got %d findings, want 2", len(snap.Findings))
	}
}
