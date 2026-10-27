package tracker

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/yuanying/vuln-tracker/internal/annotation"
	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/stage"
)

func testSnapshot() Snapshot {
	run := imageref.Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: "sha256:aa"}
	ann := annotation.Annotation{State: "upstream", Status: "not_affected", ReviewBy: "2026-10-26"}
	return Snapshot{
		Findings: []Finding{
			{Image: run, Vuln: Vuln{ID: "CVE-1", Package: "json", InstalledVersion: "2.18.0", FixedVersion: ">= 2.19.2", Severity: "CRITICAL"}, Stage: stage.FixedInMain, Fixable: true, Annotation: &ann, VexExpired: true, FirstSeen: 0},
			{Image: run, Vuln: Vuln{ID: "CVE-2", Package: "libssl3", InstalledVersion: "3.5.0", FixedVersion: "3.5.1", Severity: "HIGH"}, Stage: stage.Unfixed, Fixable: true, FirstSeen: 1761566400},
			{Image: run, Vuln: Vuln{ID: "CVE-3", Package: "busybox", Severity: "LOW"}, Stage: stage.Unfixed, FirstSeen: 1761566400},
			{Image: run, Vuln: Vuln{ID: "CVE-4", Package: "zlib", Severity: "LOW"}, Stage: stage.Unfixed, FirstSeen: 1761566400},
		},
		Images: []ImageView{{
			Ref: run, SelfBuilt: true, Source: "https://github.com/yuanying/hshelf", Revision: "abc",
			Workloads:   []Workload{{Namespace: "aphrael", Kind: "ReplicaSet", Name: "aphrael-1", Container: "aphrael"}},
			Candidates:  []CandidateView{{CandidateRef: CandidateRef{Kind: stage.Main, Tag: "main", Digest: "sha256:bb", Revision: "def"}, Result: stage.Scanned, At: now}},
			RenovatePRs: []string{"https://github.com/yuanying/fleet-infra/pull/1"},
		}},
	}
}

func TestCollector(t *testing.T) {
	snap := testSnapshot()
	c := &Collector{DetailSeverities: map[string]bool{"CRITICAL": true, "HIGH": true}, Snapshot: func() (Snapshot, bool) { return snap, true }}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)

	want := `
# HELP vuln_tracker_finding A vulnerability in a package of an image running in production, for the severities listed in detail. The value is when the image × vulnerability pair was first seen (unix seconds; 0 for what was there when the tracker was installed).
# TYPE vuln_tracker_finding gauge
vuln_tracker_finding{digest="sha256:aa",fixable="true",fixed_version=">= 2.19.2",image="ghcr.io/yuanying/hshelf",installed_version="2.18.0",package="json",severity="CRITICAL",stage="fixed-in-main",tag="1.0.0",vex_expired="true",vex_review_by="2026-10-26",vex_state="upstream",vex_status="not_affected",vulnerability_id="CVE-1"} 0
vuln_tracker_finding{digest="sha256:aa",fixable="true",fixed_version="3.5.1",image="ghcr.io/yuanying/hshelf",installed_version="3.5.0",package="libssl3",severity="HIGH",stage="unfixed",tag="1.0.0",vex_expired="false",vex_review_by="",vex_state="none",vex_status="",vulnerability_id="CVE-2"} 1.7615664e+09
# HELP vuln_tracker_findings Findings of images running in production, counted by image, severity, stage and annotation.
# TYPE vuln_tracker_findings gauge
vuln_tracker_findings{digest="sha256:aa",fixable="false",image="ghcr.io/yuanying/hshelf",severity="LOW",stage="unfixed",tag="1.0.0",vex_expired="false",vex_state="none"} 2
vuln_tracker_findings{digest="sha256:aa",fixable="true",image="ghcr.io/yuanying/hshelf",severity="CRITICAL",stage="fixed-in-main",tag="1.0.0",vex_expired="true",vex_state="upstream"} 1
vuln_tracker_findings{digest="sha256:aa",fixable="true",image="ghcr.io/yuanying/hshelf",severity="HIGH",stage="unfixed",tag="1.0.0",vex_expired="false",vex_state="none"} 1
# HELP vuln_tracker_image_info An image running in production: whether it is built here, its source and the revision it was built from.
# TYPE vuln_tracker_image_info gauge
vuln_tracker_image_info{digest="sha256:aa",image="ghcr.io/yuanying/hshelf",revision="abc",self_built="true",source="https://github.com/yuanying/hshelf",tag="1.0.0"} 1
# HELP vuln_tracker_image_workload_info Where an image running in production runs.
# TYPE vuln_tracker_image_workload_info gauge
vuln_tracker_image_workload_info{container="aphrael",digest="sha256:aa",image="ghcr.io/yuanying/hshelf",kind="ReplicaSet",name="aphrael-1",namespace="aphrael",tag="1.0.0"} 1
# HELP vuln_tracker_candidate_info A version that may carry fixes for an image running in production. The value is when it was last scanned (unix seconds; 0 if not yet).
# TYPE vuln_tracker_candidate_info gauge
vuln_tracker_candidate_info{candidate="main",candidate_digest="sha256:bb",candidate_tag="main",digest="sha256:aa",image="ghcr.io/yuanying/hshelf",result="scanned",revision="def"} 1.7931024e+09
# HELP vuln_tracker_image_renovate_pr_info An open Renovate pull request that names an image running in production.
# TYPE vuln_tracker_image_renovate_pr_info gauge
vuln_tracker_image_renovate_pr_info{image="ghcr.io/yuanying/hshelf",url="https://github.com/yuanying/fleet-infra/pull/1"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
}

// Before the first evaluation nothing is exported, rather than zeros that
// would read as "nothing is vulnerable".
func TestCollectorBeforeFirstEvaluation(t *testing.T) {
	c := &Collector{Snapshot: func() (Snapshot, bool) { return Snapshot{}, false }}
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Errorf("collected %d series", n)
	}
}

func TestOperationalMetrics(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	m := NewMetrics(reg)
	m.Scans.WithLabelValues("success").Inc()
	m.SyncErrors.WithLabelValues("vex").Add(2)
	m.SyncTimestamp.WithLabelValues("fleet-infra").Set(1)
	m.DigestSent.Set(1)
	m.ScanDuration.Observe(3)
	names := map[string]bool{}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	for _, n := range []string{
		"vuln_tracker_scans_total", "vuln_tracker_scan_duration_seconds", "vuln_tracker_sync_timestamp_seconds",
		"vuln_tracker_sync_errors_total", "vuln_tracker_digest_sent_timestamp_seconds",
	} {
		if !names[n] {
			t.Errorf("%s is not registered", n)
		}
	}
}
