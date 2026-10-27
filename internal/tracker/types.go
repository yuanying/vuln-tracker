// Package tracker puts the pieces together: what runs in production, which
// candidate versions might carry its fixes, what the scans of those found, and
// what fleet-infra's annotations say (ADR 0001). Evaluate is the pure core;
// the loops around it read the cluster, the registries and GitHub.
package tracker

import (
	"time"

	"github.com/yuanying/vuln-tracker/internal/annotation"
	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/scanner"
	"github.com/yuanying/vuln-tracker/internal/stage"
)

// Vuln is one entry of a VulnerabilityReport.
type Vuln struct {
	ID               string
	Package          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	PURL             string
}

// Workload is where an image runs.
type Workload struct {
	Namespace string
	Kind      string
	Name      string
	Container string
}

// Report is what the tracker reads from one VulnerabilityReport.
type Report struct {
	Image    imageref.Ref
	Workload Workload
	Vulns    []Vuln
}

// Image is one version running in production: an image name and a digest,
// with the vulnerabilities reported for it and where it runs.
type Image struct {
	Ref       imageref.Ref
	Vulns     []Vuln
	Workloads []Workload
}

// Key identifies a running version.
func (i Image) Key() string {
	return i.Ref.Name() + "@" + i.Ref.Digest
}

// CandidateRef is one version that may carry a fix.
type CandidateRef struct {
	Kind     stage.Candidate
	Tag      string
	Digest   string
	Revision string
}

// Ref names the candidate for scanning.
func (c CandidateRef) Ref(name string) string {
	return name + "@" + c.Digest
}

// Candidates is what discovery found for one running version.
type Candidates struct {
	Origin   stage.Origin
	Source   string
	Revision string
	List     []CandidateRef
	// DiscoveryFailed says a registry could not be read, so candidates may
	// be missing.
	DiscoveryFailed bool
	RenovatePRs     []string
}

// ScanResult is the outcome of the last scan of one digest.
type ScanResult struct {
	At  time.Time
	Set scanner.Set
	Err error
}

// Finding is one vulnerability in one package of one running version, with
// its stage and annotation.
type Finding struct {
	Image      imageref.Ref
	Vuln       Vuln
	Stage      stage.Stage
	Fixable    bool
	Annotation *annotation.Annotation
	VexExpired bool
	// FirstSeen is when the image × vulnerability pair was first seen, in
	// unix seconds (ADR 0005).
	FirstSeen int64
}

// Key identifies a finding across evaluations.
func (f Finding) Key() string {
	return f.Image.Name() + "@" + f.Image.Digest + "|" + f.Vuln.ID + "|" + f.Vuln.Package
}

// VexState is the annotation's state, or "none".
func (f Finding) VexState() string {
	if f.Annotation == nil {
		return "none"
	}
	return f.Annotation.State
}

// CandidateView is a candidate with what its scan found, for the metrics.
type CandidateView struct {
	CandidateRef
	Result stage.Result
	At     time.Time
}

// ImageView is a running version with what discovery found, for the metrics.
type ImageView struct {
	Ref        imageref.Ref
	SelfBuilt  bool
	Source     string
	Revision   string
	Workloads  []Workload
	Candidates []CandidateView
	// RenovatePRs are open Renovate pull requests that name the image.
	RenovatePRs []string
}

// Snapshot is one evaluation.
type Snapshot struct {
	At       time.Time
	Findings []Finding
	Images   []ImageView
}

// firstSeenKey is the image × vulnerability pair "new" is measured on. Tags,
// digests and packages do not enter it (ADR 0005).
func firstSeenKey(name, vulnID string) string {
	return name + "|" + vulnID
}
