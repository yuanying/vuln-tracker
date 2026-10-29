// Package pipeline decides where a finding stands on the two axes of its
// remediation (ADR 0014): the source side — a self-built image's main branch
// and releases — and the manifest side — the version written in git. Like the
// stage (ADR 0002), both are read from the scans of the candidates; a linked
// pull request only says that someone means to fix it. This package only
// decides; it neither scans nor reads GitHub.
package pipeline

import "github.com/yuanying/vuln-tracker/internal/stage"

// SourceState is the source side of a finding.
type SourceState string

const (
	// SourceUnaddressed: neither :main nor the newest release has dropped
	// it, and no linked pull request is open.
	SourceUnaddressed SourceState = "unaddressed"
	// SourcePROpen: a linked pull request is open in the source repository.
	SourcePROpen SourceState = "pr-open"
	// SourceMerged: :main has dropped it (the stage fixed-in-main).
	SourceMerged SourceState = "merged"
	// SourceReleased: the newest release has dropped it.
	SourceReleased SourceState = "released"
	// SourceNotApplicable: the image is not built here.
	SourceNotApplicable SourceState = "not-applicable"
	// SourceUnknown: a candidate that may have dropped it is not scanned yet
	// or cannot be scanned.
	SourceUnknown SourceState = "unknown"
)

// ManifestState is the manifest side of a finding. A finding whose fix is
// in production is no finding any more, so there is no state for it.
type ManifestState string

const (
	// ManifestNoFix: no version to bump to has dropped it yet.
	ManifestNoFix ManifestState = "no-fix"
	// ManifestUnaddressed: a version to bump to has dropped it, and no
	// linked pull request is open in a manifest repository.
	ManifestUnaddressed ManifestState = "unaddressed"
	// ManifestPROpen: a version to bump to has dropped it, and a linked pull
	// request is open in a manifest repository.
	ManifestPROpen ManifestState = "pr-open"
	// ManifestMerged: the version written in git has dropped it (the stage
	// in-git); it waits to be applied.
	ManifestMerged ManifestState = "merged"
	// ManifestUnknown: a candidate that may have dropped it is not scanned
	// yet or cannot be scanned.
	ManifestUnknown ManifestState = "unknown"
)

// Input is what is known about one finding's candidates.
type Input struct {
	// Discovered is false until discovery has reached the running version:
	// nothing is known yet, not even its origin.
	Discovered bool
	Origin     stage.Origin
	Outcomes   []stage.Outcome
	// DiscoveryFailed says a registry could not be read, so candidates may
	// be missing.
	DiscoveryFailed bool
}

// look says what the candidates of the given kinds tell: whether one has
// dropped the vulnerability, and whether one is not scanned or failed.
func (in Input) look(kinds ...stage.Candidate) (gone, unsure bool) {
	for _, oc := range in.Outcomes {
		match := false
		for _, k := range kinds {
			match = match || oc.Candidate == k
		}
		if !match {
			continue
		}
		switch oc.Result {
		case stage.Scanned:
			gone = gone || !oc.Present
		default:
			unsure = true
		}
	}
	return gone, unsure
}

// Source decides the source side. prOpen says a linked pull request is open
// in the source repository.
func Source(in Input, prOpen bool) SourceState {
	if !in.Discovered {
		return SourceUnknown
	}
	if in.Origin != stage.SelfBuilt {
		return SourceNotApplicable
	}
	if gone, _ := in.look(stage.Release); gone {
		return SourceReleased
	}
	gone, unsure := in.look(stage.Main, stage.Release)
	switch {
	case gone:
		return SourceMerged
	case unsure || in.DiscoveryFailed:
		return SourceUnknown
	case prOpen:
		return SourcePROpen
	}
	return SourceUnaddressed
}

// Manifest decides the manifest side. prOpen says a linked pull request is
// open in a manifest repository.
func Manifest(in Input, prOpen bool) ManifestState {
	if !in.Discovered {
		return ManifestUnknown
	}
	gitGone, gitUnsure := in.look(stage.Git)
	if gitGone {
		return ManifestMerged
	}
	if gitUnsure {
		return ManifestUnknown
	}
	fix := stage.Upstream
	if in.Origin == stage.SelfBuilt {
		fix = stage.Release
	}
	gone, unsure := in.look(fix)
	switch {
	case gone && prOpen:
		return ManifestPROpen
	case gone:
		return ManifestUnaddressed
	case unsure || in.DiscoveryFailed:
		return ManifestUnknown
	}
	return ManifestNoFix
}
