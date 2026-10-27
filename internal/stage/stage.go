// Package stage decides how far the fix for one finding has got (ADR 0002).
//
// A finding is a vulnerability in one package of an image running in
// production. Each candidate version — :main, the newest release, the newest
// of the same upstream series, the version written in git — is scanned, and
// the finding's stage is the furthest candidate the vulnerability is gone
// from. This package only decides; it does not scan.
package stage

// Stage is the value of the `stage` label (ADR 0005).
type Stage string

const (
	InGit          Stage = "in-git"
	FixedInRelease Stage = "fixed-in-release"
	FixedUpstream  Stage = "fixed-upstream"
	FixedInMain    Stage = "fixed-in-main"
	Unfixed        Stage = "unfixed"
	Unscannable    Stage = "unscannable"
	Pending        Stage = "pending"
)

// All lists every stage, furthest first.
func All() []Stage {
	return []Stage{InGit, FixedInRelease, FixedUpstream, FixedInMain, Unfixed, Unscannable, Pending}
}

// rank orders stages by how far the fix has got. Unscannable and Pending say
// nothing about the fix, so they rank with Unfixed: moving from either to
// Unfixed is not progress.
func rank(s Stage) int {
	switch s {
	case InGit:
		return 3
	case FixedInRelease, FixedUpstream:
		return 2
	case FixedInMain:
		return 1
	default:
		return 0
	}
}

// Advanced reports whether moving from one stage to the other is progress, as
// the weekly digest lists it.
func Advanced(from, to Stage) bool {
	return rank(to) > rank(from)
}

// Origin says who builds an image, which decides which candidates count.
type Origin int

const (
	// SelfBuilt images come from a repository of ours and publish :main.
	SelfBuilt Origin = iota
	// External images are built by someone else.
	External
)

// Candidate names a version that may carry the fix.
type Candidate string

const (
	Main     Candidate = "main"
	Release  Candidate = "release"
	Upstream Candidate = "upstream"
	Git      Candidate = "git"
)

// Result says whether a candidate has been scanned.
type Result string

const (
	Scanned    Result = "scanned"
	Failed     Result = "failed"
	NotScanned Result = "pending"
)

// Outcome is what is known about one candidate for one finding. Present is
// meaningful only when the candidate was scanned.
type Outcome struct {
	Candidate Candidate
	Result    Result
	Present   bool
}

// stageFor is the stage a fix found in the candidate puts the finding at, for
// an image of the given origin, or "" when the candidate does not count.
func stageFor(o Origin, c Candidate) Stage {
	switch {
	case c == Git:
		return InGit
	case o == SelfBuilt && c == Release:
		return FixedInRelease
	case o == SelfBuilt && c == Main:
		return FixedInMain
	case o == External && c == Upstream:
		return FixedUpstream
	}
	return ""
}

// Decide returns the stage of a finding. discoveryFailed says the registry
// could not be read, so candidates that may exist were never found.
func Decide(o Origin, outcomes []Outcome, discoveryFailed bool) Stage {
	best := Stage("")
	sawFailed, sawPending := discoveryFailed, false
	for _, oc := range outcomes {
		s := stageFor(o, oc.Candidate)
		if s == "" {
			continue
		}
		switch oc.Result {
		case Scanned:
			if !oc.Present && (best == "" || rank(s) > rank(best)) {
				best = s
			}
		case Failed:
			sawFailed = true
		default:
			sawPending = true
		}
	}
	switch {
	case best != "":
		return best
	case sawFailed:
		return Unscannable
	case sawPending:
		return Pending
	}
	return Unfixed
}
