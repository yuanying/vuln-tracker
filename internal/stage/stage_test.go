package stage

import "testing"

func fixed(k Candidate) Outcome   { return Outcome{Candidate: k, Result: Scanned, Present: false} }
func present(k Candidate) Outcome { return Outcome{Candidate: k, Result: Scanned, Present: true} }
func failed(k Candidate) Outcome  { return Outcome{Candidate: k, Result: Failed} }
func pending(k Candidate) Outcome { return Outcome{Candidate: k, Result: NotScanned} }

func TestDecide(t *testing.T) {
	tests := []struct {
		name            string
		origin          Origin
		outcomes        []Outcome
		discoveryFailed bool
		want            Stage
	}{
		// Built here: main → release → git → production.
		{"self: no candidates at all", SelfBuilt, nil, false, Unfixed},
		{"self: main still has it", SelfBuilt, []Outcome{present(Main)}, false, Unfixed},
		{"self: fixed in main only", SelfBuilt, []Outcome{fixed(Main), present(Release)}, false, FixedInMain},
		{"self: fixed in main, no release yet", SelfBuilt, []Outcome{fixed(Main)}, false, FixedInMain},
		{"self: fixed in release", SelfBuilt, []Outcome{fixed(Main), fixed(Release)}, false, FixedInRelease},
		{"self: release fixed, git still old", SelfBuilt, []Outcome{fixed(Main), fixed(Release), present(Git)}, false, FixedInRelease},
		{"self: in git", SelfBuilt, []Outcome{fixed(Main), fixed(Release), fixed(Git)}, false, InGit},
		{"self: git alone is enough", SelfBuilt, []Outcome{present(Main), fixed(Git)}, false, InGit},
		{"self: upstream is not a candidate for us", SelfBuilt, []Outcome{fixed(Upstream), present(Main)}, false, Unfixed},

		// Built by someone else: upstream → git → production.
		{"ext: no newer version", External, nil, false, Unfixed},
		{"ext: upstream still has it", External, []Outcome{present(Upstream)}, false, Unfixed},
		{"ext: fixed upstream", External, []Outcome{fixed(Upstream)}, false, FixedUpstream},
		{"ext: in git", External, []Outcome{fixed(Upstream), fixed(Git)}, false, InGit},
		{"ext: main and release are not ours to read", External, []Outcome{fixed(Main), fixed(Release)}, false, Unfixed},

		// What could not be known.
		{"pending beats unfixed", SelfBuilt, []Outcome{present(Main), pending(Release)}, false, Pending},
		{"a fix found wins over pending", SelfBuilt, []Outcome{fixed(Main), pending(Release)}, false, FixedInMain},
		{"failed scan", External, []Outcome{failed(Upstream)}, false, Unscannable},
		{"failed beats pending", SelfBuilt, []Outcome{failed(Main), pending(Release)}, false, Unscannable},
		{"a fix found wins over a failure", SelfBuilt, []Outcome{failed(Main), fixed(Release)}, false, FixedInRelease},
		{"the registry could not be read", External, nil, true, Unscannable},
		{"the registry could not be read, but git was scanned and fixed", External, []Outcome{fixed(Git)}, true, InGit},
		{"the registry could not be read, git still has it", External, []Outcome{present(Git)}, true, Unscannable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(tt.origin, tt.outcomes, tt.discoveryFailed); got != tt.want {
				t.Errorf("Decide() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The values are the metrics contract (ADR 0005).
func TestStageNames(t *testing.T) {
	want := map[Stage]string{
		InGit:          "in-git",
		FixedInRelease: "fixed-in-release",
		FixedUpstream:  "fixed-upstream",
		FixedInMain:    "fixed-in-main",
		Unfixed:        "unfixed",
		Unscannable:    "unscannable",
		Pending:        "pending",
	}
	for s, name := range want {
		if string(s) != name {
			t.Errorf("stage %q, want %q", s, name)
		}
	}
	if len(All()) != len(want) {
		t.Errorf("All() has %d stages, want %d", len(All()), len(want))
	}
}

func TestAdvanced(t *testing.T) {
	tests := []struct {
		from, to Stage
		want     bool
	}{
		{Unfixed, FixedInMain, true},
		{FixedInMain, FixedInRelease, true},
		{FixedInRelease, InGit, true},
		{FixedUpstream, InGit, true},
		{Unfixed, FixedUpstream, true},
		{InGit, FixedInRelease, false},
		{Unfixed, Unfixed, false},
		{Pending, Unfixed, false},
		{Unscannable, FixedInMain, true},
		{Pending, InGit, true},
		{FixedInMain, Pending, false},
	}
	for _, tt := range tests {
		if got := Advanced(tt.from, tt.to); got != tt.want {
			t.Errorf("Advanced(%q, %q) = %v, want %v", tt.from, tt.to, got, tt.want)
		}
	}
}
