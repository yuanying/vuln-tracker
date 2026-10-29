package pipeline

import (
	"testing"

	"github.com/yuanying/vuln-tracker/internal/stage"
)

func gone(c stage.Candidate) stage.Outcome {
	return stage.Outcome{Candidate: c, Result: stage.Scanned}
}

func present(c stage.Candidate) stage.Outcome {
	return stage.Outcome{Candidate: c, Result: stage.Scanned, Present: true}
}

func failed(c stage.Candidate) stage.Outcome {
	return stage.Outcome{Candidate: c, Result: stage.Failed}
}

func pending(c stage.Candidate) stage.Outcome {
	return stage.Outcome{Candidate: c, Result: stage.NotScanned}
}

func self(outcomes ...stage.Outcome) Input {
	return Input{Discovered: true, Origin: stage.SelfBuilt, Outcomes: outcomes}
}

func external(outcomes ...stage.Outcome) Input {
	return Input{Discovered: true, Origin: stage.External, Outcomes: outcomes}
}

func TestSource(t *testing.T) {
	tests := []struct {
		name   string
		in     Input
		prOpen bool
		want   SourceState
	}{
		{"not discovered yet", Input{}, false, SourceUnknown},
		{"external", external(gone(stage.Upstream)), false, SourceNotApplicable},
		{"released", self(present(stage.Main), gone(stage.Release)), false, SourceReleased},
		{"released wins over an open PR", self(gone(stage.Release)), true, SourceReleased},
		// :main is skipped when it is the release's commit; the release
		// says it all.
		{"released, main skipped", self(gone(stage.Release), gone(stage.Git)), false, SourceReleased},
		{"merged", self(gone(stage.Main), present(stage.Release)), false, SourceMerged},
		{"merged with an open PR", self(gone(stage.Main)), true, SourceMerged},
		{"merged though the release failed", self(gone(stage.Main), failed(stage.Release)), false, SourceMerged},
		{"pr open", self(present(stage.Main), present(stage.Release)), true, SourcePROpen},
		{"unaddressed", self(present(stage.Main), present(stage.Release)), false, SourceUnaddressed},
		{"unaddressed without candidates", self(), false, SourceUnaddressed},
		// git does not tell about the source.
		{"git alone does not count", self(present(stage.Main), gone(stage.Git)), false, SourceUnaddressed},
		{"main not scanned yet", self(pending(stage.Main), present(stage.Release)), true, SourceUnknown},
		{"release failed", self(present(stage.Main), failed(stage.Release)), false, SourceUnknown},
		{"registry unreadable", Input{Discovered: true, Origin: stage.SelfBuilt, DiscoveryFailed: true}, true, SourceUnknown},
	}
	for _, tt := range tests {
		if got := Source(tt.in, tt.prOpen); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestManifest(t *testing.T) {
	tests := []struct {
		name   string
		in     Input
		prOpen bool
		want   ManifestState
	}{
		{"not discovered yet", Input{}, false, ManifestUnknown},
		{"merged (self-built)", self(gone(stage.Release), gone(stage.Git)), false, ManifestMerged},
		{"merged (external)", external(gone(stage.Upstream), gone(stage.Git)), false, ManifestMerged},
		{"merged though nothing else was scanned", external(pending(stage.Upstream), gone(stage.Git)), false, ManifestMerged},
		{"one of two git versions is enough", external(present(stage.Git), gone(stage.Git)), false, ManifestMerged},
		{"git not scanned yet", self(gone(stage.Release), pending(stage.Git)), true, ManifestUnknown},
		{"git failed", external(gone(stage.Upstream), failed(stage.Git)), false, ManifestUnknown},
		{"release fixed, unaddressed", self(gone(stage.Release), present(stage.Git)), false, ManifestUnaddressed},
		{"release fixed, pr open", self(gone(stage.Release)), true, ManifestPROpen},
		{"upstream fixed, unaddressed", external(gone(stage.Upstream)), false, ManifestUnaddressed},
		{"upstream fixed, pr open", external(gone(stage.Upstream), present(stage.Git)), true, ManifestPROpen},
		// Fixed in :main only: nothing to bump to yet.
		{"fixed in main only", self(gone(stage.Main), present(stage.Release)), true, ManifestNoFix},
		{"no candidates", external(), false, ManifestNoFix},
		{"upstream still has it", external(present(stage.Upstream)), true, ManifestNoFix},
		// The upstream candidate does not count for a self-built image.
		{"upstream ignored for self-built", self(gone(stage.Upstream)), false, ManifestNoFix},
		{"release not scanned yet", self(gone(stage.Main), pending(stage.Release)), false, ManifestUnknown},
		{"upstream failed", external(failed(stage.Upstream)), false, ManifestUnknown},
		{"registry unreadable", Input{Discovered: true, Origin: stage.External, DiscoveryFailed: true}, false, ManifestUnknown},
		{"registry unreadable but a fix was found", Input{Discovered: true, Origin: stage.External, DiscoveryFailed: true, Outcomes: []stage.Outcome{gone(stage.Upstream)}}, false, ManifestUnaddressed},
	}
	for _, tt := range tests {
		if got := Manifest(tt.in, tt.prOpen); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}
