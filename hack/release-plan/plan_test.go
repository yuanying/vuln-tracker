package main

import (
	"strings"
	"testing"
)

func TestLatestVersion(t *testing.T) {
	tests := []struct {
		name   string
		tags   []string
		want   string
		wantOK bool
	}{
		{
			name: "no tags",
		},
		{
			name: "only tags that are not vX.Y.Z",
			tags: []string{"v0.17.0.1", "release-1", "v1.2", "1.2.3", "v1.2.3-rc.1"},
		},
		{
			name:   "versions compare by number, not by string",
			tags:   []string{"v0.9.0", "v0.10.0", "v0.2.11"},
			want:   "v0.10.0",
			wantOK: true,
		},
		{
			name:   "a four-part tag above the latest version is ignored",
			tags:   []string{"v0.17.0", "v0.17.0.1", "v0.16.3"},
			want:   "v0.17.0",
			wantOK: true,
		},
		{
			name:   "vuln-tracker's tags",
			tags:   []string{"v0.1.0", "v0.2.0"},
			want:   "v0.2.0",
			wantOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := LatestVersion(tt.tags)
			if ok != tt.wantOK {
				t.Fatalf("LatestVersion(%q) ok = %v, want %v", tt.tags, ok, tt.wantOK)
			}
			if ok && got.String() != tt.want {
				t.Errorf("LatestVersion(%q) = %s, want %s", tt.tags, got, tt.want)
			}
		})
	}
}

func TestDecide(t *testing.T) {
	latest := Version{Major: 0, Minor: 2, Patch: 0}
	renovate := func(subject string) Commit { return Commit{Author: RenovateAuthor, Subject: subject} }

	tests := []struct {
		name        string
		commits     []Commit
		changed     []string
		wantRelease bool
		wantReason  string
	}{
		{
			name: "only Renovate, and the image's content changed",
			commits: []Commit{
				renovate("chore(deps): update module github.com/google/go-containerregistry to v0.21.1"),
				renovate("chore(deps): update mirror.gcr.io/aquasec/trivy docker tag to v0.75.1"),
			},
			changed:     []string{"go.mod", "go.sum", "Dockerfile"},
			wantRelease: true,
		},
		{
			name: "a change to the source counts as the image's content",
			commits: []Commit{
				renovate("chore(deps): update module golang.org/x/net to v0.47.1"),
			},
			changed:     []string{"internal/registry/client.go"},
			wantRelease: true,
		},
		{
			name: "a commit by someone else leaves the release to a human",
			commits: []Commit{
				renovate("chore(deps): update kubernetes monorepo"),
				{Author: "OTSUKA, Yuanying", Subject: "Ask vuln-responder over A2A about new untreated Criticals"},
			},
			changed:    []string{"go.mod", "go.sum", "internal/responder/client.go"},
			wantReason: "not by renovate[bot]",
		},
		{
			name: "only Renovate, but only the workflows and renovate.json changed",
			commits: []Commit{
				renovate("chore(deps): update github-actions"),
				renovate("chore(config): migrate renovate config"),
			},
			changed:    []string{".github/workflows/ci.yml", ".github/workflows/publish.yml", "renovate.json"},
			wantReason: "nothing the image is built from",
		},
		{
			name: "only Renovate, but only the manifests changed",
			commits: []Commit{
				renovate("chore(deps): pin dependencies"),
			},
			changed:    []string{"config/manager/deployment.yaml"},
			wantReason: "nothing the image is built from",
		},
		{
			name:       "no commits since the tag",
			wantReason: "no commits since v0.2.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(latest, tt.commits, tt.changed)
			if got.Release != tt.wantRelease {
				t.Fatalf("Decide().Release = %v, want %v (reason: %s)", got.Release, tt.wantRelease, got.Reason)
			}
			if got.Reason == "" {
				t.Error("Decide().Reason is empty; every outcome says why")
			}
			if !strings.Contains(got.Reason, tt.wantReason) {
				t.Errorf("Decide().Reason = %q, want it to contain %q", got.Reason, tt.wantReason)
			}
			if !got.Release {
				if got.Version != "" || got.Message != "" {
					t.Errorf("Decide() without a release has Version %q and Message %q, want both empty", got.Version, got.Message)
				}
				return
			}
			if got.Version != "v0.2.1" {
				t.Errorf("Decide().Version = %q, want v0.2.1", got.Version)
			}
			if !strings.HasPrefix(got.Message, "v0.2.1: dependency updates\n\n") {
				t.Errorf("Decide().Message = %q, want it to open with the version and say these are dependency updates", got.Message)
			}
			for _, c := range tt.commits {
				if !strings.Contains(got.Message, "- "+c.Subject+"\n") {
					t.Errorf("Decide().Message = %q, want it to list %q", got.Message, c.Subject)
				}
			}
		})
	}
}

func TestIsImageContent(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"Dockerfile", true},
		{"go.mod", true},
		{"go.sum", true},
		{"cmd/vuln-tracker/main.go", true},
		{"internal/stage/stage.go", true},
		{".github/workflows/ci.yml", false},
		{"renovate.json", false},
		{"hack/release-plan/plan.go", false},
		{"config/manager/deployment.yaml", false},
		{"testdata/crds/aquasecurity.github.io_vulnerabilityreports.yaml", false},
		{"docs/adr/0010-weekly-dependency-release.md", false},
		{"README.md", false},
		{"Makefile", false},
		{"internalx/file.go", false},
	}
	for _, tt := range tests {
		if got := IsImageContent(tt.path); got != tt.want {
			t.Errorf("IsImageContent(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
