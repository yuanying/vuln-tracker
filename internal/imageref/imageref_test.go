package imageref

import (
	"testing"

	"github.com/openvex/go-vex/pkg/vex"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want Ref
	}{
		{"ghcr.io/yuanying/hshelf:1.0.0", Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0"}},
		{"nginx:1.30.6-alpine", Ref{Registry: "index.docker.io", Repository: "library/nginx", Tag: "1.30.6-alpine"}},
		{"docker.io/longhornio/longhorn-engine:v1.13.0", Ref{Registry: "index.docker.io", Repository: "longhornio/longhorn-engine", Tag: "v1.13.0"}},
		{"index.docker.io/library/httpd:2.4.69-alpine", Ref{Registry: "index.docker.io", Repository: "library/httpd", Tag: "2.4.69-alpine"}},
		{"quay.io/metallb/speaker", Ref{Registry: "quay.io", Repository: "metallb/speaker"}},
		{
			"ghcr.io/yuanying/hshelf:1.0.0@sha256:28bed156fd3edf8f3899f4e669608e0faa16d25c51904bd04ce40ec4c4e06b5e",
			Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: "sha256:28bed156fd3edf8f3899f4e669608e0faa16d25c51904bd04ce40ec4c4e06b5e"},
		},
		{"registry.fraction.jp:5000/llm-wiki:main", Ref{Registry: "registry.fraction.jp:5000", Repository: "llm-wiki", Tag: "main"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "UPPER/case:tag", "a b"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", in)
		}
	}
}

func TestNameAndString(t *testing.T) {
	r := Ref{Registry: "index.docker.io", Repository: "library/nginx", Tag: "1.30.6-alpine", Digest: "sha256:abc"}
	if got, want := r.Name(), "index.docker.io/library/nginx"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
	if got, want := r.String(), "index.docker.io/library/nginx:1.30.6-alpine@sha256:abc"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got, want := r.WithDigestOnly().String(), "index.docker.io/library/nginx@sha256:abc"; got != want {
		t.Errorf("WithDigestOnly().String() = %q, want %q", got, want)
	}
}

// Trivy Operator writes the repository name into the tag when the image was
// referenced as name:tag@digest through a kustomize newTag, so only what
// follows the last colon is the tag.
func TestReportTag(t *testing.T) {
	tests := map[string]string{
		"1.0.0":                     "1.0.0",
		"httpd:2.4.69-alpine":       "2.4.69-alpine",
		"nginx:1.30.6-alpine":       "1.30.6-alpine",
		"searxng/searxng:2026.10.25-54ca1d9cf": "2026.10.25-54ca1d9cf",
		"":                          "",
	}
	for in, want := range tests {
		if got := ReportTag(in); got != want {
			t.Errorf("ReportTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPURL(t *testing.T) {
	r := Ref{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: "sha256:28bed156"}
	got := r.PURL()
	// The forms security/vex/README.md in fleet-infra tells annotators to
	// write: every version, and one version by digest.
	for _, vexSide := range []string{
		"pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf",
		"pkg:oci/hshelf@sha256:28bed156?repository_url=ghcr.io/yuanying/hshelf",
	} {
		if !vex.PurlMatches(vexSide, got) {
			t.Errorf("PURL() = %q, does not match %q", got, vexSide)
		}
	}
	for _, other := range []string{
		"pkg:oci/hshelf@sha256:ffff?repository_url=ghcr.io/yuanying/hshelf",
		"pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf&tag=1.0.0",
		"pkg:oci/tumblr-like?repository_url=ghcr.io/yuanying/tumblr-like",
	} {
		if vex.PurlMatches(other, got) {
			t.Errorf("PURL() = %q, unexpectedly matches %q", got, other)
		}
	}
}

func TestShortName(t *testing.T) {
	tests := map[string]string{
		"index.docker.io/library/nginx":              "nginx",
		"index.docker.io/longhornio/longhorn-engine": "longhornio/longhorn-engine",
		"ghcr.io/yuanying/hshelf":                    "ghcr.io/yuanying/hshelf",
	}
	for in, want := range tests {
		if got := ShortName(in); got != want {
			t.Errorf("ShortName(%q) = %q, want %q", in, got, want)
		}
	}
}
