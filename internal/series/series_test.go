package series

import (
	"regexp"
	"testing"
)

func TestNewestInSeries(t *testing.T) {
	tests := []struct {
		name    string
		running string
		tags    []string
		want    string
		wantOK  bool
	}{
		{
			name:    "same major and suffix, newest wins",
			running: "1.30.5-alpine",
			tags:    []string{"1.30.5-alpine", "1.30.6-alpine", "1.31.8-alpine", "1.31.8", "2.0.0-alpine", "1.31.10-alpine-slim", "latest"},
			want:    "1.31.8-alpine",
			wantOK:  true,
		},
		{
			name:    "v prefix must agree",
			running: "v1.13.0",
			tags:    []string{"1.14.0", "v1.13.1", "v1.13.0"},
			want:    "v1.13.1",
			wantOK:  true,
		},
		{
			name:    "double digits compare as numbers",
			running: "v0.9.0",
			tags:    []string{"v0.10.0", "v0.9.1"},
			want:    "v0.10.0",
			wantOK:  true,
		},
		{
			name:    "nothing newer",
			running: "v0.16.1",
			tags:    []string{"v0.16.1", "v0.16.0"},
			wantOK:  false,
		},
		{
			name:    "a running tag without a version has no series",
			running: "latest",
			tags:    []string{"1.0.0"},
			wantOK:  false,
		},
		{
			name:    "distroless suffix",
			running: "v3.15.0-distroless",
			tags:    []string{"v3.15.1", "v3.16.0-distroless", "v4.0.0-distroless"},
			want:    "v3.16.0-distroless",
			wantOK:  true,
		},
		{
			name:    "two-part versions",
			running: "3.24",
			tags:    []string{"3.25", "3.24.1"},
			want:    "3.25",
			wantOK:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NewestInSeries(tt.running, tt.tags, nil)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("NewestInSeries(%q) = %q, %v; want %q, %v", tt.running, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// A pattern from the fleet-infra table replaces the default series: its first
// capture group is the version that is compared, and both tags must match it.
func TestNewestInSeriesWithPattern(t *testing.T) {
	p := regexp.MustCompile(`^(\d+\.\d+\.\d+)-[0-9a-f]+$`)
	got, ok := NewestInSeries("2026.10.25-54ca1d9cf", []string{"2026.10.26-0abc123", "2026.11.1-ffff000", "latest"}, p)
	if !ok || got != "2026.11.1-ffff000" {
		t.Errorf("got %q, %v; want 2026.11.1-ffff000, true", got, ok)
	}
	if _, ok := NewestInSeries("latest", []string{"2026.10.26-0abc123"}, p); ok {
		t.Error("a running tag that does not match the pattern has no series")
	}
}

func TestNewestRelease(t *testing.T) {
	tests := []struct {
		name    string
		running string
		tags    []string
		want    string
		wantOK  bool
	}{
		{"newer release", "1.0.0", []string{"main", "1.0.0", "1.0", "latest", "1.1.0", "1.0.1"}, "1.1.0", true},
		{"v prefixed", "v0.1.52", []string{"v0.1.52", "v0.1.53", "main", "sha-abc"}, "v0.1.53", true},
		{"any major", "0.4.0", []string{"1.0.0", "0.5.0"}, "1.0.0", true},
		{"nothing newer", "1.0.0", []string{"1.0.0", "0.9.0", "main"}, "", false},
		{"prerelease is not a release", "1.0.0", []string{"1.1.0-rc.1"}, "", false},
		{"running is not a version", "main", []string{"0.1.0", "0.2.0"}, "0.2.0", true},
		{"partial version tags are aliases", "1.0.0", []string{"1", "1.1"}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NewestRelease(tt.running, tt.tags)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("NewestRelease(%q) = %q, %v; want %q, %v", tt.running, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestIsVersion(t *testing.T) {
	for tag, want := range map[string]bool{
		"1.0.0": true, "v1.13.0": true, "1.30.6-alpine": true, "3.24": true,
		"latest": false, "alpine": false, "main": false, "": false, "ee09717": false,
	} {
		if got := IsVersion(tag); got != want {
			t.Errorf("IsVersion(%q) = %v, want %v", tag, got, want)
		}
	}
}
