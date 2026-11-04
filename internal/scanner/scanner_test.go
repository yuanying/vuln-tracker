package scanner

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const trivyReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "ghcr.io/yuanying/hshelf@sha256:aaaa",
  "Results": [
    {
      "Target": "ghcr.io/yuanying/hshelf (alpine 3.24.3)",
      "Class": "os-pkgs",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-0001", "PkgName": "libssl3", "InstalledVersion": "3.5.0-r0", "FixedVersion": "3.5.1-r0", "Severity": "HIGH"}
      ]
    },
    {
      "Target": "Ruby",
      "Class": "lang-pkgs",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-33210", "PkgName": "json", "InstalledVersion": "2.18.0", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2026-33210", "PkgName": "json", "InstalledVersion": "2.19.0", "Severity": "CRITICAL"}
      ]
    },
    {"Target": "app/Gemfile.lock", "Class": "lang-pkgs"}
  ]
}`

func TestParseReport(t *testing.T) {
	got, err := ParseReport([]byte(trivyReport))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %d findings, want 2: %v", len(got), got)
	}
	for _, k := range []Key{{"CVE-2026-0001", "libssl3"}, {"CVE-2026-33210", "json"}} {
		if !got.Has(k) {
			t.Errorf("missing %v", k)
		}
	}
	if got.Has(Key{"CVE-2026-33210", "rack"}) {
		t.Error("a package that is not in the trivyReport was found")
	}
	if _, err := ParseReport([]byte("not json")); err == nil {
		t.Error("garbage parsed")
	}
}

func TestArgs(t *testing.T) {
	tr := &Trivy{Binary: "/usr/local/bin/trivy", ServerURL: "http://trivy-service.trivy-system:4954", CacheDir: "/work/cache", Timeout: 10 * time.Minute, Token: "s3cret"}
	args := tr.args("ghcr.io/yuanying/hshelf@sha256:aaaa")
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"image",
		"--server http://trivy-service.trivy-system:4954",
		"--image-src remote",
		"--format json",
		"--scanners vuln",
		"--cache-dir /work/cache",
		"--timeout 10m0s",
		"--quiet",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q lack %q", joined, want)
		}
	}
	if args[len(args)-1] != "ghcr.io/yuanying/hshelf@sha256:aaaa" {
		t.Errorf("the image should be the last argument: %v", args)
	}
	// The token goes through the environment, never the command line, where
	// anything that lists processes could read it.
	if strings.Contains(joined, "s3cret") {
		t.Errorf("the token is on the command line: %q", joined)
	}
	if !slices.Contains(tr.env(), "TRIVY_TOKEN=s3cret") {
		t.Errorf("env lacks the token: %v", tr.env())
	}
	if slices.ContainsFunc((&Trivy{}).env(), func(s string) bool { return strings.HasPrefix(s, "TRIVY_TOKEN=") }) {
		t.Error("an empty token should not be set")
	}
}

// skippedPatterns returns the patterns given to --skip-files.
func skippedPatterns(args []string) []string {
	var patterns []string
	for i, a := range args {
		if a == "--skip-files" && i+1 < len(args) {
			patterns = append(patterns, args[i+1])
		}
	}
	return patterns
}

// TestArgsSkipJavaArchives pins that the Java archives never reach trivy's
// jar analyzer, so trivy never downloads the Java DB (ADR 0003). The patterns
// are doublestar globs over the path in the image; "**/" matches any
// directory, so the file name part is checked here with path.Match.
func TestArgsSkipJavaArchives(t *testing.T) {
	patterns := skippedPatterns((&Trivy{ServerURL: "http://x"}).args("x@sha256:aaaa"))
	if len(patterns) == 0 {
		t.Fatal("no --skip-files in the args")
	}
	skipped := func(file string) bool {
		for _, p := range patterns {
			name, ok := strings.CutPrefix(p, "**/")
			if !ok {
				t.Fatalf("pattern %q does not start with **/", p)
			}
			if m, err := path.Match(name, path.Base(file)); err != nil {
				t.Fatalf("pattern %q: %v", p, err)
			} else if m {
				return true
			}
		}
		return false
	}
	// trivy 0.76.1's jar analyzer takes these extensions, ignoring case.
	for _, tc := range []struct {
		file string
		want bool
	}{
		{"usr/share/java/libintl.jar", true},
		{"app/app.war", true},
		{"opt/app.ear", true},
		{"opt/app.par", true},
		{"opt/App.JAR", true},
		{"opt/App.War", true},
		{"app.jar", true},
		{"app/Gemfile.lock", false},
		{"usr/lib/python3/dist-packages/foo.py", false},
		{"opt/app.jar.sha1", false},
		{"opt/app.rar", false},
		{"opt/app.tar", false},
		{"usr/bin/jar", false},
	} {
		if got := skipped(tc.file); got != tc.want {
			t.Errorf("skipped(%q) = %v, want %v (patterns %v)", tc.file, got, tc.want, patterns)
		}
	}
}

func TestScan(t *testing.T) {
	tmp := t.TempDir()
	tr := &Trivy{Binary: "trivy", ServerURL: "http://x", TempDir: tmp}
	var gotEnv []string
	tr.run = func(_ context.Context, name string, args, env []string) ([]byte, error) {
		gotEnv = env
		// Leave something behind, as a scan of a large image does.
		if err := os.WriteFile(filepath.Join(tmp, "layer.tar"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return []byte(trivyReport), nil
	}
	got, err := tr.Scan(context.Background(), "ghcr.io/yuanying/hshelf@sha256:aaaa")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("got %v", got)
	}
	if !slices.Contains(gotEnv, "TMPDIR="+tmp) {
		t.Errorf("TMPDIR not set to the work area: %v", gotEnv)
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 0 {
		t.Errorf("the work area was not emptied: %v", entries)
	}
}

func TestScanFails(t *testing.T) {
	tr := &Trivy{Binary: "trivy", ServerURL: "http://x", TempDir: t.TempDir()}
	tr.run = func(context.Context, string, []string, []string) ([]byte, error) {
		return nil, errors.New("exit status 1: MANIFEST_UNKNOWN")
	}
	if _, err := tr.Scan(context.Background(), "x@sha256:aaaa"); err == nil {
		t.Error("a failed run should be an error")
	}
}
