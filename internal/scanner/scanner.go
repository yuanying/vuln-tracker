// Package scanner scans a candidate version by running the trivy binary as a
// client of the shared Trivy server (ADR 0003). Trivy's Go packages are not
// imported: the binary is the same path Trivy Operator's scan jobs take, so the
// results line up with the VulnerabilityReports.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Key names a vulnerability in a package. A finding is gone from a candidate
// when its Key is not in the candidate's Set.
type Key struct {
	VulnerabilityID string
	Package         string
}

// Set is the vulnerabilities found in one image.
type Set map[Key]struct{}

// Has reports whether the vulnerability is in the set.
func (s Set) Has(k Key) bool {
	_, ok := s[k]
	return ok
}

// Scanner scans one image, named by digest.
type Scanner interface {
	Scan(ctx context.Context, ref string) (Set, error)
}

type report struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID string `json:"VulnerabilityID"`
			PkgName         string `json:"PkgName"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseReport reads trivy's JSON output.
func ParseReport(b []byte) (Set, error) {
	var r report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("reading trivy's report: %w", err)
	}
	set := Set{}
	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			set[Key{VulnerabilityID: v.VulnerabilityID, Package: v.PkgName}] = struct{}{}
		}
	}
	return set, nil
}

// Trivy runs the trivy binary in client mode.
type Trivy struct {
	// Binary is the path of trivy.
	Binary string
	// ServerURL is the Trivy server, e.g. http://trivy-service.trivy-system:4954.
	ServerURL string
	// Token is the server's token, if it has one. It is passed through the
	// environment.
	Token string
	// CacheDir keeps what the client downloads for itself (the Java DB).
	CacheDir string
	// TempDir is where trivy writes its temporary files. It is emptied after
	// every scan.
	TempDir string
	// Timeout bounds one scan.
	Timeout time.Duration

	run func(ctx context.Context, name string, args, env []string) ([]byte, error)
}

func (t *Trivy) args(ref string) []string {
	args := []string{
		"image",
		"--server", t.ServerURL,
		"--image-src", "remote",
		"--format", "json",
		"--scanners", "vuln",
		"--quiet",
		"--no-progress",
	}
	if t.CacheDir != "" {
		args = append(args, "--cache-dir", t.CacheDir)
	}
	if t.Timeout > 0 {
		args = append(args, "--timeout", t.Timeout.String())
	}
	return append(args, ref)
}

func (t *Trivy) env() []string {
	env := os.Environ()
	if t.TempDir != "" {
		env = append(env, "TMPDIR="+t.TempDir)
	}
	if t.Token != "" {
		env = append(env, "TRIVY_TOKEN="+t.Token)
	}
	return env
}

// Scan runs one scan and parses its report.
func (t *Trivy) Scan(ctx context.Context, ref string) (Set, error) {
	defer t.cleanTemp()
	if t.Timeout > 0 {
		var cancel context.CancelFunc
		// A little longer than trivy's own timeout, so trivy reports it.
		ctx, cancel = context.WithTimeout(ctx, t.Timeout+time.Minute)
		defer cancel()
	}
	run := t.run
	if run == nil {
		run = execRun
	}
	out, err := run(ctx, t.Binary, t.args(ref), t.env())
	if err != nil {
		return nil, fmt.Errorf("scanning %s: %w", ref, err)
	}
	return ParseReport(out)
}

func (t *Trivy) cleanTemp() {
	if t.TempDir == "" {
		return
	}
	entries, err := os.ReadDir(t.TempDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(t.TempDir, e.Name()))
	}
}

func execRun(ctx context.Context, name string, args, env []string) ([]byte, error) {
	// The binary path is configuration and the image reference is one the
	// tracker built itself from a registry name and a digest.
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return nil, fmt.Errorf("%w: %s", err, msg)
	}
	return stdout.Bytes(), nil
}
