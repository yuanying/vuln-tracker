package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func tarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	// GitHub puts everything under one top directory named after the commit.
	if err := tw.WriteHeader(&tar.Header{Name: "yuanying-fleet-infra-abc1234/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		hdr := &tar.Header{Name: "yuanying-fleet-infra-abc1234/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func server(t *testing.T, wantToken string) *httptest.Server {
	t.Helper()
	tb := tarball(t, map[string]string{
		"apps/a/kustomization.yaml":           "images: []",
		"security/vex/README.md":              "# vex",
		"security/vex/ghcr.io/a.openvex.json": "{}",
		"security/image-sources.yaml":         "images: []",
		"docs/big.bin":                        "binary",
	})
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if wantToken != "" && r.Header.Get("Authorization") != "Bearer "+wantToken {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /repos/yuanying/fleet-infra/commits/main", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github.sha" {
			http.Error(w, "want the sha media type", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("abc1234def"))
	}))
	mux.HandleFunc("GET /repos/yuanying/fleet-infra/tarball/abc1234def", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tb)
	}))
	mux.HandleFunc("GET /repos/yuanying/fleet-infra/pulls", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != "open" {
			http.Error(w, "want open", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`[
  {"html_url": "https://github.com/yuanying/fleet-infra/pull/9", "number": 9, "state": "open", "title": "Update quay.io/kiwigrid/k8s-sidecar Docker tag to v2.15.0", "body": "x", "user": {"login": "renovate-y[bot]"}, "head": {"ref": "renovate/k8s-sidecar", "sha": "f00"}},
  {"html_url": "https://github.com/yuanying/fleet-infra/pull/8", "title": "Add vuln-tracker", "body": null, "user": {"login": "yuanying"}}
]`))
	}))
	mux.HandleFunc("GET /repos/yuanying/hshelf/pulls/3", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"html_url": "https://github.com/yuanying/hshelf/pull/3", "number": 3, "state": "closed", "merged_at": "2026-10-28T01:02:03Z", "title": "Bump json", "body": "CVE-2026-33210", "user": {"login": "fraction-vuln-responder[bot]"}, "head": {"ref": "vuln-responder/json", "sha": "b0b"}}`))
	}))
	mux.HandleFunc("GET /repos/yuanying/hshelf/pulls/4", auth(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"html_url": "https://github.com/yuanying/hshelf/pull/4", "number": 4, "state": "closed", "merged_at": null, "title": "Try", "body": null, "user": {"login": "yuanying"}, "head": {"ref": "try", "sha": "c0c"}}`))
	}))
	mux.HandleFunc("GET /repos/yuanying/fleet-infra/pulls/9/files", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("per_page") != "100" {
			http.Error(w, "want per_page=100", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`[{"filename": "security/vex/ghcr.io/yuanying/hshelf.openvex.json"}, {"filename": "apps/hshelf/kustomization.yaml"}]`))
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestHeadAndFiles(t *testing.T) {
	srv := server(t, "tok")
	c := &Client{BaseURL: srv.URL, Token: "tok", HTTP: srv.Client()}
	ctx := context.Background()
	sha, err := c.Head(ctx, "yuanying/fleet-infra", "main")
	if err != nil {
		t.Fatal(err)
	}
	if sha != "abc1234def" {
		t.Errorf("Head = %q", sha)
	}
	files, err := c.Files(ctx, "yuanying/fleet-infra", sha)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"apps/a/kustomization.yaml", "security/vex/ghcr.io/a.openvex.json", "security/image-sources.yaml"} {
		if _, ok := files[want]; !ok {
			t.Errorf("missing %s: %v", want, keys(files))
		}
	}
	// Only manifests and VEX documents are kept.
	for _, unwanted := range []string{"security/vex/README.md", "docs/big.bin"} {
		if _, ok := files[unwanted]; ok {
			t.Errorf("kept %s", unwanted)
		}
	}
}

func TestUnauthorised(t *testing.T) {
	srv := server(t, "tok")
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.Head(context.Background(), "yuanying/fleet-infra", "main"); err == nil {
		t.Error("a 401 should be an error")
	}
}

func TestOpenPullRequests(t *testing.T) {
	srv := server(t, "")
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	prs, err := c.OpenPullRequests(context.Background(), "yuanying/fleet-infra")
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 2 || prs[0].Author != "renovate-y[bot]" || prs[0].URL != "https://github.com/yuanying/fleet-infra/pull/9" || prs[1].Body != "" {
		t.Errorf("got %+v", prs)
	}
	want := PullRequest{
		URL: "https://github.com/yuanying/fleet-infra/pull/9", Repository: "yuanying/fleet-infra", Number: 9, State: StateOpen,
		Title: "Update quay.io/kiwigrid/k8s-sidecar Docker tag to v2.15.0", Body: "x", Author: "renovate-y[bot]",
		HeadRef: "renovate/k8s-sidecar", HeadSHA: "f00",
	}
	if prs[0] != want {
		t.Errorf("got %+v\nwant %+v", prs[0], want)
	}
}

// A pull request read by its number says whether it was merged or only
// closed.
func TestPullRequest(t *testing.T) {
	srv := server(t, "")
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	pr, err := c.PullRequest(context.Background(), "yuanying/hshelf", 3)
	if err != nil {
		t.Fatal(err)
	}
	if pr.State != StateMerged || pr.Repository != "yuanying/hshelf" || pr.Number != 3 || pr.Author != "fraction-vuln-responder[bot]" || pr.HeadRef != "vuln-responder/json" {
		t.Errorf("got %+v", pr)
	}
	pr, err = c.PullRequest(context.Background(), "yuanying/hshelf", 4)
	if err != nil {
		t.Fatal(err)
	}
	if pr.State != StateClosed {
		t.Errorf("closed without merging: %+v", pr)
	}
	if _, err := c.PullRequest(context.Background(), "yuanying/hshelf", 5); err == nil {
		t.Error("a 404 should be an error")
	}
}

func TestPullRequestFiles(t *testing.T) {
	srv := server(t, "")
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	files, err := c.PullRequestFiles(context.Background(), "yuanying/fleet-infra", 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0] != "security/vex/ghcr.io/yuanying/hshelf.openvex.json" || files[1] != "apps/hshelf/kustomization.yaml" {
		t.Errorf("got %v", files)
	}
}

func TestParsePullRequestURL(t *testing.T) {
	tests := map[string]struct {
		repo   string
		number int
		ok     bool
	}{
		"https://github.com/yuanying/hshelf/pull/3":         {"yuanying/hshelf", 3, true},
		"https://github.com/yuanying/hshelf/pull/3/files":   {"yuanying/hshelf", 3, true},
		"https://github.com/yuanying/hshelf/pull/3#comment": {"yuanying/hshelf", 3, true},
		"https://github.com/yuanying/hshelf/issues/3":       {"", 0, false},
		"https://example.com/yuanying/hshelf/pull/3":        {"", 0, false},
		"https://github.com/yuanying/hshelf/pull/x":         {"", 0, false},
		"": {"", 0, false},
	}
	for in, want := range tests {
		repo, n, ok := ParsePullRequestURL(in)
		if repo != want.repo || n != want.number || ok != want.ok {
			t.Errorf("%q: got %q %d %v, want %+v", in, repo, n, ok, want)
		}
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
