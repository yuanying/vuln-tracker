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
  {"html_url": "https://github.com/yuanying/fleet-infra/pull/9", "title": "Update quay.io/kiwigrid/k8s-sidecar Docker tag to v2.15.0", "body": "x", "user": {"login": "renovate-y[bot]"}},
  {"html_url": "https://github.com/yuanying/fleet-infra/pull/8", "title": "Add vuln-tracker", "body": null, "user": {"login": "yuanying"}}
]`))
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
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
