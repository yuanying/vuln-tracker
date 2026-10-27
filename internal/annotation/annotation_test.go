package annotation

import (
	"os"
	"strings"
	"testing"
)

const (
	hshelfPath    = "security/vex/ghcr.io/yuanying/hshelf.openvex.json"
	longhornPath  = "security/vex/index.docker.io/longhornio/longhorn-engine.openvex.json"
	hshelfPURL    = "pkg:oci/hshelf@sha256:28bed156fd3edf8f3899f4e669608e0faa16d25c51904bd04ce40ec4c4e06b5e?repository_url=ghcr.io%2Fyuanying%2Fhshelf"
	longhornPURL  = "pkg:oci/longhorn-engine@sha256:b0cc5090889d57705acd69c5106492992e84560170ac3bec4a1cc8dd3fe83ca6?repository_url=index.docker.io%2Flonghornio%2Flonghorn-engine"
	longhornOther = "pkg:oci/longhorn-engine@sha256:0000000000000000000000000000000000000000000000000000000000000000?repository_url=index.docker.io%2Flonghornio%2Flonghorn-engine"
)

func fixtures(t *testing.T) map[string][]byte {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return map[string][]byte{
		hshelfPath:   read("hshelf.openvex.json"),
		longhornPath: read("longhorn-engine.openvex.json"),
		// Not a VEX file: ignored, not an error.
		"security/vex/README.md":    []byte("# security/vex"),
		"apps/x/kustomization.yaml": []byte("images: []"),
	}
}

func TestLookup(t *testing.T) {
	set, errs := Load(fixtures(t))
	if len(errs) != 0 {
		t.Fatalf("Load: %v", errs)
	}
	tests := []struct {
		name      string
		vuln      string
		image     string
		pkg       string
		wantOK    bool
		wantState string
	}{
		{"every version, matching subcomponent", "CVE-2026-33210", hshelfPURL, "pkg:gem/json@2.18.0", true, "upstream"},
		{"subcomponent names another package", "CVE-2026-33210", hshelfPURL, "pkg:gem/rack@3.0.0", false, ""},
		{"no package purl: the product alone matches", "CVE-2026-33210", hshelfPURL, "", true, "upstream"},
		{"another vulnerability", "CVE-2026-54696", hshelfPURL, "pkg:gem/json@2.18.0", false, ""},
		{"one version by digest", "SUSE-SU-2026:4619-1", longhornPURL, "pkg:rpm/sles/libexpat1@2.7.1", true, "upstream"},
		{"another digest of the same image", "SUSE-SU-2026:4619-1", longhornOther, "pkg:rpm/sles/libexpat1@2.7.1", false, ""},
		{"another image", "CVE-2026-33210", longhornPURL, "pkg:gem/json@2.18.0", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, ok := set.Lookup(tt.vuln, tt.image, tt.pkg)
			if ok != tt.wantOK {
				t.Fatalf("Lookup ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && a.State != tt.wantState {
				t.Errorf("State = %q, want %q", a.State, tt.wantState)
			}
		})
	}
}

func TestAnnotationFields(t *testing.T) {
	set, _ := Load(fixtures(t))
	a, ok := set.Lookup("SUSE-SU-2026:4619-1", longhornPURL, "")
	if !ok {
		t.Fatal("no annotation")
	}
	if a.Status != "affected" || a.ReviewBy != "2026-11-30" || a.Tag != "v1.13.0" || a.Path != longhornPath {
		t.Errorf("got %+v", a)
	}
	if !strings.HasPrefix(a.Reason, "Waiting for upstream.") {
		t.Errorf("Reason should be the action_statement for affected, got %q", a.Reason)
	}
	h, _ := set.Lookup("CVE-2026-33210", hshelfPURL, "")
	if h.Status != "not_affected" || !strings.HasPrefix(h.Reason, "json 2.18.0") {
		t.Errorf("Reason should be the impact_statement for not_affected, got %+v", h)
	}
}

func TestExpired(t *testing.T) {
	a := Annotation{ReviewBy: "2026-11-30"}
	for today, want := range map[string]bool{
		"2026-11-29": false,
		"2026-11-30": false, // the review-by day itself is still in time
		"2026-12-01": true,
	} {
		if got := a.Expired(today); got != want {
			t.Errorf("Expired(%s) = %v, want %v", today, got, want)
		}
	}
}

func TestNewestStatementWins(t *testing.T) {
	doc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://github.com/yuanying/fleet-infra/security/vex/ghcr.io/yuanying/hshelf",
  "author": "yuanying",
  "timestamp": "2026-10-01T00:00:00Z",
  "version": 2,
  "statements": [
    {"vulnerability": {"name": "CVE-1"}, "timestamp": "2026-10-27T00:00:00Z",
     "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf"}],
     "status": "affected", "action_statement": "newer",
     "status_notes": "state: in-progress\nreview-by: 2026-11-01"},
    {"vulnerability": {"name": "CVE-1"}, "timestamp": "2026-10-01T00:00:00Z",
     "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf"}],
     "status": "under_investigation", "action_statement": "older",
     "status_notes": "state: investigating\nreview-by: 2026-11-01"}
  ]
}`
	set, errs := Load(map[string][]byte{hshelfPath: []byte(doc)})
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	a, ok := set.Lookup("CVE-1", hshelfPURL, "")
	if !ok || a.Reason != "newer" || a.State != "in-progress" {
		t.Errorf("got %+v, %v", a, ok)
	}
}

// A statement whose status_notes break the convention in fleet-infra's README
// is dropped and counted; the rest of the document still applies.
func TestBadStatusNotes(t *testing.T) {
	doc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "x",
  "author": "yuanying",
  "timestamp": "2026-10-01T00:00:00Z",
  "version": 1,
  "statements": [
    {"vulnerability": {"name": "CVE-1"}, "timestamp": "2026-10-27T00:00:00Z",
     "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf"}],
     "status": "affected", "action_statement": "a",
     "status_notes": "state: in-progress"},
    {"vulnerability": {"name": "CVE-2"}, "timestamp": "2026-10-27T00:00:00Z",
     "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf"}],
     "status": "affected", "action_statement": "b",
     "status_notes": "state: in-progress\nreview-by: 2026-13-45"},
    {"vulnerability": {"name": "CVE-3"}, "timestamp": "2026-10-27T00:00:00Z",
     "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf"}],
     "status": "affected", "action_statement": "c",
     "status_notes": "state: someday\nreview-by: 2026-11-01"},
    {"vulnerability": {"name": "CVE-4"}, "timestamp": "2026-10-27T00:00:00Z",
     "products": [{"@id": "pkg:oci/hshelf?repository_url=ghcr.io/yuanying/hshelf"}],
     "status": "affected", "action_statement": "d",
     "status_notes": "state: upstream\nreview-by: 2026-11-01"}
  ]
}`
	set, errs := Load(map[string][]byte{hshelfPath: []byte(doc)})
	if len(errs) != 3 {
		t.Errorf("got %d errors, want 3: %v", len(errs), errs)
	}
	for _, v := range []string{"CVE-1", "CVE-2", "CVE-3"} {
		if _, ok := set.Lookup(v, hshelfPURL, ""); ok {
			t.Errorf("%s: a statement with bad status_notes was used", v)
		}
	}
	if _, ok := set.Lookup("CVE-4", hshelfPURL, ""); !ok {
		t.Error("CVE-4: the good statement was dropped with the bad ones")
	}
}

func TestUnreadableDocument(t *testing.T) {
	files := fixtures(t)
	files["security/vex/quay.io/x/y.openvex.json"] = []byte("{not json")
	set, errs := Load(files)
	if len(errs) != 1 {
		t.Errorf("got %d errors, want 1", len(errs))
	}
	if _, ok := set.Lookup("CVE-2026-33210", hshelfPURL, ""); !ok {
		t.Error("the other documents should still be used")
	}
}

func TestPathFor(t *testing.T) {
	if got, want := PathFor("index.docker.io/library/nginx"), "security/vex/index.docker.io/library/nginx.openvex.json"; got != want {
		t.Errorf("PathFor = %q, want %q", got, want)
	}
}
