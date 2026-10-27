package sources

import "testing"

func TestParse(t *testing.T) {
	tbl, err := Parse([]byte(`
images:
- image: index.docker.io/longhornio/longhorn-engine
  source: https://github.com/longhorn/longhorn-engine
- image: index.docker.io/searxng/searxng
  tagPattern: '^(\d+\.\d+\.\d+)-[0-9a-f]+$'
`))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := tbl.Lookup("index.docker.io/longhornio/longhorn-engine")
	if !ok || e.Source != "https://github.com/longhorn/longhorn-engine" || e.TagPattern != nil {
		t.Errorf("longhorn-engine: %+v, %v", e, ok)
	}
	e, ok = tbl.Lookup("index.docker.io/searxng/searxng")
	if !ok || e.Source != "" || e.TagPattern == nil || !e.TagPattern.MatchString("2026.10.25-54ca1d9cf") {
		t.Errorf("searxng: %+v, %v", e, ok)
	}
	if _, ok := tbl.Lookup("ghcr.io/yuanying/hshelf"); ok {
		t.Error("an image not in the table was found")
	}
}

func TestParseErrors(t *testing.T) {
	for name, in := range map[string]string{
		"bad yaml":      "images: [",
		"bad pattern":   "images:\n- image: a/b\n  tagPattern: '('\n",
		"no image":      "images:\n- source: https://example.com\n",
		"duplicate":     "images:\n- image: a/b\n- image: a/b\n",
		"unknown field": "images:\n- image: a/b\n  sauce: x\n",
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: Parse succeeded, want an error", name)
		}
	}
}

// A missing file is an empty table: the file is optional in fleet-infra.
func TestEmpty(t *testing.T) {
	tbl, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tbl.Lookup("a/b"); ok {
		t.Error("empty table found an image")
	}
}
