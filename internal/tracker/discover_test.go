package tracker

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/manifests"
	"github.com/yuanying/vuln-tracker/internal/registry"
	"github.com/yuanying/vuln-tracker/internal/sources"
	"github.com/yuanying/vuln-tracker/internal/stage"
)

type fakeRegistry struct {
	tags    map[string][]string          // name → tags
	digests map[string]string            // name:tag → digest
	labels  map[string]map[string]string // name@digest → labels
	fail    bool
	calls   map[string]int
}

func (f *fakeRegistry) count(op string) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[op]++
}

func (f *fakeRegistry) Tags(_ context.Context, repo string) ([]string, error) {
	f.count("tags")
	if f.fail {
		return nil, errors.New("unauthorized")
	}
	t, ok := f.tags[repo]
	if !ok {
		return nil, fmt.Errorf("%s: %w", repo, registry.ErrNotFound)
	}
	return t, nil
}

func (f *fakeRegistry) Digest(_ context.Context, ref string) (string, error) {
	f.count("digest")
	if f.fail {
		return "", errors.New("unauthorized")
	}
	d, ok := f.digests[ref]
	if !ok {
		return "", fmt.Errorf("%s: %w", ref, registry.ErrNotFound)
	}
	return d, nil
}

func (f *fakeRegistry) Labels(_ context.Context, ref string) (map[string]string, error) {
	f.count("labels")
	if f.fail {
		return nil, errors.New("unauthorized")
	}
	return f.labels[ref], nil
}

func labels(source, revision string) map[string]string {
	return map[string]string{"org.opencontainers.image.source": source, "org.opencontainers.image.revision": revision}
}

func kinds(c Candidates) []string {
	var out []string
	for _, r := range c.List {
		out = append(out, fmt.Sprintf("%s:%s@%s", r.Kind, r.Tag, r.Digest[:len("sha256:")+1]))
	}
	return out
}

func newDiscoverer(reg registry.Registry, at *time.Time) *Discoverer {
	return &Discoverer{Registry: reg, SelfSourcePrefix: "https://github.com/yuanying/", RenovateAuthor: regexp.MustCompile("renovate"), Now: func() time.Time { return *at }}
}

func TestDiscoverSelfBuilt(t *testing.T) {
	const name = "ghcr.io/yuanying/hshelf"
	reg := &fakeRegistry{
		tags:    map[string][]string{name: {"1.0.0", "1.1.0", "main", "latest"}},
		digests: map[string]string{name + ":main": dMain, name + ":1.1.0": dRelease},
		labels: map[string]map[string]string{
			name + "@" + dRun:     labels("https://github.com/yuanying/hshelf", "aaa"),
			name + "@" + dMain:    labels("https://github.com/yuanying/hshelf", "ccc"),
			name + "@" + dRelease: labels("https://github.com/yuanying/hshelf", "bbb"),
		},
	}
	at := now
	d := newDiscoverer(reg, &at)
	ix := manifests.Index{name: {
		{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.0", Digest: dRun}, // what runs
		{Registry: "ghcr.io", Repository: "yuanying/hshelf", Tag: "1.0.1", Digest: dGit},
	}}
	c := d.Discover(context.Background(), hshelf(), World{Manifests: ix})
	if c.Origin != stage.SelfBuilt || c.Source != "https://github.com/yuanying/hshelf" || c.Revision != "aaa" || c.DiscoveryFailed {
		t.Errorf("got %+v", c)
	}
	want := []string{"main:main@sha256:2", "release:1.1.0@sha256:3", "git:1.0.1@sha256:4"}
	if got := kinds(c); !slices.Equal(got, want) {
		t.Errorf("candidates %v, want %v", got, want)
	}
	if c.List[0].Revision != "ccc" || c.List[1].Revision != "bbb" {
		t.Errorf("revisions: %+v", c.List)
	}
}

// When :main is the commit the release was built from, scanning it again
// would find the same thing (ADR 0002).
func TestDiscoverSkipsMainAtTheRelease(t *testing.T) {
	const name = "ghcr.io/yuanying/hshelf"
	reg := &fakeRegistry{
		tags:    map[string][]string{name: {"1.0.0", "1.1.0", "main"}},
		digests: map[string]string{name + ":main": dMain, name + ":1.1.0": dRelease},
		labels: map[string]map[string]string{
			name + "@" + dRun:     labels("https://github.com/yuanying/hshelf", "aaa"),
			name + "@" + dMain:    labels("https://github.com/yuanying/hshelf", "bbb"),
			name + "@" + dRelease: labels("https://github.com/yuanying/hshelf", "bbb"),
		},
	}
	at := now
	c := newDiscoverer(reg, &at).Discover(context.Background(), hshelf(), World{})
	if got := kinds(c); !slices.Equal(got, []string{"release:1.1.0@sha256:3"}) {
		t.Errorf("candidates %v", got)
	}
}

func TestDiscoverExternal(t *testing.T) {
	const name = "index.docker.io/library/nginx"
	img := Image{Ref: imageref.Ref{Registry: "index.docker.io", Repository: "library/nginx", Tag: "1.30.5-alpine", Digest: dRun}}
	reg := &fakeRegistry{
		tags:    map[string][]string{name: {"1.30.5-alpine", "1.30.6-alpine", "1.31.0", "alpine"}},
		digests: map[string]string{name + ":1.30.6-alpine": dRelease},
		labels:  map[string]map[string]string{},
	}
	at := now
	tbl, err := sources.Parse([]byte("images:\n- image: index.docker.io/library/nginx\n  source: https://github.com/nginx/docker-nginx\n"))
	if err != nil {
		t.Fatal(err)
	}
	prs := []github.PullRequest{
		{URL: "https://github.com/yuanying/fleet-infra/pull/1", Title: "Update nginx Docker tag to v1.30.6", Author: "renovate-y[bot]"},
		{URL: "https://github.com/yuanying/fleet-infra/pull/2", Title: "Update nginx by hand", Author: "yuanying"},
		{URL: "https://github.com/yuanying/fleet-infra/pull/3", Title: "Update httpd Docker tag", Author: "renovate-y[bot]"},
		{URL: "https://github.com/yuanying/fleet-infra/pull/4", Title: "Update nginx-exporter Docker tag", Author: "renovate-y[bot]"},
		{URL: "https://github.com/yuanying/fleet-infra/pull/5", Title: "Update dependencies", Body: "| docker.io/library/nginx | 1.30.5 -> 1.30.6 |", Author: "renovate-y[bot]"},
	}
	c := newDiscoverer(reg, &at).Discover(context.Background(), img, World{Sources: tbl, PullRequests: prs})
	if c.Origin != stage.External || c.Source != "https://github.com/nginx/docker-nginx" {
		t.Errorf("got %+v", c)
	}
	if got := kinds(c); !slices.Equal(got, []string{"upstream:1.30.6-alpine@sha256:3"}) {
		t.Errorf("candidates %v", got)
	}
	if !slices.Equal(c.RenovatePRs, []string{"https://github.com/yuanying/fleet-infra/pull/1", "https://github.com/yuanying/fleet-infra/pull/5"}) {
		t.Errorf("renovate PRs %v", c.RenovatePRs)
	}
}

// A tag that is not a version is followed by its digest (ADR 0002).
func TestDiscoverMovingTag(t *testing.T) {
	const name = "ghcr.io/iwaco/movies"
	img := Image{Ref: imageref.Ref{Registry: "ghcr.io", Repository: "iwaco/movies", Tag: "latest", Digest: dRun}}
	reg := &fakeRegistry{
		tags:    map[string][]string{name: {"latest"}},
		digests: map[string]string{name + ":latest": dRelease},
	}
	at := now
	c := newDiscoverer(reg, &at).Discover(context.Background(), img, World{})
	if got := kinds(c); !slices.Equal(got, []string{"upstream:latest@sha256:3"}) {
		t.Errorf("candidates %v", got)
	}
	// Not moved: no candidate.
	reg.digests[name+":latest"] = dRun
	at = at.Add(2 * time.Hour)
	if got := kinds(newDiscoverer(reg, &at).Discover(context.Background(), img, World{})); len(got) != 0 {
		t.Errorf("candidates %v, want none", got)
	}
}

func TestDiscoverRegistryUnreadable(t *testing.T) {
	img := Image{Ref: imageref.Ref{Registry: "registry.fraction.jp", Repository: "llm-wiki", Tag: "main", Digest: dRun}}
	reg := &fakeRegistry{fail: true}
	at := now
	ix := manifests.Index{"registry.fraction.jp/llm-wiki": {{Registry: "registry.fraction.jp", Repository: "llm-wiki", Tag: "ee09717", Digest: dGit}}}
	c := newDiscoverer(reg, &at).Discover(context.Background(), img, World{Manifests: ix})
	if !c.DiscoveryFailed || c.Origin != stage.External || c.Source != "" {
		t.Errorf("got %+v", c)
	}
	// A digest written in git needs no registry to be a candidate.
	if got := kinds(c); !slices.Equal(got, []string{"git:ee09717@sha256:4"}) {
		t.Errorf("candidates %v", got)
	}
}

func TestDiscoverCaches(t *testing.T) {
	const name = "ghcr.io/yuanying/hshelf"
	reg := &fakeRegistry{
		tags:    map[string][]string{name: {"1.0.0", "main"}},
		digests: map[string]string{name + ":main": dMain},
		labels:  map[string]map[string]string{name + "@" + dRun: labels("https://github.com/yuanying/hshelf", "aaa")},
	}
	at := now
	d := newDiscoverer(reg, &at)
	d.Discover(context.Background(), hshelf(), World{})
	before := map[string]int{}
	for k, v := range reg.calls {
		before[k] = v
	}
	at = at.Add(30 * time.Minute)
	d.Discover(context.Background(), hshelf(), World{})
	if reg.calls["tags"] != before["tags"] || reg.calls["digest"] != before["digest"] || reg.calls["labels"] != before["labels"] {
		t.Errorf("within the TTLs nothing should be read again: before %v, after %v", before, reg.calls)
	}
	// After an hour the moving tags are resolved again; the tag list waits six.
	at = at.Add(time.Hour)
	d.Discover(context.Background(), hshelf(), World{})
	if reg.calls["digest"] == before["digest"] {
		t.Error(":main should be resolved again after an hour")
	}
	if reg.calls["tags"] != before["tags"] {
		t.Error("the tag list should wait six hours")
	}
	if reg.calls["labels"] != before["labels"] {
		t.Error("labels of a digest never change")
	}
}
