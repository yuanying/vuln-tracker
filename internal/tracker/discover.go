package tracker

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/imageref"
	"github.com/yuanying/vuln-tracker/internal/manifests"
	"github.com/yuanying/vuln-tracker/internal/registry"
	"github.com/yuanying/vuln-tracker/internal/series"
	"github.com/yuanying/vuln-tracker/internal/sources"
	"github.com/yuanying/vuln-tracker/internal/stage"
)

const (
	labelSource   = "org.opencontainers.image.source"
	labelRevision = "org.opencontainers.image.revision"

	// How long registry answers are kept (ADR 0002). The tag list is read
	// rarely because Docker Hub limits anonymous reads; a moving tag's
	// digest is cheap to read; the labels of a digest never change.
	tagsTTL   = 6 * time.Hour
	digestTTL = time.Hour
	// errorTTL is how soon a failed read is retried.
	errorTTL = time.Hour
)

// World is what discovery reads from the manifest repositories.
type World struct {
	Manifests    manifests.Index
	Sources      sources.Table
	PullRequests []github.PullRequest
}

type cached[T any] struct {
	at  time.Time
	val T
	err error
}

// Discoverer finds the candidate versions of a running version (ADR 0002).
type Discoverer struct {
	Registry registry.Registry
	// SelfSourcePrefix is the start of the source URL of an image built here,
	// e.g. "https://github.com/yuanying/".
	SelfSourcePrefix string
	// RenovateAuthor matches the login of Renovate's pull requests.
	RenovateAuthor *regexp.Regexp
	Now            func() time.Time

	mu      sync.Mutex
	tags    map[string]cached[[]string]
	digests map[string]cached[string]
	labels  map[string]cached[map[string]string]
}

func (d *Discoverer) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func fresh[T any](c cached[T], ok bool, now time.Time, ttl time.Duration) bool {
	if !ok {
		return false
	}
	if c.err != nil {
		ttl = errorTTL
	}
	return ttl < 0 || now.Sub(c.at) < ttl
}

func (d *Discoverer) readTags(ctx context.Context, name string) ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.tags == nil {
		d.tags = map[string]cached[[]string]{}
	}
	now := d.now()
	if c, ok := d.tags[name]; fresh(c, ok, now, tagsTTL) {
		return c.val, c.err
	}
	t, err := d.Registry.Tags(ctx, name)
	d.tags[name] = cached[[]string]{at: now, val: t, err: err}
	return t, err
}

func (d *Discoverer) readDigest(ctx context.Context, ref string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.digests == nil {
		d.digests = map[string]cached[string]{}
	}
	now := d.now()
	if c, ok := d.digests[ref]; fresh(c, ok, now, digestTTL) {
		return c.val, c.err
	}
	v, err := d.Registry.Digest(ctx, ref)
	d.digests[ref] = cached[string]{at: now, val: v, err: err}
	return v, err
}

func (d *Discoverer) readLabels(ctx context.Context, ref string) (map[string]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.labels == nil {
		d.labels = map[string]cached[map[string]string]{}
	}
	now := d.now()
	if c, ok := d.labels[ref]; fresh(c, ok, now, -1) {
		return c.val, c.err
	}
	v, err := d.Registry.Labels(ctx, ref)
	d.labels[ref] = cached[map[string]string]{at: now, val: v, err: err}
	return v, err
}

// Forget drops what is cached about images no longer running.
func (d *Discoverer) Forget(running map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.tags {
		if !running[k] {
			delete(d.tags, k)
		}
	}
	for k := range d.digests {
		if !running[refName(k)] {
			delete(d.digests, k)
		}
	}
	for k := range d.labels {
		if !running[refName(k)] {
			delete(d.labels, k)
		}
	}
}

// refName is the image name of "name:tag" or "name@digest".
func refName(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i]
	}
	return ref
}

// Discover returns the candidates of one running version.
func (d *Discoverer) Discover(ctx context.Context, img Image, w World) Candidates {
	name := img.Ref.Name()
	c := Candidates{Origin: stage.External}

	lbls, err := d.readLabels(ctx, name+"@"+img.Ref.Digest)
	if err != nil {
		c.DiscoveryFailed = true
	}
	c.Source, c.Revision = lbls[labelSource], lbls[labelRevision]
	var pattern *regexp.Regexp
	if e, ok := w.Sources.Lookup(name); ok {
		if c.Source == "" {
			c.Source = e.Source
		}
		pattern = e.TagPattern
	}
	if d.SelfSourcePrefix != "" && strings.HasPrefix(c.Source, d.SelfSourcePrefix) {
		c.Origin = stage.SelfBuilt
	}

	seen := map[string]bool{img.Ref.Digest: true}
	add := func(r CandidateRef) {
		if r.Digest == "" || seen[r.Digest] {
			return
		}
		seen[r.Digest] = true
		c.List = append(c.List, r)
	}
	resolve := func(tag string) (string, bool) {
		dg, err := d.readDigest(ctx, name+":"+tag)
		if err != nil {
			if !errors.Is(err, registry.ErrNotFound) {
				c.DiscoveryFailed = true
			}
			return "", false
		}
		return dg, true
	}

	if tags, err := d.readTags(ctx, name); err != nil {
		c.DiscoveryFailed = true
	} else if c.Origin == stage.SelfBuilt {
		var mainRef, releaseRef CandidateRef
		if dg, ok := resolve("main"); ok {
			mainRef = CandidateRef{Kind: stage.Main, Tag: "main", Digest: dg}
			if l, err := d.readLabels(ctx, name+"@"+dg); err == nil {
				mainRef.Revision = l[labelRevision]
			}
		}
		if t, ok := series.NewestRelease(img.Ref.Tag, tags); ok {
			if dg, ok := resolve(t); ok {
				releaseRef = CandidateRef{Kind: stage.Release, Tag: t, Digest: dg}
				if l, err := d.readLabels(ctx, name+"@"+dg); err == nil {
					releaseRef.Revision = l[labelRevision]
				}
			}
		}
		// :main built from the commit the release was built from would
		// scan the same.
		if releaseRef.Digest != "" && mainRef.Revision != "" && mainRef.Revision == releaseRef.Revision {
			mainRef = CandidateRef{}
		}
		add(mainRef)
		add(releaseRef)
	} else {
		switch {
		case pattern == nil && !series.IsVersion(img.Ref.Tag):
			// A tag that is not a version moves: what it points at now is
			// the upstream candidate.
			if img.Ref.Tag != "" {
				if dg, ok := resolve(img.Ref.Tag); ok {
					add(CandidateRef{Kind: stage.Upstream, Tag: img.Ref.Tag, Digest: dg})
				}
			}
		default:
			if t, ok := series.NewestInSeries(img.Ref.Tag, tags, pattern); ok {
				if dg, ok := resolve(t); ok {
					add(CandidateRef{Kind: stage.Upstream, Tag: t, Digest: dg})
				}
			}
		}
	}

	for _, r := range w.Manifests.Versions(name) {
		dg := r.Digest
		if dg == "" {
			var ok bool
			if dg, ok = resolve(r.Tag); !ok {
				continue
			}
		}
		add(CandidateRef{Kind: stage.Git, Tag: r.Tag, Digest: dg})
	}

	c.RenovatePRs = d.renovatePRs(name, w.PullRequests)
	return c
}

func (d *Discoverer) renovatePRs(name string, prs []github.PullRequest) []string {
	if d.RenovateAuthor == nil {
		return nil
	}
	// Renovate writes the name the manifest wrote, which may or may not
	// carry the registry.
	names := []string{name, imageref.ShortName(name)}
	if strings.HasPrefix(name, "index.docker.io/") {
		names = append(names, "docker.io/"+strings.TrimPrefix(name, "index.docker.io/"))
	}
	var out []string
	for _, pr := range prs {
		if !d.RenovateAuthor.MatchString(pr.Author) {
			continue
		}
		for _, n := range names {
			if mentions(pr.Title, n) || mentions(pr.Body, n) {
				out = append(out, pr.URL)
				break
			}
		}
	}
	return out
}

// mentions reports whether text names the image as a whole word, so that
// "nginx" does not match "nginx-exporter".
func mentions(text, image string) bool {
	for i := 0; ; {
		j := strings.Index(text[i:], image)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(image)
		before := start == 0 || !nameChar(text[start-1])
		after := end == len(text) || !nameChar(text[end])
		if before && after {
			return true
		}
		i = start + 1
	}
}

func nameChar(b byte) bool {
	return b == '-' || b == '_' || b == '/' || b == '.' ||
		('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')
}
