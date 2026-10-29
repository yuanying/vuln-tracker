package pipeline

import (
	"regexp"
	"slices"
	"strings"

	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/imageref"
)

// LinkKind says why a pull request is linked to a finding (ADR 0014).
type LinkKind string

const (
	// LinkResponder: vuln-responder's reply to a request about the finding
	// named it.
	LinkResponder LinkKind = "vuln-responder"
	// LinkRenovate: Renovate opened it and it names the image (in a manifest
	// repository) or the package (in the source repository).
	LinkRenovate LinkKind = "renovate"
	// LinkMentionsID: its title or body names the vulnerability.
	LinkMentionsID LinkKind = "mentions-id"
)

// PR is a pull request linked to a finding.
type PR struct {
	github.PullRequest
	Link LinkKind
}

// Finding is what a finding is linked by.
type Finding struct {
	// Image is the normalized image name, as Trivy writes it.
	Image           string
	VulnerabilityID string
	Package         string
	// SourceRepository is "owner/name" of a self-built image, or "".
	SourceRepository string
}

// Repos is what is known about the pull requests.
type Repos struct {
	// Manifests are the manifest repositories, "owner/name".
	Manifests []string
	// Open are the open pull requests, by repository.
	Open map[string][]github.PullRequest
	// VEXOnly are the pull requests, by URL, that change nothing but VEX
	// documents.
	VEXOnly map[string]bool
	// Renovate matches the login of Renovate's pull requests.
	Renovate *regexp.Regexp
}

// Linked are the pull requests linked to a finding, by what they work on.
type Linked struct {
	Source   []PR
	Manifest []PR
	// VEX are pull requests to the manifest repositories that only annotate.
	VEX []PR
}

// AnyOpen reports whether one of the pull requests is open.
func AnyOpen(prs []PR) bool {
	return slices.ContainsFunc(prs, func(p PR) bool { return p.State == github.StateOpen })
}

// words are what a pull request's title and body name, split once so that
// thousands of findings can be looked up in them.
type words struct {
	names map[string]bool
	ids   map[string]bool
}

func split(text string, in func(byte) bool, into map[string]bool) {
	start := -1
	for i := 0; i <= len(text); i++ {
		if i < len(text) && in(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			into[text[start:i]] = true
			start = -1
		}
	}
}

func wordsOf(texts ...string) words {
	w := words{names: map[string]bool{}, ids: map[string]bool{}}
	for _, t := range texts {
		split(t, nameChar, w.names)
		split(strings.ToLower(t), idChar, w.ids)
	}
	return w
}

func (w words) image(name string) bool {
	for _, n := range imageNames(name) {
		if w.names[n] {
			return true
		}
	}
	return false
}

// Index links pull requests to findings (ADR 0014).
type Index struct {
	repos Repos
	words map[string]words
}

// NewIndex reads the open pull requests once for the findings to come.
func NewIndex(r Repos) *Index {
	ix := &Index{repos: r, words: map[string]words{}}
	for _, prs := range r.Open {
		for _, p := range prs {
			ix.words[p.URL] = wordsOf(p.Title, p.Body)
		}
	}
	return ix
}

// Link links the pull requests to a finding. responder are the pull requests
// vuln-responder's replies named for it, in whatever state they are now. A
// pull request in the source repository works on the source side; one in a
// manifest repository works on the manifest side, unless it changes only VEX
// documents. vuln-responder's replies come first, then the open pull requests
// in the order they were listed.
func (ix *Index) Link(f Finding, responder []github.PullRequest) Linked {
	r := ix.repos
	var out Linked
	seen := map[string]bool{}
	put := func(p github.PullRequest, kind LinkKind) {
		if seen[p.URL] {
			return
		}
		seen[p.URL] = true
		l := PR{PullRequest: p, Link: kind}
		switch {
		case f.SourceRepository != "" && p.Repository == f.SourceRepository:
			out.Source = append(out.Source, l)
		case slices.Contains(r.Manifests, p.Repository) && r.VEXOnly[p.URL]:
			out.VEX = append(out.VEX, l)
		case slices.Contains(r.Manifests, p.Repository):
			out.Manifest = append(out.Manifest, l)
		}
	}
	for _, p := range responder {
		put(p, LinkResponder)
	}
	renovate := func(p github.PullRequest) bool {
		return r.Renovate != nil && r.Renovate.MatchString(p.Author)
	}
	id := strings.ToLower(f.VulnerabilityID)
	if f.SourceRepository != "" {
		for _, p := range r.Open[f.SourceRepository] {
			w := ix.words[p.URL]
			switch {
			case renovate(p) && f.Package != "" && w.names[f.Package]:
				put(p, LinkRenovate)
			case id != "" && w.ids[id]:
				put(p, LinkMentionsID)
			}
		}
	}
	for _, repo := range r.Manifests {
		for _, p := range r.Open[repo] {
			w := ix.words[p.URL]
			switch {
			case renovate(p) && w.image(f.Image):
				put(p, LinkRenovate)
			case id != "" && w.ids[id]:
				put(p, LinkMentionsID)
			}
		}
	}
	return out
}

// MentionsImage reports whether text names the image as a whole word, so
// that "nginx" does not match "nginx-exporter". Renovate writes the name the
// manifest wrote, which may or may not carry the registry.
func MentionsImage(text, name string) bool {
	return wordsOf(text).image(name)
}

func imageNames(name string) []string {
	names := []string{name, imageref.ShortName(name)}
	if rest, ok := strings.CutPrefix(name, "index.docker.io/"); ok {
		names = append(names, "docker.io/"+rest)
	}
	return names
}

// MentionsID reports whether text names the vulnerability, ignoring case. An
// ID ends where letters, digits and hyphens do, so a sentence's full stop
// does not hide it.
func MentionsID(text, id string) bool {
	return id != "" && wordsOf(text).ids[strings.ToLower(id)]
}

func nameChar(b byte) bool {
	return b == '-' || b == '_' || b == '/' || b == '.' || alnum(b)
}

func idChar(b byte) bool {
	return b == '-' || alnum(b)
}

func alnum(b byte) bool {
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')
}
