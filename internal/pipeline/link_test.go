package pipeline

import (
	"regexp"
	"slices"
	"testing"

	"github.com/yuanying/vuln-tracker/internal/github"
)

func pr(repo string, n int, author, title, body string) github.PullRequest {
	return github.PullRequest{
		URL: "https://github.com/" + repo + "/pull/" + string(rune('0'+n)), Repository: repo, Number: n,
		State: github.StateOpen, Author: author, Title: title, Body: body,
	}
}

func urls(prs []PR) []string {
	var out []string
	for _, p := range prs {
		out = append(out, string(p.Link)+" "+p.URL)
	}
	return out
}

func TestLink(t *testing.T) {
	const (
		src   = "yuanying/hshelf"
		fleet = "yuanying/fleet-infra"
		k8s   = "yuanying/k8s-manifests-fraction"
	)
	renovate := regexp.MustCompile("renovate")
	f := Finding{Image: "ghcr.io/yuanying/hshelf", VulnerabilityID: "CVE-2026-33210", Package: "json", SourceRepository: src}

	responderFix := pr(src, 1, "fraction-vuln-responder[bot]", "Bump json", "")
	responderFix.State = github.StateMerged
	responderVEX := pr(fleet, 2, "fraction-vuln-responder[bot]", "Annotate CVE-2026-33210 in hshelf", "")
	open := map[string][]github.PullRequest{
		src: {
			responderFix, // listed again as open would be a duplicate
			pr(src, 3, "renovate[bot]", "Update dependency json to v2.18.1", ""),
			pr(src, 4, "renovate[bot]", "Update dependency package.json-tools to v2", ""), // not the package
			pr(src, 5, "yuanying", "Fix cve-2026-33210", ""),                              // case is ignored
			pr(src, 6, "yuanying", "Refactor", "see CVE-2026-332100"),                     // another ID
		},
		fleet: {
			responderVEX,
			pr(fleet, 7, "renovate[bot]", "Update ghcr.io/yuanying/hshelf Docker tag to v1.1.0", ""),
			pr(fleet, 8, "yuanying", "Bump hshelf", "Fixes CVE-2026-33210."),
			pr(fleet, 9, "yuanying", "VEX for CVE-2026-33210", ""),
			pr(fleet, 1, "renovate[bot]", "Update ghcr.io/yuanying/hshelf-worker Docker tag", ""), // another image
		},
		k8s: {pr(k8s, 2, "yuanying", "Unrelated", "")},
		// A repository that is neither the source nor a manifest one is
		// not read for this finding.
		"yuanying/other": {pr("yuanying/other", 1, "yuanying", "CVE-2026-33210", "")},
	}
	r := Repos{
		Manifests: []string{fleet, k8s},
		Open:      open,
		VEXOnly:   map[string]bool{responderVEX.URL: true, open[fleet][3].URL: true},
		Renovate:  renovate,
	}
	got := NewIndex(r).Link(f, []github.PullRequest{responderFix, responderVEX})
	if want := []string{"vuln-responder " + responderFix.URL, "renovate " + open[src][1].URL, "mentions-id " + open[src][3].URL}; !slices.Equal(urls(got.Source), want) {
		t.Errorf("source:\n got %v\nwant %v", urls(got.Source), want)
	}
	if want := []string{"renovate " + open[fleet][1].URL, "mentions-id " + open[fleet][2].URL}; !slices.Equal(urls(got.Manifest), want) {
		t.Errorf("manifest:\n got %v\nwant %v", urls(got.Manifest), want)
	}
	// Pull requests that change only VEX documents annotate; they fix
	// nothing.
	if want := []string{"vuln-responder " + responderVEX.URL, "mentions-id " + open[fleet][3].URL}; !slices.Equal(urls(got.VEX), want) {
		t.Errorf("vex:\n got %v\nwant %v", urls(got.VEX), want)
	}
	if got.Source[0].State != github.StateMerged {
		t.Errorf("the reply's state is kept: %+v", got.Source[0])
	}
	if !AnyOpen(got.Source) || AnyOpen(got.Source[:1]) {
		t.Error("AnyOpen")
	}
}

// An external image has no source repository; Renovate names it in the
// manifest repositories with or without the registry.
func TestLinkExternal(t *testing.T) {
	const fleet = "yuanying/fleet-infra"
	f := Finding{Image: "index.docker.io/library/nginx", VulnerabilityID: "CVE-1", Package: "openssl"}
	r := Repos{
		Manifests: []string{fleet},
		Open: map[string][]github.PullRequest{fleet: {
			pr(fleet, 1, "renovate[bot]", "Update nginx Docker tag to v1.31.0", ""),
			pr(fleet, 2, "renovate[bot]", "Update docker.io/library/nginx Docker tag", ""),
			pr(fleet, 3, "renovate[bot]", "Update nginx-exporter Docker tag", ""),
			pr(fleet, 4, "renovate[bot]", "Update dependency openssl", ""), // the package is not linked here
		}},
		Renovate: regexp.MustCompile("renovate"),
	}
	got := NewIndex(r).Link(f, nil)
	if len(got.Source) != 0 {
		t.Errorf("source: %v", urls(got.Source))
	}
	if want := []string{"renovate " + r.Open[fleet][0].URL, "renovate " + r.Open[fleet][1].URL}; !slices.Equal(urls(got.Manifest), want) {
		t.Errorf("manifest:\n got %v\nwant %v", urls(got.Manifest), want)
	}
}

func TestMentionsImage(t *testing.T) {
	tests := []struct {
		text, image string
		want        bool
	}{
		{"Update ghcr.io/yuanying/hshelf to v1", "ghcr.io/yuanying/hshelf", true},
		{"Update nginx Docker tag", "index.docker.io/library/nginx", true},
		{"Update docker.io/library/nginx", "index.docker.io/library/nginx", true},
		{"Update nginx-exporter", "index.docker.io/library/nginx", false},
		{"", "index.docker.io/library/nginx", false},
	}
	for _, tt := range tests {
		if got := MentionsImage(tt.text, tt.image); got != tt.want {
			t.Errorf("%q %q: got %v", tt.text, tt.image, got)
		}
	}
}

func TestMentionsID(t *testing.T) {
	tests := []struct {
		text string
		want bool
	}{
		{"CVE-2026-1", true},
		{"fixes cve-2026-1.", true},
		{"(CVE-2026-1)", true},
		{"CVE-2026-12", false},
		{"XCVE-2026-1", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := MentionsID(tt.text, "CVE-2026-1"); got != tt.want {
			t.Errorf("%q: got %v", tt.text, got)
		}
	}
	if MentionsID("anything", "") {
		t.Error("an empty ID matches nothing")
	}
}
