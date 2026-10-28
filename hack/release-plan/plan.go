package main

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// RenovateAuthor is the author name git records for Renovate's commits.
const RenovateAuthor = "renovate[bot]"

// VulnResponderAuthor is the author name git records for the commits
// vuln-responder writes in its fix pull requests (ADR 0012).
const VulnResponderAuthor = "fraction-vuln-responder[bot]"

// isBot reports whether author is one whose commits are released without a
// person: Renovate's dependency updates and vuln-responder's fixes.
func isBot(author string) bool {
	return author == RenovateAuthor || author == VulnResponderAuthor
}

// Version is a release version, vMAJOR.MINOR.PATCH.
type Version struct {
	Major, Minor, Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) less(o Version) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor < o.Minor
	}
	return v.Patch < o.Patch
}

var versionTag = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// LatestVersion picks the highest vX.Y.Z among tags, compared as numbers.
// Anything else — a fourth part, a pre-release, a missing v — is not a
// version this repository releases and is skipped.
func LatestVersion(tags []string) (Version, bool) {
	var latest Version
	found := false
	for _, tag := range tags {
		m := versionTag.FindStringSubmatch(tag)
		if m == nil {
			continue
		}
		var v Version
		var err error
		if v.Major, err = strconv.Atoi(m[1]); err != nil {
			continue
		}
		if v.Minor, err = strconv.Atoi(m[2]); err != nil {
			continue
		}
		if v.Patch, err = strconv.Atoi(m[3]); err != nil {
			continue
		}
		if !found || latest.less(v) {
			latest, found = v, true
		}
	}
	return latest, found
}

// imageContent is what the Dockerfile builds the image from: the Dockerfile
// itself and every path it copies in.
var imageContent = []string{"Dockerfile", "go.mod", "go.sum", "cmd/", "internal/"}

// IsImageContent reports whether a change to path can change the image.
func IsImageContent(path string) bool {
	for _, p := range imageContent {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(path, p) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}

// Commit is one non-merge commit between the latest version and HEAD.
type Commit struct {
	SHA     string
	Author  string
	Subject string
}

// Plan is what the run does. Without a release, Version and Message are
// empty and Reason says why nothing is released.
type Plan struct {
	Release bool
	Version string
	// Message is the annotated tag's message.
	Message string
	Reason  string
	// Next is the next patch version, released or not: the one a person
	// would tag by hand.
	Next string
	// Blockers are the commits by someone other than the bots, which leave
	// the release to a person.
	Blockers []Commit
}

// Decide whether the commits since latest are released as the next patch
// version (ADR 0010, ADR 0012). It is released only when every commit is
// Renovate's or vuln-responder's and at least one changed path is part of the
// image. Anything a person wrote is released by that person, who chooses the
// version and writes the message.
func Decide(latest Version, commits []Commit, changed []string) Plan {
	next := Version{Major: latest.Major, Minor: latest.Minor, Patch: latest.Patch + 1}
	if len(commits) == 0 {
		return Plan{Next: next.String(), Reason: fmt.Sprintf("no commits since %s", latest)}
	}
	var blockers []Commit
	fixes := false
	for _, c := range commits {
		if !isBot(c.Author) {
			blockers = append(blockers, c)
		}
		fixes = fixes || c.Author == VulnResponderAuthor
	}
	if len(blockers) > 0 {
		first := blockers[0]
		return Plan{
			Next:     next.String(),
			Blockers: blockers,
			Reason: fmt.Sprintf("%d of the %d commits since %s are not by %s or %s, the first %q by %s; releasing them is left to a person",
				len(blockers), len(commits), latest, RenovateAuthor, VulnResponderAuthor, first.Subject, first.Author),
		}
	}
	if !slices.ContainsFunc(changed, IsImageContent) {
		return Plan{Next: next.String(), Reason: fmt.Sprintf("the bots' commits since %s change nothing the image is built from (%s)", latest, strings.Join(imageContent, ", "))}
	}

	heading := "dependency updates"
	if fixes {
		heading = "vulnerability fixes and dependency updates"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n\n", next, heading)
	fmt.Fprintf(&b, "Only commits by %s and %s since %s,\nreleased without a person (ADR 0010, ADR 0012):\n\n", RenovateAuthor, VulnResponderAuthor, latest)
	for _, c := range commits {
		fmt.Fprintf(&b, "- %s\n", c.Subject)
	}
	return Plan{
		Release: true,
		Version: next.String(),
		Next:    next.String(),
		Message: b.String(),
		Reason:  fmt.Sprintf("%d commits since %s, all by %s or %s, and the image's content changed", len(commits), latest, RenovateAuthor, VulnResponderAuthor),
	}
}

// Summary is the Markdown the run writes to its job summary. When commits by
// a person stopped the release, it lists them and the commands that release
// head by hand, as a person always could (ADR 0008).
func Summary(plan Plan, head string) string {
	var b strings.Builder
	if plan.Release {
		fmt.Fprintf(&b, "### Releasing %s\n\n%s\n", plan.Version, plan.Reason)
		return b.String()
	}
	fmt.Fprintf(&b, "### No release\n\n%s\n", plan.Reason)
	if len(plan.Blockers) == 0 {
		return b.String()
	}
	b.WriteString("\nThe commits that stopped it:\n\n")
	for _, c := range plan.Blockers {
		fmt.Fprintf(&b, "- `%.12s` %s (%s)\n", c.SHA, c.Subject, c.Author)
	}
	fmt.Fprintf(&b, "\nTo release %s by hand, write what changed in the message and push the tag;\n", head)
	fmt.Fprintf(&b, "the publish workflow builds the image for it:\n\n")
	fmt.Fprintf(&b, "```sh\ngit fetch origin --tags\ngit tag -a %s %s\ngit push origin %s\n```\n", plan.Next, head, plan.Next)
	return b.String()
}
