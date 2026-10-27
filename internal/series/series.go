// Package series picks, from a registry's tag list, the version a running tag
// would move to: the newest of the same series for an image someone else
// builds, and the newest release for one built here (ADR 0002).
package series

import (
	"regexp"
	"strconv"
	"strings"
)

// version is a tag split into an optional "v", up to three numbers and
// whatever follows them.
type version struct {
	v      bool
	parts  [3]int
	nparts int
	suffix string
}

var versionPattern = regexp.MustCompile(`^(v?)(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$`)

func parse(tag string) (version, bool) {
	m := versionPattern.FindStringSubmatch(tag)
	if m == nil {
		return version{}, false
	}
	var out version
	out.v = m[1] == "v"
	for i, s := range m[2:5] {
		if s == "" {
			break
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return version{}, false
		}
		out.parts[i] = n
		out.nparts = i + 1
	}
	out.suffix = m[5]
	// "1.2.3.4" or "1.2x" are not versions this package understands: what
	// follows the numbers has to start a suffix of its own.
	if out.suffix != "" && !strings.HasPrefix(out.suffix, "-") && !strings.HasPrefix(out.suffix, "+") && !strings.HasPrefix(out.suffix, "_") {
		return version{}, false
	}
	return out, true
}

func compare(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// NewestInSeries returns the newest tag in the running tag's series that is
// newer than it. Without a pattern, the series is the same "v", the same
// major, the same number of parts and the same suffix. With one, a tag is in
// the series when the pattern matches it, and the pattern's first capture
// group is the version compared.
func NewestInSeries(running string, tags []string, pattern *regexp.Regexp) (string, bool) {
	if pattern != nil {
		return newestByPattern(running, tags, pattern)
	}
	cur, ok := parse(running)
	if !ok {
		return "", false
	}
	best, bestTag := cur, ""
	for _, t := range tags {
		v, ok := parse(t)
		if !ok || v.v != cur.v || v.suffix != cur.suffix || v.nparts != cur.nparts || v.parts[0] != cur.parts[0] {
			continue
		}
		if compare(v.parts, best.parts) > 0 {
			best, bestTag = v, t
		}
	}
	return bestTag, bestTag != ""
}

func newestByPattern(running string, tags []string, pattern *regexp.Regexp) (string, bool) {
	extract := func(tag string) (version, bool) {
		m := pattern.FindStringSubmatch(tag)
		if m == nil {
			return version{}, false
		}
		s := m[0]
		if len(m) > 1 {
			s = m[1]
		}
		return parse(s)
	}
	cur, ok := extract(running)
	if !ok {
		return "", false
	}
	best, bestTag := cur, ""
	for _, t := range tags {
		v, ok := extract(t)
		if ok && compare(v.parts, best.parts) > 0 {
			best, bestTag = v, t
		}
	}
	return bestTag, bestTag != ""
}

// NewestRelease returns the newest release tag — three numbers, an optional
// "v" and nothing after — that is newer than the running tag. A running tag
// that is not a version (main, a commit) is older than every release.
func NewestRelease(running string, tags []string) (string, bool) {
	var floor [3]int
	hasFloor := false
	if cur, ok := parse(running); ok && cur.nparts == 3 && cur.suffix == "" {
		floor, hasFloor = cur.parts, true
	}
	var best [3]int
	bestTag := ""
	for _, t := range tags {
		v, ok := parse(t)
		if !ok || v.nparts != 3 || v.suffix != "" {
			continue
		}
		if hasFloor && compare(v.parts, floor) <= 0 {
			continue
		}
		if bestTag == "" || compare(v.parts, best) > 0 {
			best, bestTag = v.parts, t
		}
	}
	return bestTag, bestTag != ""
}

// IsVersion reports whether a tag carries a version this package can order.
// One that does not — latest, alpine, a commit — is followed by its digest
// instead (ADR 0002).
func IsVersion(tag string) bool {
	_, ok := parse(tag)
	return ok
}
