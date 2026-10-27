// Package annotation reads the OpenVEX documents in fleet-infra's
// security/vex/ and lays them over findings (ADR 0004).
//
// The documents follow the convention in fleet-infra's security/vex/README.md:
// the state, the review-by date and a tag for people to read are kept in
// status_notes, one "key: value" per line. Matching is go-vex's, which is what
// Trivy uses for --vex, so an annotation that passes fleet-infra's checks
// matches here the way it would there.
package annotation

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
)

const (
	dir    = "security/vex/"
	suffix = ".openvex.json"
)

// States are the values of the "state" key, the repository's own words for
// where an annotation stands.
var States = []string{"upstream", "not-exploitable", "in-progress", "investigating", "fixed"}

// Annotation is what one statement says about one finding.
type Annotation struct {
	// State is the status_notes "state".
	State string
	// Status is the OpenVEX status.
	Status string
	// ReviewBy is the status_notes "review-by", YYYY-MM-DD.
	ReviewBy string
	// Tag is the status_notes "tag", for people to read.
	Tag string
	// Reason is the impact_statement or the action_statement, whichever the
	// status calls for.
	Reason string
	// Path is the document the statement came from, relative to fleet-infra.
	Path string

	timestamp time.Time
}

// Expired reports whether the review-by date is before today. Both are
// YYYY-MM-DD in the tracker's time zone; the review-by day itself is in time.
func (a Annotation) Expired(today string) bool {
	return a.ReviewBy != "" && a.ReviewBy < today
}

type statement struct {
	stmt vex.Statement
	ann  Annotation
}

// Set is every usable statement read from fleet-infra.
type Set struct {
	statements []statement
}

// PathFor is the document an image's annotations are filed in.
func PathFor(imageName string) string {
	return dir + imageName + suffix
}

// Load parses every VEX document among files, keyed by their path in
// fleet-infra. Files outside security/vex/ or not named *.openvex.json are
// ignored. A document that cannot be read, and a statement whose status_notes
// break the convention, is left out and reported; everything else is used.
func Load(files map[string][]byte) (*Set, []error) {
	set := &Set{}
	var errs []error
	paths := make([]string, 0, len(files))
	for p := range files {
		if strings.HasPrefix(p, dir) && strings.HasSuffix(p, suffix) {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	for _, p := range paths {
		doc, err := vex.Parse(files[p])
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		for i, st := range doc.Statements {
			ann, err := annotate(st)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: statement %d (%s): %w", p, i, st.Vulnerability.Name, err))
				continue
			}
			ann.Path = p
			switch {
			case st.Timestamp != nil:
				ann.timestamp = *st.Timestamp
			case doc.Timestamp != nil:
				ann.timestamp = *doc.Timestamp
			}
			set.statements = append(set.statements, statement{stmt: st, ann: ann})
		}
	}
	return set, errs
}

func annotate(st vex.Statement) (Annotation, error) {
	a := Annotation{Status: string(st.Status)}
	for line := range strings.SplitSeq(st.StatusNotes, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return Annotation{}, fmt.Errorf("status_notes line %q is not key: value", line)
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "state":
			a.State = v
		case "review-by":
			a.ReviewBy = v
		case "tag":
			a.Tag = v
		}
	}
	if !slices.Contains(States, a.State) {
		return Annotation{}, fmt.Errorf("status_notes state %q is not one of %v", a.State, States)
	}
	if _, err := time.Parse(time.DateOnly, a.ReviewBy); err != nil {
		return Annotation{}, fmt.Errorf("status_notes review-by %q is not a date", a.ReviewBy)
	}
	switch st.Status {
	case vex.StatusNotAffected, vex.StatusFixed:
		a.Reason = st.ImpactStatement
	default:
		a.Reason = st.ActionStatement
	}
	return a, nil
}

// Lookup returns the annotation for a vulnerability in an image, given the
// image's purl (imageref.Ref.PURL) and the package's purl from the
// VulnerabilityReport, which may be empty. When several statements match, the
// newest one wins.
func (s *Set) Lookup(vulnID, imagePURL, pkgPURL string) (Annotation, bool) {
	var subs []string
	if pkgPURL != "" {
		subs = []string{pkgPURL}
	}
	var best *Annotation
	for i := range s.statements {
		st := &s.statements[i]
		if !st.stmt.Matches(vulnID, imagePURL, subs) {
			continue
		}
		if best == nil || st.ann.timestamp.After(best.timestamp) {
			best = &st.ann
		}
	}
	if best == nil {
		return Annotation{}, false
	}
	return *best, true
}

// Len is the number of usable statements.
func (s *Set) Len() int {
	return len(s.statements)
}
