// Package api serves the findings as JSON (ADR 0015): one finding per
// running version × vulnerability × package of the detailed severities, with
// its stage, both sides of its remediation, the pull requests linked to them
// and its annotation.
//
// There is no authentication here: the Ingress in front of it is gated's,
// which lets only the owner and the claude ServiceAccount through.
package api

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/yuanying/vuln-tracker/internal/pipeline"
	"github.com/yuanying/vuln-tracker/internal/tracker"
)

// Server serves what Snapshot returns.
type Server struct {
	// Snapshot is the tracker's latest evaluation, or false before the
	// first.
	Snapshot func() (tracker.Snapshot, bool)
	// Severities are the detailed severities, in the order they are
	// listed; only their findings are served.
	Severities []string
	// VEXBaseURL turns a VEX document's path into a link.
	VEXBaseURL string
}

// Handler routes the API's paths.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/findings", s.findings)
	return mux
}

// FindingsResponse is the body of GET /api/findings (ADR 0015).
type FindingsResponse struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Severities  []string  `json:"severities"`
	Findings    []Finding `json:"findings"`
}

// Finding is one finding. Keys without a value are null; lists are never
// null.
type Finding struct {
	Image            string     `json:"image"`
	Tag              string     `json:"tag"`
	Digest           string     `json:"digest"`
	VulnerabilityID  string     `json:"vulnerabilityID"`
	Severity         string     `json:"severity"`
	Package          string     `json:"package"`
	InstalledVersion string     `json:"installedVersion"`
	FixedVersion     string     `json:"fixedVersion"`
	Fixable          bool       `json:"fixable"`
	SelfBuilt        bool       `json:"selfBuilt"`
	SourceRepository *string    `json:"sourceRepository"`
	Stage            string     `json:"stage"`
	Source           Source     `json:"source"`
	Manifest         Manifest   `json:"manifest"`
	VEX              VEX        `json:"vex"`
	Workloads        []Workload `json:"workloads"`
	FirstSeenAt      *time.Time `json:"firstSeenAt"`
}

// Source is the source side.
type Source struct {
	State        string        `json:"state"`
	PullRequests []PullRequest `json:"pullRequests"`
}

// Manifest is the manifest side.
type Manifest struct {
	State        string        `json:"state"`
	Repository   *string       `json:"repository"`
	PullRequests []PullRequest `json:"pullRequests"`
}

// VEX is the annotation, apart from the two sides.
type VEX struct {
	State    string  `json:"state"`
	Status   *string `json:"status"`
	ReviewBy *string `json:"reviewBy"`
	Document *string `json:"document"`
	Reason   *string `json:"reason"`
	Expired  bool    `json:"expired"`
	// PullRequests change only VEX documents.
	PullRequests []PullRequest `json:"pullRequests"`
}

// PullRequest is a pull request linked to a finding.
type PullRequest struct {
	URL        string `json:"url"`
	Repository string `json:"repository"`
	Number     int    `json:"number"`
	Title      string `json:"title"`
	State      string `json:"state"`
	Author     string `json:"author"`
	Link       string `json:"link"`
}

// Workload is where the version runs.
type Workload struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container"`
}

func (s *Server) findings(w http.ResponseWriter, _ *http.Request) {
	snap, ok := s.Snapshot()
	if !ok || !snap.Synced {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "the repositories and registries have not been read yet; try again in a minute",
		})
		return
	}
	writeJSON(w, http.StatusOK, s.Response(snap))
}

// Response builds the body for a snapshot.
func (s *Server) Response(snap tracker.Snapshot) FindingsResponse {
	images := map[string]tracker.ImageView{}
	for _, v := range snap.Images {
		images[v.Ref.Name()+"@"+v.Ref.Digest] = v
	}
	out := FindingsResponse{GeneratedAt: snap.At.UTC(), Severities: slices.Clone(s.Severities), Findings: []Finding{}}
	if out.Severities == nil {
		out.Severities = []string{}
	}
	for _, f := range snap.Findings {
		if !slices.Contains(s.Severities, f.Vuln.Severity) {
			continue
		}
		view := images[f.Image.Name()+"@"+f.Image.Digest]
		p := f.Pipeline
		item := Finding{
			Image:            f.Image.Name(),
			Tag:              f.Image.Tag,
			Digest:           f.Image.Digest,
			VulnerabilityID:  f.Vuln.ID,
			Severity:         f.Vuln.Severity,
			Package:          f.Vuln.Package,
			InstalledVersion: f.Vuln.InstalledVersion,
			FixedVersion:     f.Vuln.FixedVersion,
			Fixable:          f.Fixable,
			SelfBuilt:        view.SelfBuilt,
			SourceRepository: optional(p.SourceRepository),
			Stage:            string(f.Stage),
			Source:           Source{State: string(p.Source), PullRequests: pullRequests(p.SourcePRs)},
			Manifest:         Manifest{State: string(p.Manifest), Repository: optional(p.ManifestRepository), PullRequests: pullRequests(p.ManifestPRs)},
			VEX:              VEX{State: f.VexState(), Expired: f.VexExpired, PullRequests: pullRequests(p.VEXPRs)},
			Workloads:        []Workload{},
		}
		if a := f.Annotation; a != nil {
			item.VEX.Status, item.VEX.ReviewBy, item.VEX.Reason = optional(a.Status), optional(a.ReviewBy), optional(a.Reason)
			if a.Path != "" && s.VEXBaseURL != "" {
				item.VEX.Document = optional(strings.TrimSuffix(s.VEXBaseURL, "/") + "/" + a.Path)
			}
		}
		for _, wl := range view.Workloads {
			x := Workload(wl)
			if !slices.Contains(item.Workloads, x) {
				item.Workloads = append(item.Workloads, x)
			}
		}
		// 0 is what was there when the tracker was installed: when it
		// came is not known.
		if f.FirstSeen > 0 {
			t := time.Unix(f.FirstSeen, 0).UTC()
			item.FirstSeenAt = &t
		}
		out.Findings = append(out.Findings, item)
	}
	return out
}

func pullRequests(prs []pipeline.PR) []PullRequest {
	out := make([]PullRequest, 0, len(prs))
	for _, p := range prs {
		out = append(out, PullRequest{
			URL: p.URL, Repository: p.Repository, Number: p.Number, Title: p.Title,
			State: p.State, Author: p.Author, Link: string(p.Link),
		})
	}
	return out
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
