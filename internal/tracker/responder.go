package tracker

import (
	"context"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/yuanying/vuln-tracker/internal/digest"
	"github.com/yuanying/vuln-tracker/internal/responder"
	"github.com/yuanying/vuln-tracker/internal/stage"
	"github.com/yuanying/vuln-tracker/internal/state"
)

// untreated are the stages in which nothing has been done about a fix: the
// same as the immediate alert's (ADR 0005).
var untreated = map[stage.Stage]bool{
	stage.Unfixed:       true,
	stage.FixedUpstream: true,
	stage.Unscannable:   true,
	stage.Pending:       true,
}

// sourceRepository reads "<owner>/<repo>" from a GitHub source URL.
func sourceRepository(source string) (string, bool) {
	rest, ok := strings.CutPrefix(source, "https://github.com/")
	if !ok {
		return "", false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	return parts[0] + "/" + strings.TrimSuffix(parts[1], ".git"), true
}

// trigger is what a finding is asked about, or "" (ADR 0011). With mode fix, a
// Critical whose stage reached a fixed version asks for a bump, annotated or
// not, new or not. Otherwise a new, fixable, unannotated, untreated Critical
// asks for triage (ADR 0009).
func trigger(f Finding, since int64, mode string) string {
	if f.Vuln.Severity != "CRITICAL" {
		return ""
	}
	if mode == "fix" && (f.Stage == stage.FixedInRelease || f.Stage == stage.FixedUpstream) {
		return responder.TriggerBump
	}
	if !f.Fixable || f.Annotation != nil || !untreated[f.Stage] || f.FirstSeen <= 0 || f.FirstSeen < since {
		return ""
	}
	return responder.TriggerTriage
}

// fixedIn is the candidate that put a finding at its stage: the release for
// fixed-in-release, the upstream version for fixed-upstream.
func fixedIn(view ImageView, st stage.Stage) (CandidateRef, bool) {
	kind := stage.Release
	if st == stage.FixedUpstream {
		kind = stage.Upstream
	}
	for _, c := range view.Candidates {
		if c.Kind == kind {
			return c.CandidateRef, true
		}
	}
	return CandidateRef{}, false
}

// responderWanted picks the findings to ask vuln-responder about and groups
// them by target, in the order of the targets' keys (ADR 0009, ADR 0011).
func responderWanted(snap Snapshot, now time.Time, within time.Duration, mode string) []responder.Wanted {
	views := map[string]ImageView{}
	for _, v := range snap.Images {
		views[v.Ref.Name()+"@"+v.Ref.Digest] = v
	}
	since := now.Add(-within).Unix()
	byTarget := map[string]*responder.Wanted{}
	for _, f := range snap.Findings {
		trig := trigger(f, since, mode)
		if trig == "" {
			continue
		}
		view := views[f.Image.Name()+"@"+f.Image.Digest]
		target := responder.Target{Type: "image", Image: f.Image.Name()}
		if repo, ok := sourceRepository(view.Source); ok && view.SelfBuilt {
			target = responder.Target{Type: "source", Repository: repo}
		}
		w, ok := byTarget[target.Key()]
		if !ok {
			w = &responder.Wanted{Target: target}
			byTarget[target.Key()] = w
		}
		rf := responder.Finding{
			VulnerabilityID:  f.Vuln.ID,
			Severity:         f.Vuln.Severity,
			Package:          f.Vuln.Package,
			InstalledVersion: f.Vuln.InstalledVersion,
			FixedVersion:     f.Vuln.FixedVersion,
			Stage:            string(f.Stage),
			VexState:         f.VexState(),
			Image:            f.Image.Name(),
			Tag:              f.Image.Tag,
			Digest:           f.Image.Digest,
			Trigger:          trig,
			RenovatePRs:      slices.Clone(view.RenovatePRs),
		}
		if trig == responder.TriggerBump {
			if c, ok := fixedIn(view, f.Stage); ok {
				rf.FixedInTag, rf.FixedInDigest = c.Tag, c.Digest
			}
		}
		for _, wl := range view.Workloads {
			r := responder.Workload(wl)
			if !slices.Contains(rf.Workloads, r) {
				rf.Workloads = append(rf.Workloads, r)
			}
		}
		w.Findings = append(w.Findings, rf)
	}
	keys := slices.Sorted(maps.Keys(byTarget))
	out := make([]responder.Wanted, 0, len(keys))
	for _, k := range keys {
		w := byTarget[k]
		sort.SliceStable(w.Findings, func(i, j int) bool {
			a, b := w.Findings[i], w.Findings[j]
			if a.Image != b.Image {
				return a.Image < b.Image
			}
			if a.VulnerabilityID != b.VulnerabilityID {
				return a.VulnerabilityID < b.VulnerabilityID
			}
			return a.Package < b.Package
		})
		out = append(out, *w)
	}
	return out
}

func cloneRequests(in map[string]state.Request) map[string]state.Request {
	out := make(map[string]state.Request, len(in))
	for k, r := range in {
		r.Asked, r.Sending = slices.Clone(r.Asked), slices.Clone(r.Sending)
		out[k] = r
	}
	return out
}

// ResponderRequests returns a copy of the requests to vuln-responder.
func (t *Tracker) ResponderRequests() map[string]state.Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state == nil {
		return nil
	}
	return cloneRequests(t.state.Requests)
}

// RespondOnce sends one request to vuln-responder, or looks at the one
// running (ADR 0009). Without a responder it does nothing.
func (t *Tracker) RespondOnce(ctx context.Context) {
	if t.Responder == nil {
		return
	}
	now := t.now()
	t.mu.Lock()
	if !t.hasSnapshot || t.state == nil {
		t.mu.Unlock()
		return
	}
	wanted := responderWanted(t.snapshot, now, t.ResponderNewWithin, t.Responder.Mode)
	records := cloneRequests(t.state.Requests)
	t.mu.Unlock()

	if !t.Responder.Step(ctx, now, wanted, records) {
		return
	}
	t.mu.Lock()
	t.state.Requests = records
	t.stateDirty = true
	t.mu.Unlock()
	// A request sent must not be forgotten by a restart, or it would be
	// sent again.
	t.saveState(ctx)
}

// digestRequests are the requests whose state changed since the last digest.
func digestRequests(records map[string]state.Request, since int64) []digest.Request {
	var out []digest.Request
	for _, k := range slices.Sorted(maps.Keys(records)) {
		r := records[k]
		if r.UpdatedAt <= since {
			continue
		}
		out = append(out, digest.Request{Target: r.Target, State: r.State, PR: r.PR, Summary: r.Summary})
	}
	return out
}
