package tracker

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/yuanying/vuln-tracker/internal/responder"
	"github.com/yuanying/vuln-tracker/internal/stage"
)

// Reasons a source repository is a gap in what vuln-responder can fix
// (ADR 0016). They are the `reason` label of
// vuln_tracker_responder_coverage_gap (ADR 0005).
const (
	// GapArchived is a source archived on GitHub: nothing can be pushed.
	GapArchived = "archived"
	// GapNotWritable is a source missing from github-writer.json.
	GapNotWritable = "not-writable"
)

// archivedTTL is how long a read of whether a source is archived stands.
// Archiving is rare, and the alert waits an hour anyway.
const archivedTTL = time.Hour

// syncTargetRepositories is the `target` label of the reads of whether the
// sources are archived (ADR 0005).
const syncTargetRepositories = "repositories"

// CoverageGap is one source repository vuln-responder cannot fix, for one
// reason.
type CoverageGap struct {
	// SourceRepository is "owner/name".
	SourceRepository string
	Reason           string
}

type archivedRead struct {
	at       time.Time
	archived bool
}

// CoverageGaps are the source repositories of the self-built images that
// vuln-responder cannot fix, sorted. A nil writable, which is a
// github-writer.json never read, makes nothing not writable; a source missing
// from archived is taken as not archived.
func CoverageGaps(images []ImageView, writable responder.Writable, archived map[string]bool) []CoverageGap {
	sources := map[string]bool{}
	for _, img := range images {
		if !img.SelfBuilt {
			continue
		}
		if repo, ok := sourceRepository(img.Source); ok {
			sources[repo] = true
		}
	}
	var gaps []CoverageGap
	for _, repo := range slices.Sorted(maps.Keys(sources)) {
		if archived[repo] {
			gaps = append(gaps, CoverageGap{SourceRepository: repo, Reason: GapArchived})
		}
		if writable != nil && !writable.Has(repo) {
			gaps = append(gaps, CoverageGap{SourceRepository: repo, Reason: GapNotWritable})
		}
	}
	return gaps
}

// syncArchived reads whether each self-built image's source is archived,
// when the last read is older than archivedTTL. A read that fails keeps the
// last one; the sources no longer running are forgotten.
func (t *Tracker) syncArchived(ctx context.Context, images []Image, cands map[string]Candidates) {
	now := t.now()
	sources := map[string]bool{}
	for _, img := range images {
		c, ok := cands[img.Key()]
		if !ok || c.Origin != stage.SelfBuilt {
			continue
		}
		if repo, ok := sourceRepository(c.Source); ok {
			sources[repo] = true
		}
	}
	t.mu.Lock()
	for repo := range t.archived {
		if !sources[repo] {
			delete(t.archived, repo)
		}
	}
	var due []string
	for _, repo := range slices.Sorted(maps.Keys(sources)) {
		if a, ok := t.archived[repo]; !ok || now.Sub(a.at) >= archivedTTL {
			due = append(due, repo)
		}
	}
	t.mu.Unlock()
	if len(due) == 0 {
		return
	}

	failed := 0
	for _, repo := range due {
		archived, err := t.GitHub.Archived(ctx, repo)
		if err != nil {
			t.Log.Error(err, "reading whether a source repository is archived", "repository", repo)
			failed++
			continue
		}
		t.mu.Lock()
		t.archived[repo] = archivedRead{at: now, archived: archived}
		t.mu.Unlock()
	}
	if t.Metrics != nil {
		if failed > 0 {
			t.Metrics.SyncErrors.WithLabelValues(syncTargetRepositories).Add(float64(failed))
		} else {
			t.Metrics.SyncTimestamp.WithLabelValues(syncTargetRepositories).SetToCurrentTime()
		}
	}
}
