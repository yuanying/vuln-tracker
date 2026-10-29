package tracker

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/yuanying/vuln-tracker/internal/annotation"
	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/pipeline"
	"github.com/yuanying/vuln-tracker/internal/scanner"
	"github.com/yuanying/vuln-tracker/internal/stage"
	"github.com/yuanying/vuln-tracker/internal/state"
)

// Input is everything one evaluation reads.
type Input struct {
	// Images are the versions running in production.
	Images []Image
	// Candidates are keyed by Image.Key. A running version discovery has not
	// reached yet has none, and its findings are pending.
	Candidates map[string]Candidates
	// Scans are keyed by digest.
	Scans map[string]ScanResult
	// VEX is fleet-infra's annotations; nil means none.
	VEX *annotation.Set
	// State records first-seen times. Evaluate updates it.
	State *state.State
	Now   time.Time
	// Today is YYYY-MM-DD in the tracker's time zone, for review-by dates.
	Today string
	// ManifestRepos are the manifest repositories, in the order of
	// --manifests.
	ManifestRepos []RepoIndex
	// PullRequests are linked to the findings (ADR 0014).
	PullRequests PullRequests
	// Synced is copied to the snapshot.
	Synced bool
}

// replies maps a finding ("<image>|<vulnerability>|<package>") to the pull
// requests vuln-responder's replies named for it: the reply to every request
// that asked about it.
func replies(st *state.State, prs map[string]github.PullRequest) map[string][]github.PullRequest {
	out := map[string][]github.PullRequest{}
	if st == nil {
		return out
	}
	for _, rec := range st.Requests {
		pr, ok := prs[rec.PR]
		if rec.PR == "" || !ok {
			continue
		}
		for _, k := range append(slices.Clone(rec.Asked), rec.Sending...) {
			// A bump's key carries the stage after the package.
			parts := strings.SplitN(k, "|", 4)
			if len(parts) < 3 {
				continue
			}
			fk := strings.Join(parts[:3], "|")
			if !slices.ContainsFunc(out[fk], func(p github.PullRequest) bool { return p.URL == pr.URL }) {
				out[fk] = append(out[fk], pr)
			}
		}
	}
	return out
}

// manifestRepository is the first repository that names the image.
func manifestRepository(repos []RepoIndex, name string) string {
	for _, r := range repos {
		if len(r.Index.Versions(name)) > 0 {
			return r.Name
		}
	}
	return ""
}

// Evaluate decides the stage and annotation of every finding. It updates the
// first-seen times in in.State and touches nothing else.
func Evaluate(in Input) Snapshot {
	snap := Snapshot{At: in.Now, Synced: in.Synced}
	var seenKeys []string
	repoNames := make([]string, 0, len(in.ManifestRepos))
	for _, r := range in.ManifestRepos {
		repoNames = append(repoNames, r.Name)
	}
	links := pipeline.NewIndex(pipeline.Repos{
		Manifests: repoNames,
		Open:      in.PullRequests.Open,
		VEXOnly:   in.PullRequests.VEXOnly,
		Renovate:  in.PullRequests.Renovate,
	})
	replied := replies(in.State, in.PullRequests.Replies)
	images := append([]Image(nil), in.Images...)
	sort.Slice(images, func(i, j int) bool { return images[i].Key() < images[j].Key() })

	for _, img := range images {
		cands, discovered := in.Candidates[img.Key()]
		view := ImageView{
			Ref:         img.Ref,
			SelfBuilt:   cands.Origin == stage.SelfBuilt && discovered,
			Source:      cands.Source,
			Revision:    cands.Revision,
			Workloads:   img.Workloads,
			RenovatePRs: cands.RenovatePRs,
		}
		for _, c := range cands.List {
			v := CandidateView{CandidateRef: c, Result: stage.NotScanned}
			if r, ok := in.Scans[c.Digest]; ok {
				v.At = r.At
				v.Result = stage.Scanned
				if r.Err != nil {
					v.Result = stage.Failed
				}
			}
			view.Candidates = append(view.Candidates, v)
		}
		snap.Images = append(snap.Images, view)

		purl := img.Ref.PURL()
		srcRepo := ""
		if repo, ok := sourceRepository(view.Source); ok && view.SelfBuilt {
			srcRepo = repo
		}
		manRepo := manifestRepository(in.ManifestRepos, img.Ref.Name())
		done := map[scanner.Key]bool{}
		for _, v := range img.Vulns {
			k := scanner.Key{VulnerabilityID: v.ID, Package: v.Package}
			if done[k] {
				continue
			}
			done[k] = true

			f := Finding{Image: img.Ref, Vuln: v, Fixable: v.FixedVersion != ""}
			pin := pipeline.Input{Discovered: discovered, Origin: cands.Origin, DiscoveryFailed: cands.DiscoveryFailed}
			if !discovered {
				f.Stage = stage.Pending
			} else {
				for _, c := range view.Candidates {
					oc := stage.Outcome{Candidate: c.Kind, Result: c.Result}
					if c.Result == stage.Scanned {
						oc.Present = in.Scans[c.Digest].Set.Has(k)
					}
					pin.Outcomes = append(pin.Outcomes, oc)
				}
				f.Stage = stage.Decide(cands.Origin, pin.Outcomes, cands.DiscoveryFailed)
			}
			linked := links.Link(pipeline.Finding{Image: img.Ref.Name(), VulnerabilityID: v.ID, Package: v.Package, SourceRepository: srcRepo},
				replied[img.Ref.Name()+"|"+v.ID+"|"+v.Package])
			f.Pipeline = Pipeline{
				SourceRepository:   srcRepo,
				Source:             pipeline.Source(pin, pipeline.AnyOpen(linked.Source)),
				SourcePRs:          linked.Source,
				ManifestRepository: manRepo,
				Manifest:           pipeline.Manifest(pin, pipeline.AnyOpen(linked.Manifest)),
				ManifestPRs:        linked.Manifest,
				VEXPRs:             linked.VEX,
			}
			if in.VEX != nil {
				if a, ok := in.VEX.Lookup(v.ID, purl, v.PURL); ok {
					f.Annotation = &a
					f.VexExpired = a.Expired(in.Today)
				}
			}
			seenKeys = append(seenKeys, firstSeenKey(img.Ref.Name(), v.ID))
			snap.Findings = append(snap.Findings, f)
		}
	}

	in.State.Observe(in.Now, seenKeys)
	for i := range snap.Findings {
		f := &snap.Findings[i]
		f.FirstSeen = in.State.FirstSeen(firstSeenKey(f.Image.Name(), f.Vuln.ID))
	}
	return snap
}
