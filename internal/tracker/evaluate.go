package tracker

import (
	"sort"
	"time"

	"github.com/yuanying/vuln-tracker/internal/annotation"
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
}

// Evaluate decides the stage and annotation of every finding. It updates the
// first-seen times in in.State and touches nothing else.
func Evaluate(in Input) Snapshot {
	snap := Snapshot{At: in.Now}
	var seenKeys []string
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
		done := map[scanner.Key]bool{}
		for _, v := range img.Vulns {
			k := scanner.Key{VulnerabilityID: v.ID, Package: v.Package}
			if done[k] {
				continue
			}
			done[k] = true

			f := Finding{Image: img.Ref, Vuln: v, Fixable: v.FixedVersion != ""}
			if !discovered {
				f.Stage = stage.Pending
			} else {
				outcomes := make([]stage.Outcome, 0, len(view.Candidates))
				for _, c := range view.Candidates {
					oc := stage.Outcome{Candidate: c.Kind, Result: c.Result}
					if c.Result == stage.Scanned {
						oc.Present = in.Scans[c.Digest].Set.Has(k)
					}
					outcomes = append(outcomes, oc)
				}
				f.Stage = stage.Decide(cands.Origin, outcomes, cands.DiscoveryFailed)
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
