package tracker

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/yuanying/vuln-tracker/internal/state"
)

// The metrics are the contract with the dashboard and the alert rules in
// fleet-infra (ADR 0005). Renaming a metric or a label means changing those
// in the same breath.
var (
	findingDesc = prometheus.NewDesc("vuln_tracker_finding",
		"A vulnerability in a package of an image running in production, for the severities listed in detail. The value is when the image × vulnerability pair was first seen (unix seconds; 0 for what was there when the tracker was installed).",
		[]string{"image", "tag", "digest", "severity", "stage", "fixable", "vex_state", "vex_expired", "vulnerability_id", "package", "installed_version", "fixed_version", "vex_status", "vex_review_by"}, nil)
	findingsDesc = prometheus.NewDesc("vuln_tracker_findings",
		"Findings of images running in production, counted by image, severity, stage and annotation.",
		[]string{"image", "tag", "digest", "severity", "stage", "fixable", "vex_state", "vex_expired"}, nil)
	imageInfoDesc = prometheus.NewDesc("vuln_tracker_image_info",
		"An image running in production: whether it is built here, its source and the revision it was built from.",
		[]string{"image", "tag", "digest", "self_built", "source", "revision"}, nil)
	workloadInfoDesc = prometheus.NewDesc("vuln_tracker_image_workload_info",
		"Where an image running in production runs.",
		[]string{"image", "tag", "digest", "namespace", "kind", "name", "container"}, nil)
	candidateInfoDesc = prometheus.NewDesc("vuln_tracker_candidate_info",
		"A version that may carry fixes for an image running in production. The value is when it was last scanned (unix seconds; 0 if not yet).",
		[]string{"image", "digest", "candidate", "candidate_tag", "candidate_digest", "revision", "result"}, nil)
	requestDesc = prometheus.NewDesc("vuln_tracker_responder_request_info",
		"A request to vuln-responder for one target, as last seen. The value is when its state last changed (unix seconds).",
		[]string{"target", "target_type", "state", "pr"}, nil)
	renovateDesc = prometheus.NewDesc("vuln_tracker_image_renovate_pr_info",
		"An open Renovate pull request that names an image running in production.",
		[]string{"image", "url"}, nil)
)

// Collector exports the latest snapshot. It is unchecked: the series come
// and go with what runs in production.
type Collector struct {
	// DetailSeverities are the severities vuln_tracker_finding is exported
	// for.
	DetailSeverities map[string]bool
	// Snapshot returns the latest evaluation, or false before the first.
	Snapshot func() (Snapshot, bool)
	// Requests returns the requests to vuln-responder; nil exports none.
	Requests func() map[string]state.Request
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	if c.Requests != nil {
		for _, r := range c.Requests() {
			ch <- prometheus.MustNewConstMetric(requestDesc, prometheus.GaugeValue, float64(r.UpdatedAt),
				r.Target, r.TargetType, r.State, r.PR)
		}
	}
	snap, ok := c.Snapshot()
	if !ok {
		return
	}
	type countKey struct {
		image, tag, digest, severity, stage, fixable, vexState, vexExpired string
	}
	counts := map[countKey]int{}
	for _, f := range snap.Findings {
		fixable := strconv.FormatBool(f.Fixable)
		expired := strconv.FormatBool(f.VexExpired)
		counts[countKey{f.Image.Name(), f.Image.Tag, f.Image.Digest, f.Vuln.Severity, string(f.Stage), fixable, f.VexState(), expired}]++
		if !c.DetailSeverities[f.Vuln.Severity] {
			continue
		}
		var status, reviewBy string
		if f.Annotation != nil {
			status, reviewBy = f.Annotation.Status, f.Annotation.ReviewBy
		}
		ch <- prometheus.MustNewConstMetric(findingDesc, prometheus.GaugeValue, float64(f.FirstSeen),
			f.Image.Name(), f.Image.Tag, f.Image.Digest, f.Vuln.Severity, string(f.Stage), fixable, f.VexState(), expired,
			f.Vuln.ID, f.Vuln.Package, f.Vuln.InstalledVersion, f.Vuln.FixedVersion, status, reviewBy)
	}
	for k, n := range counts {
		ch <- prometheus.MustNewConstMetric(findingsDesc, prometheus.GaugeValue, float64(n),
			k.image, k.tag, k.digest, k.severity, k.stage, k.fixable, k.vexState, k.vexExpired)
	}
	for _, img := range snap.Images {
		name := img.Ref.Name()
		ch <- prometheus.MustNewConstMetric(imageInfoDesc, prometheus.GaugeValue, 1,
			name, img.Ref.Tag, img.Ref.Digest, strconv.FormatBool(img.SelfBuilt), img.Source, img.Revision)
		seenWorkload := map[Workload]bool{}
		for _, w := range img.Workloads {
			if seenWorkload[w] {
				continue
			}
			seenWorkload[w] = true
			ch <- prometheus.MustNewConstMetric(workloadInfoDesc, prometheus.GaugeValue, 1,
				name, img.Ref.Tag, img.Ref.Digest, w.Namespace, w.Kind, w.Name, w.Container)
		}
		for _, cv := range img.Candidates {
			var at float64
			if !cv.At.IsZero() {
				at = float64(cv.At.Unix())
			}
			ch <- prometheus.MustNewConstMetric(candidateInfoDesc, prometheus.GaugeValue, at,
				name, img.Ref.Digest, string(cv.Kind), cv.Tag, cv.Digest, cv.Revision, string(cv.Result))
		}
	}
	// One series per image and pull request, even when several running
	// versions of the image name it.
	seenPR := map[[2]string]bool{}
	for _, img := range snap.Images {
		for _, u := range img.RenovatePRs {
			k := [2]string{img.Ref.Name(), u}
			if seenPR[k] {
				continue
			}
			seenPR[k] = true
			ch <- prometheus.MustNewConstMetric(renovateDesc, prometheus.GaugeValue, 1, k[0], k[1])
		}
	}
}

// Metrics are the tracker's own operational metrics.
type Metrics struct {
	Scans         *prometheus.CounterVec
	ScanDuration  prometheus.Histogram
	SyncTimestamp *prometheus.GaugeVec
	SyncErrors    *prometheus.CounterVec
	DigestSent    prometheus.Gauge
}

// NewMetrics creates the operational metrics and registers them.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Scans: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vuln_tracker_scans_total",
			Help: "Scans of candidate versions, by result.",
		}, []string{"result"}),
		ScanDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vuln_tracker_scan_duration_seconds",
			Help:    "How long one scan of a candidate version took.",
			Buckets: []float64{5, 15, 30, 60, 120, 300, 600},
		}),
		SyncTimestamp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "vuln_tracker_sync_timestamp_seconds",
			Help: "When a source was last read successfully (unix seconds).",
		}, []string{"target"}),
		SyncErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vuln_tracker_sync_errors_total",
			Help: "Failed reads of a source. For vex, the documents and statements left out.",
		}, []string{"target"}),
		DigestSent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vuln_tracker_digest_sent_timestamp_seconds",
			Help: "When the weekly digest was last sent (unix seconds).",
		}),
	}
	reg.MustRegister(m.Scans, m.ScanDuration, m.SyncTimestamp, m.SyncErrors, m.DigestSent)
	return m
}
