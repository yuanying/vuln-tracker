package tracker

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/yuanying/vuln-tracker/internal/imageref"
)

// VulnerabilityReportGVK is Trivy Operator's report. The tracker reads it as
// unstructured: the CRD belongs to Trivy Operator, and only a handful of its
// fields are read.
var VulnerabilityReportGVK = schema.GroupVersionKind{Group: "aquasecurity.github.io", Version: "v1alpha1", Kind: "VulnerabilityReport"}

type reportJSON struct {
	Metadata struct {
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Report struct {
		Registry struct {
			Server string `json:"server"`
		} `json:"registry"`
		Artifact struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
			Digest     string `json:"digest"`
		} `json:"artifact"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"vulnerabilityID"`
			Resource         string `json:"resource"`
			InstalledVersion string `json:"installedVersion"`
			FixedVersion     string `json:"fixedVersion"`
			Severity         string `json:"severity"`
			PackagePURL      string `json:"packagePURL"`
		} `json:"vulnerabilities"`
	} `json:"report"`
}

// ParseReport reads a VulnerabilityReport.
func ParseReport(u *unstructured.Unstructured) (Report, error) {
	var r reportJSON
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &r); err != nil {
		return Report{}, fmt.Errorf("reading VulnerabilityReport %s/%s: %w", u.GetNamespace(), u.GetName(), err)
	}
	a := r.Report.Artifact
	if r.Report.Registry.Server == "" || a.Repository == "" || a.Digest == "" {
		return Report{}, fmt.Errorf("VulnerabilityReport %s/%s names no image digest", u.GetNamespace(), u.GetName())
	}
	out := Report{
		Image: imageref.Ref{
			Registry:   r.Report.Registry.Server,
			Repository: a.Repository,
			Tag:        imageref.ReportTag(a.Tag),
			Digest:     a.Digest,
		},
		Workload: Workload{
			Namespace: r.Metadata.Namespace,
			Kind:      r.Metadata.Labels["trivy-operator.resource.kind"],
			Name:      r.Metadata.Labels["trivy-operator.resource.name"],
			Container: r.Metadata.Labels["trivy-operator.container.name"],
		},
	}
	for _, v := range r.Report.Vulnerabilities {
		out.Vulns = append(out.Vulns, Vuln{
			ID:               v.VulnerabilityID,
			Package:          v.Resource,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     v.FixedVersion,
			Severity:         v.Severity,
			PURL:             v.PackagePURL,
		})
	}
	return out, nil
}

// RunningDigests is every digest a Pod runs, init containers included.
func RunningDigests(pods []corev1.Pod) map[string]bool {
	out := map[string]bool{}
	for _, p := range pods {
		for _, list := range [][]corev1.ContainerStatus{p.Status.ContainerStatuses, p.Status.InitContainerStatuses} {
			for _, cs := range list {
				if _, d, ok := strings.Cut(cs.ImageID, "@"); ok && d != "" {
					out[d] = true
				}
			}
		}
	}
	return out
}

// alwaysRunning says whether a report counts as running without a Pod: the
// Pods of a CronJob come and go between runs (ADR 0002).
func alwaysRunning(w Workload) bool {
	return w.Kind == "CronJob" || w.Kind == "Job"
}

// Inventory turns reports into running versions. It holds the last report of
// a version while its report is being retaken (Trivy Operator deletes it at
// the end of its TTL and scans again), for as long as a Pod still runs it.
type Inventory struct {
	held map[string]Image
}

// NewInventory returns an empty inventory.
func NewInventory() *Inventory {
	return &Inventory{held: map[string]Image{}}
}

// Build returns the versions running now.
func (inv *Inventory) Build(reports []Report, running map[string]bool) []Image {
	byKey := map[string]*Image{}
	for _, r := range reports {
		if !running[r.Image.Digest] && !alwaysRunning(r.Workload) {
			continue
		}
		ref := r.Image
		key := ref.Name() + "@" + ref.Digest
		img, ok := byKey[key]
		if !ok {
			img = &Image{Ref: ref}
			byKey[key] = img
		}
		img.Workloads = append(img.Workloads, r.Workload)
		// The same version scanned for two workloads lists the same
		// vulnerabilities; Evaluate keeps one of each.
		img.Vulns = append(img.Vulns, r.Vulns...)
	}
	for key, img := range inv.held {
		if _, ok := byKey[key]; ok {
			continue
		}
		if !running[img.Ref.Digest] {
			delete(inv.held, key)
			continue
		}
		held := img
		byKey[key] = &held
	}

	out := make([]Image, 0, len(byKey))
	for key, img := range byKey {
		inv.held[key] = *img
		out = append(out, *img)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}
