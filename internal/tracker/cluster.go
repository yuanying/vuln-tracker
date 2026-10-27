package tracker

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClusterSource reads VulnerabilityReports and Pods from the manager's cache
// (ADR 0001).
type ClusterSource struct {
	Reader client.Reader
}

// List implements Source. A report that names no image is skipped.
func (s *ClusterSource) List(ctx context.Context) ([]Report, []corev1.Pod, error) {
	var list unstructured.UnstructuredList
	list.SetGroupVersionKind(VulnerabilityReportGVK.GroupVersion().WithKind(VulnerabilityReportGVK.Kind + "List"))
	if err := s.Reader.List(ctx, &list); err != nil {
		return nil, nil, fmt.Errorf("listing VulnerabilityReports: %w", err)
	}
	reports := make([]Report, 0, len(list.Items))
	for i := range list.Items {
		r, err := ParseReport(&list.Items[i])
		if err != nil {
			continue
		}
		reports = append(reports, r)
	}
	var pods corev1.PodList
	if err := s.Reader.List(ctx, &pods); err != nil {
		return nil, nil, fmt.Errorf("listing Pods: %w", err)
	}
	return reports, pods.Items, nil
}

// StripPod is the cache transform for Pods: only what tells which digests
// run is kept (ADR 0007).
func StripPod(obj any) (any, error) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return obj, nil
	}
	out := &corev1.Pod{}
	out.Name, out.Namespace, out.UID, out.ResourceVersion = p.Name, p.Namespace, p.UID, p.ResourceVersion
	strip := func(in []corev1.ContainerStatus) []corev1.ContainerStatus {
		res := make([]corev1.ContainerStatus, 0, len(in))
		for _, cs := range in {
			res = append(res, corev1.ContainerStatus{Name: cs.Name, ImageID: cs.ImageID})
		}
		return res
	}
	out.Status.ContainerStatuses = strip(p.Status.ContainerStatuses)
	out.Status.InitContainerStatuses = strip(p.Status.InitContainerStatuses)
	return out, nil
}
