package tracker

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func vr(ns, kind, name, container, repo, tag, digest string, vulns ...map[string]any) *unstructured.Unstructured {
	vs := make([]any, 0, len(vulns))
	for _, v := range vulns {
		vs = append(vs, v)
	}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"metadata": map[string]any{
			"namespace": ns,
			"name":      kind + "-" + name + "-" + container,
			"labels": map[string]any{
				"trivy-operator.resource.kind":      kind,
				"trivy-operator.resource.name":      name,
				"trivy-operator.resource.namespace": ns,
				"trivy-operator.container.name":     container,
			},
		},
		"report": map[string]any{
			"registry":        map[string]any{"server": "ghcr.io"},
			"artifact":        map[string]any{"repository": repo, "tag": tag, "digest": digest},
			"vulnerabilities": vs,
		},
	}}
	return u
}

func vuln(id, pkg, sev, fixed string) map[string]any {
	return map[string]any{
		"vulnerabilityID": id, "resource": pkg, "severity": sev, "fixedVersion": fixed,
		"installedVersion": "1.0", "packagePURL": "pkg:generic/" + pkg + "@1.0",
	}
}

func pod(ns, name string, imageIDs ...string) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	for _, id := range imageIDs {
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{ImageID: id})
	}
	return p
}

func TestParseReport(t *testing.T) {
	r, err := ParseReport(vr("aphrael", "ReplicaSet", "aphrael-1", "aphrael", "yuanying/hshelf", "httpd:1.0.0", dRun,
		vuln("CVE-1", "json", "CRITICAL", ">= 2.19.2")))
	if err != nil {
		t.Fatal(err)
	}
	if r.Image.Name() != "ghcr.io/yuanying/hshelf" || r.Image.Tag != "1.0.0" || r.Image.Digest != dRun {
		t.Errorf("image: %+v (the tag should be read after the last colon)", r.Image)
	}
	if r.Workload != (Workload{Namespace: "aphrael", Kind: "ReplicaSet", Name: "aphrael-1", Container: "aphrael"}) {
		t.Errorf("workload: %+v", r.Workload)
	}
	if len(r.Vulns) != 1 || r.Vulns[0] != (Vuln{ID: "CVE-1", Package: "json", InstalledVersion: "1.0", FixedVersion: ">= 2.19.2", Severity: "CRITICAL", PURL: "pkg:generic/json@1.0"}) {
		t.Errorf("vulns: %+v", r.Vulns)
	}
}

func TestRunningDigests(t *testing.T) {
	p := pod("a", "p", "ghcr.io/yuanying/hshelf@"+dRun, "docker.io/library/nginx@"+dMain, "")
	p.Status.InitContainerStatuses = []corev1.ContainerStatus{{ImageID: "docker-pullable://busybox@" + dGit}}
	got := RunningDigests([]corev1.Pod{p})
	for _, d := range []string{dRun, dMain, dGit} {
		if !got[d] {
			t.Errorf("%s not running: %v", d, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %v", got)
	}
}

func TestInventory(t *testing.T) {
	inv := NewInventory()
	running := RunningDigests([]corev1.Pod{pod("aphrael", "p", "ghcr.io/yuanying/hshelf@"+dRun)})
	reports := []Report{
		mustParse(t, vr("aphrael", "ReplicaSet", "aphrael-1", "aphrael", "yuanying/hshelf", "1.0.0", dRun, vuln("CVE-1", "json", "CRITICAL", "x"))),
		mustParse(t, vr("aphrael", "ReplicaSet", "aphrael-2", "aphrael", "yuanying/hshelf", "1.0.0", dRun, vuln("CVE-1", "json", "CRITICAL", "x"))),
		// A ReplicaSet scaled to zero keeps its report, but nothing runs it.
		mustParse(t, vr("aphrael", "ReplicaSet", "aphrael-0", "aphrael", "yuanying/hshelf", "0.9.0", dGit, vuln("CVE-0", "json", "CRITICAL", "x"))),
		// A CronJob runs between its Pods too.
		mustParse(t, vr("backup", "CronJob", "nightly", "job", "yuanying/backup", "1.0.0", dMain, vuln("CVE-2", "tar", "HIGH", ""))),
	}
	imgs := inv.Build(reports, running)
	if len(imgs) != 2 {
		t.Fatalf("got %d images, want 2: %+v", len(imgs), imgs)
	}
	byKey := map[string]Image{}
	for _, i := range imgs {
		byKey[i.Key()] = i
	}
	h := byKey["ghcr.io/yuanying/hshelf@"+dRun]
	if len(h.Workloads) != 2 {
		t.Errorf("hshelf should run in two places: %+v", h.Workloads)
	}
	if _, ok := byKey["ghcr.io/yuanying/backup@"+dMain]; !ok {
		t.Error("the CronJob's image is missing")
	}

	// The report is retaken: it is gone for a while, the Pod still runs.
	imgs = inv.Build(reports[3:], running)
	if len(imgs) != 2 {
		t.Fatalf("a report in its TTL gap should be held: %+v", imgs)
	}
	// The Pod moves to a new version: the held report goes too.
	imgs = inv.Build(reports[3:], RunningDigests(nil))
	if len(imgs) != 1 {
		t.Errorf("got %+v, want only the CronJob", imgs)
	}
	// And it is not resurrected when the old digest runs again without a report.
	imgs = inv.Build(reports[3:], running)
	if len(imgs) != 1 {
		t.Errorf("a dropped report came back: %+v", imgs)
	}
}

func mustParse(t *testing.T, u *unstructured.Unstructured) Report {
	t.Helper()
	r, err := ParseReport(u)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
