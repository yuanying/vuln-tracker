package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/yuanying/vuln-tracker/internal/config"
	"github.com/yuanying/vuln-tracker/internal/github"
	"github.com/yuanying/vuln-tracker/internal/registry"
	"github.com/yuanying/vuln-tracker/internal/scanner"
	"github.com/yuanying/vuln-tracker/internal/state"
	"github.com/yuanying/vuln-tracker/internal/tracker"
)

const (
	ns      = "vuln-tracker"
	image   = "ghcr.io/yuanying/hshelf"
	dRun    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dMain   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	dOldRun = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
)

type fakeRegistry struct{}

func (fakeRegistry) Tags(context.Context, string) ([]string, error) {
	return []string{"1.0.0", "main"}, nil
}

func (fakeRegistry) Digest(_ context.Context, ref string) (string, error) {
	if ref == image+":main" {
		return dMain, nil
	}
	return "", fmt.Errorf("%s: %w", ref, registry.ErrNotFound)
}

func (fakeRegistry) Labels(context.Context, string) (map[string]string, error) {
	return map[string]string{"org.opencontainers.image.source": "https://github.com/yuanying/hshelf"}, nil
}

type fakeScanner struct{}

// :main has fixed the one vulnerability.
func (fakeScanner) Scan(context.Context, string) (scanner.Set, error) { return scanner.Set{}, nil }

type fakeRepos struct{}

func (fakeRepos) Head(context.Context, string, string) (string, error) { return "abc", nil }

func (fakeRepos) Files(context.Context, string, string) (map[string][]byte, error) {
	return map[string][]byte{}, nil
}

func (fakeRepos) OpenPullRequests(context.Context, string) ([]github.PullRequest, error) {
	return nil, nil
}

// applyManifests creates every object in the YAML files of dir.
func applyManifests(t *testing.T, c client.Client, dir string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.HasSuffix(p, "kustomization.yaml") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(b), 4096)
		for {
			var u unstructured.Unstructured
			if err := dec.Decode(&u.Object); err != nil {
				break
			}
			if len(u.Object) == 0 {
				continue
			}
			if err := c.Create(context.Background(), &u); err != nil && !apierrors.IsAlreadyExists(err) {
				t.Fatalf("%s: %v", p, err)
			}
		}
	}
}

// TestAgainstAnAPIServer runs the whole process against a real API server,
// as the ServiceAccount the manifests in config/rbac bind, so a permission
// the tracker needs and the manifests lack fails here.
func TestAgainstAnAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set; run `make test`, which downloads the control plane")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "testdata", "crds")}, ErrorIfCRDPathMissing: true}
	restCfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	admin, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	applyManifests(t, admin, filepath.Join("..", "..", "config"))
	applyManifests(t, admin, filepath.Join("..", "..", "config", "rbac"))
	if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "aphrael"}}); err != nil {
		t.Fatal(err)
	}

	// One Pod runs hshelf; a report for an older version is left over from
	// a ReplicaSet scaled to zero.
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "aphrael", Name: "aphrael-1"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "aphrael", Image: image + ":1.0.0"}}},
	}
	if err := admin.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "aphrael", Image: image + ":1.0.0", ImageID: image + "@" + dRun}}
	if err := admin.Status().Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct{ name, tag, digest string }{{"replicaset-aphrael-1-aphrael", "1.0.0", dRun}, {"replicaset-aphrael-0-aphrael", "0.9.0", dOldRun}} {
		vr := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "aquasecurity.github.io/v1alpha1",
			"kind":       "VulnerabilityReport",
			"metadata": map[string]any{
				"namespace": "aphrael",
				"name":      r.name,
				"labels": map[string]any{
					"trivy-operator.resource.kind":  "ReplicaSet",
					"trivy-operator.resource.name":  strings.TrimSuffix(strings.TrimPrefix(r.name, "replicaset-"), "-aphrael"),
					"trivy-operator.container.name": "aphrael",
				},
			},
			"report": map[string]any{
				"registry": map[string]any{"server": "ghcr.io"},
				"artifact": map[string]any{"repository": "yuanying/hshelf", "tag": r.tag, "digest": r.digest},
				"scanner":  map[string]any{"name": "Trivy", "vendor": "Aqua Security", "version": "0.75.0"},
				"summary": map[string]any{
					"criticalCount": int64(1), "highCount": int64(0), "mediumCount": int64(0),
					"lowCount": int64(0), "noneCount": int64(0), "unknownCount": int64(0),
				},
				"updateTimestamp": "2026-10-27T00:00:00Z",
				"os":              map[string]any{"family": "alpine", "name": "3.24.3"},
				"vulnerabilities": []any{map[string]any{
					"vulnerabilityID": "CVE-2026-33210", "resource": "json", "installedVersion": "2.18.0",
					"fixedVersion": ">= 2.19.2", "severity": "CRITICAL", "title": "json", "score": 9.1,
					"primaryLink": "https://avd.aquasec.com/nvd/cve-2026-33210", "links": []any{},
					"publishedDate": "2026-03-20T23:16:46Z", "lastModifiedDate": "2026-08-21T13:17:24Z",
				}},
			},
		}}
		if err := admin.Create(ctx, vr); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := config.Parse([]string{"--namespace=" + ns, "--metrics-bind-address=0", "--health-probe-bind-address=0"}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	// The process runs as the ServiceAccount, with only what config/rbac
	// grants it.
	asTracker := rest.CopyConfig(restCfg)
	asTracker.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:" + ns + ":vuln-tracker"}
	mgr, err := ctrl.NewManager(asTracker, managerOptions(cfg))
	if err != nil {
		t.Fatal(err)
	}
	tr := newTracker(mgr, cfg, &github.Client{})
	tr.Discoverer.Registry = fakeRegistry{}
	tr.Discoverer.RenovateAuthor = regexp.MustCompile("renovate")
	tr.Scanner = fakeScanner{}
	tr.GitHub = fakeRepos{}
	tr.Metrics = tracker.NewMetrics(prometheus.NewRegistry())
	tr.Log = logr.Discard()
	tr.LoopInterval = 200 * time.Millisecond
	tr.ScanInterval = 10 * time.Millisecond
	if err := watch(mgr, tr); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Add(tr); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := mgr.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("manager: %v", err)
		}
	})
	t.Cleanup(func() { cancel(); wg.Wait() })

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(&tracker.Collector{DetailSeverities: cfg.DetailSeverities, Snapshot: tr.Snapshot})

	want := `
# HELP vuln_tracker_findings Findings of images running in production, counted by image, severity, stage and annotation.
# TYPE vuln_tracker_findings gauge
vuln_tracker_findings{digest="` + dRun + `",fixable="true",image="ghcr.io/yuanying/hshelf",severity="CRITICAL",stage="fixed-in-main",tag="1.0.0",vex_expired="false",vex_state="none"} 1
`
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := testutil.GatherAndCompare(reg, strings.NewReader(want), "vuln_tracker_findings")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			snap, _ := tr.Snapshot()
			t.Fatalf("the finding never reached fixed-in-main: %v\nsnapshot: %+v", err, snap)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// The state went to its ConfigMap, through the narrow Role.
	var cm corev1.ConfigMap
	deadline = time.Now().Add(30 * time.Second)
	for {
		err := admin.Get(ctx, client.ObjectKey{Namespace: ns, Name: "vuln-tracker-state"}, &cm)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the state ConfigMap was never written: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	st, err := state.Decode(cm.BinaryData[state.DataKey])
	if err != nil {
		t.Fatal(err)
	}
	if st.FirstSeen(image+"|CVE-2026-33210") != 0 {
		t.Errorf("what is there at install should be first seen at 0: %+v", st.Seen)
	}
}
