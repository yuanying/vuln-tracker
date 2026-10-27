package manifests

import (
	"slices"
	"testing"
)

const digestA = "sha256:28bed156fd3edf8f3899f4e669608e0faa16d25c51904bd04ce40ec4c4e06b5e"

var files = map[string][]byte{
	"apps/aphrael/base/kustomization.yaml": []byte(`
resources:
- aphrael.yaml
images:
- name: ghcr.io/yuanying/hshelf
  newTag: 1.0.0@` + digestA + `
- name: nginx
  newTag: 1.30.6-alpine
- name: old/name
  newName: quay.io/kiwigrid/k8s-sidecar
  newTag: 2.14.2
- name: registry.k8s.io/pause
  digest: ` + digestA + `
`),
	"apps/aphrael/base/aphrael.yaml": []byte(`
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - image: ghcr.io/yuanying/hshelf:0.9.0
      initContainers:
      - image: docker.io/library/busybox:1.37
---
apiVersion: batch/v1
kind: CronJob
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - image: "ghcr.io/yuanying/tumblr-like:0.4.1"
`),
	"infrastructure/longhorn/values.yaml": []byte(`
image:
  longhorn:
    engine:
      repository: longhornio/longhorn-engine
      tag: v1.13.1
  csi:
    attacher:
      registry: registry.k8s.io
      repository: sig-storage/csi-attacher
      tag: v4.14.0
`),
	"broken.yaml":         []byte("a: [b"),
	"README.md":           []byte("image: ghcr.io/yuanying/not-read:1.0.0"),
	"empty.yaml":          []byte(""),
	"image-is-a-map.yaml": []byte("image:\n  pullPolicy: Always\n"),
}

func versions(ix Index, name string) []string {
	var out []string
	for _, r := range ix.Versions(name) {
		out = append(out, r.String())
	}
	slices.Sort(out)
	return out
}

func TestIndex(t *testing.T) {
	ix := Build(files)
	tests := []struct {
		name string
		want []string
	}{
		{"ghcr.io/yuanying/hshelf", []string{
			"ghcr.io/yuanying/hshelf:0.9.0",
			"ghcr.io/yuanying/hshelf:1.0.0@" + digestA,
		}},
		{"index.docker.io/library/nginx", []string{"index.docker.io/library/nginx:1.30.6-alpine"}},
		{"quay.io/kiwigrid/k8s-sidecar", []string{"quay.io/kiwigrid/k8s-sidecar:2.14.2"}},
		{"index.docker.io/old/name", nil},
		{"registry.k8s.io/pause", []string{"registry.k8s.io/pause@" + digestA}},
		{"index.docker.io/library/busybox", []string{"index.docker.io/library/busybox:1.37"}},
		{"ghcr.io/yuanying/tumblr-like", []string{"ghcr.io/yuanying/tumblr-like:0.4.1"}},
		{"index.docker.io/longhornio/longhorn-engine", []string{"index.docker.io/longhornio/longhorn-engine:v1.13.1"}},
		{"registry.k8s.io/sig-storage/csi-attacher", []string{"registry.k8s.io/sig-storage/csi-attacher:v4.14.0"}},
		{"ghcr.io/yuanying/not-read", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versions(ix, tt.name); !slices.Equal(got, tt.want) {
				t.Errorf("Versions(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	a := Build(map[string][]byte{"a.yaml": []byte("image: ghcr.io/yuanying/live:1.0.0")})
	b := Build(map[string][]byte{"b.yaml": []byte("image: ghcr.io/yuanying/live:1.0.1\n---\nimage: ghcr.io/yuanying/live:1.0.0")})
	got := versions(Merge(a, b), "ghcr.io/yuanying/live")
	want := []string{"ghcr.io/yuanying/live:1.0.0", "ghcr.io/yuanying/live:1.0.1"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	refs := Merge(a, b).Versions("x")
	if len(refs) != 0 {
		t.Errorf("an image no manifest names has versions: %v", refs)
	}
}
