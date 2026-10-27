// Package manifests finds which version of each image the manifest
// repositories (fleet-infra, k8s-manifests-fraction) name, so the tracker can
// tell a fix that is in git but not yet applied (ADR 0002).
//
// Nothing is rendered. Every YAML document is walked and three shapes are
// read: a kustomization's images (name or newName, with newTag and digest), an
// `image:` written as a reference, and a Helm values pair of `repository` and
// `tag` (with an optional `registry`). A version written any other way, built
// in a template for instance, is not found.
package manifests

import (
	"bufio"
	"bytes"
	"path"
	"slices"
	"strings"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

	"github.com/yuanying/vuln-tracker/internal/imageref"
)

// Index maps an image name ("<registry>/<repository>") to the versions the
// repositories name for it.
type Index map[string][]imageref.Ref

// Build reads every .yaml and .yml file among files. A file that is not valid
// YAML is skipped: a manifest repository holds plenty of templates.
func Build(files map[string][]byte) Index {
	ix := Index{}
	for p, b := range files {
		switch path.Ext(p) {
		case ".yaml", ".yml":
		default:
			continue
		}
		r := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(b)))
		for {
			doc, err := r.Read()
			// A read error other than the end leaves the rest of the
			// file unreadable; what was read so far still counts.
			if err != nil {
				break
			}
			var v any
			if err := yaml.Unmarshal(doc, &v); err != nil {
				continue
			}
			ix.walk(v)
		}
	}
	return ix
}

func (ix Index) add(r imageref.Ref) {
	if r.Tag == "" && r.Digest == "" {
		return
	}
	n := r.Name()
	if !slices.Contains(ix[n], r) {
		ix[n] = append(ix[n], r)
	}
}

func (ix Index) addString(s string) {
	if r, err := imageref.Parse(strings.TrimSpace(s)); err == nil {
		ix.add(r)
	}
}

func (ix Index) walk(v any) {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t["image"].(string); ok {
			ix.addString(s)
		}
		ix.helmPair(t)
		if list, ok := t["images"].([]any); ok {
			for _, item := range list {
				if m, ok := item.(map[string]any); ok {
					ix.kustomizeImage(m)
				}
			}
		}
		for _, child := range t {
			ix.walk(child)
		}
	case []any:
		for _, child := range t {
			ix.walk(child)
		}
	}
}

func (ix Index) helmPair(m map[string]any) {
	repo, ok := m["repository"].(string)
	if !ok || repo == "" {
		return
	}
	tag, ok := m["tag"].(string)
	if !ok || tag == "" {
		return
	}
	if reg, ok := m["registry"].(string); ok && reg != "" {
		repo = reg + "/" + repo
	}
	ix.addString(repo + ":" + tag)
}

func (ix Index) kustomizeImage(m map[string]any) {
	name, _ := m["name"].(string)
	if n, ok := m["newName"].(string); ok && n != "" {
		name = n
	}
	if name == "" {
		return
	}
	ref := name
	tag, _ := m["newTag"].(string)
	digest, _ := m["digest"].(string)
	if tag == "" && digest == "" {
		return
	}
	if tag != "" {
		ref += ":" + tag
	}
	if digest != "" && !strings.Contains(tag, "@") {
		ref += "@" + digest
	}
	ix.addString(ref)
}

// Versions returns the versions named for an image.
func (ix Index) Versions(name string) []imageref.Ref {
	return ix[name]
}

// Merge combines indexes, one per repository.
func Merge(ixs ...Index) Index {
	out := Index{}
	for _, ix := range ixs {
		for _, refs := range ix {
			for _, r := range refs {
				out.add(r)
			}
		}
	}
	return out
}
