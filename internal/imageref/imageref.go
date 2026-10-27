// Package imageref names container images the way Trivy and Trivy Operator do,
// so that a name read from a manifest, a VulnerabilityReport and a VEX file
// path all come out the same (ADR 0002, ADR 0004).
package imageref

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/package-url/packageurl-go"
)

// Ref is an image reference split into its parts. Registry and Repository are
// normalised: Docker Hub is "index.docker.io" and its official images carry
// "library/".
type Ref struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

// Parse reads a reference as written in a manifest. A reference may carry a
// tag, a digest or both.
func Parse(s string) (Ref, error) {
	if s == "" {
		return Ref{}, fmt.Errorf("empty image reference")
	}
	base, digest, hasDigest := strings.Cut(s, "@")
	var r Ref
	if hasDigest {
		h, err := v1.NewHash(digest)
		if err != nil {
			return Ref{}, fmt.Errorf("parsing image reference %q: %w", s, err)
		}
		r.Digest = h.String()
	}
	ref, err := name.ParseReference(base, name.WeakValidation)
	if err != nil {
		return Ref{}, fmt.Errorf("parsing image reference %q: %w", s, err)
	}
	r.Registry = ref.Context().RegistryStr()
	r.Repository = ref.Context().RepositoryStr()
	// ParseReference fills in "latest" when no tag was written; a reference
	// without one names no tag here.
	if t, ok := ref.(name.Tag); ok && hasExplicitTag(base) {
		r.Tag = t.TagStr()
	}
	return r, nil
}

// hasExplicitTag reports whether the last path element carries ":tag". A colon
// before the last slash belongs to a registry port.
func hasExplicitTag(s string) bool {
	last := s[strings.LastIndex(s, "/")+1:]
	return strings.Contains(last, ":")
}

// Name is "<registry>/<repository>", the name a VEX file is filed under.
func (r Ref) Name() string {
	return r.Registry + "/" + r.Repository
}

// String writes the reference back, with whichever of tag and digest it has.
func (r Ref) String() string {
	s := r.Name()
	if r.Tag != "" {
		s += ":" + r.Tag
	}
	if r.Digest != "" {
		s += "@" + r.Digest
	}
	return s
}

// WithDigestOnly drops the tag, so the reference names exactly one image.
func (r Ref) WithDigestOnly() Ref {
	r.Tag = ""
	return r
}

// PURL is the package URL of the image as Trivy builds it and as fleet-infra's
// security/vex/README.md tells annotators to match it: the last element of the
// repository as the name, the digest as the version and repository_url as the
// only qualifier.
func (r Ref) PURL() string {
	repo := r.Repository
	nm := repo[strings.LastIndex(repo, "/")+1:]
	return packageurl.NewPackageURL(
		packageurl.TypeOCI, "", nm, r.Digest,
		packageurl.Qualifiers{{Key: "repository_url", Value: r.Name()}}, "",
	).ToString()
}

// ReportTag reads the tag of a VulnerabilityReport artifact. Trivy Operator
// writes "httpd:2.4.69-alpine" when the image was referenced through a
// kustomize newTag of the form tag@digest, so the tag is what follows the last
// colon.
func ReportTag(tag string) string {
	return tag[strings.LastIndex(tag, ":")+1:]
}

// ShortName is how an image is usually written by people, and so in a pull
// request title: Docker Hub's registry and "library/" are left out.
func ShortName(imageName string) string {
	s := strings.TrimPrefix(imageName, "index.docker.io/")
	if s != imageName {
		s = strings.TrimPrefix(s, "library/")
	}
	return s
}
