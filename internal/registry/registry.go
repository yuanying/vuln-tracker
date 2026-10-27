// Package registry reads container registries: tag lists, the digest a tag
// points at, and an image's labels (ADR 0002). It only reads. Credentials come
// from the docker config file named by DOCKER_CONFIG, and a registry with none
// is read anonymously (ADR 0007).
package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// ErrNotFound is returned when the tag or repository does not exist.
var ErrNotFound = errors.New("not found")

// Registry is what the tracker reads from registries.
type Registry interface {
	// Tags lists a repository's tags. repo is "<registry>/<repository>".
	Tags(ctx context.Context, repo string) ([]string, error)
	// Digest returns the digest a reference points at, without counting as a
	// pull where the registry counts pulls.
	Digest(ctx context.Context, ref string) (string, error)
	// Labels returns the labels in an image's config. For an index, the
	// linux/amd64 image's.
	Labels(ctx context.Context, ref string) (map[string]string, error)
}

// Remote reads registries over the network.
type Remote struct {
	// Insecure allows plain HTTP. Only tests set it.
	Insecure bool
}

var _ Registry = (*Remote)(nil)

func (r *Remote) nameOpts() []name.Option {
	opts := []name.Option{name.WeakValidation}
	if r.Insecure {
		opts = append(opts, name.Insecure)
	}
	return opts
}

func (r *Remote) remoteOpts(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}),
	}
}

func classify(err error) error {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return err
	}
	notFound := terr.StatusCode == http.StatusNotFound
	for _, d := range terr.Errors {
		if d.Code == transport.ManifestUnknownErrorCode || d.Code == transport.NameUnknownErrorCode {
			notFound = true
		}
	}
	if notFound {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

// Tags implements Registry.
func (r *Remote) Tags(ctx context.Context, repo string) ([]string, error) {
	rp, err := name.NewRepository(repo, r.nameOpts()...)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", repo, err)
	}
	tags, err := remote.List(rp, r.remoteOpts(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("listing the tags of %s: %w", repo, classify(err))
	}
	return tags, nil
}

// Digest implements Registry. It sends a HEAD request, which Docker Hub does
// not count against its pull limit.
func (r *Remote) Digest(ctx context.Context, ref string) (string, error) {
	rf, err := name.ParseReference(ref, r.nameOpts()...)
	if err != nil {
		return "", fmt.Errorf("parsing %q: %w", ref, err)
	}
	desc, err := remote.Head(rf, r.remoteOpts(ctx)...)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", ref, classify(err))
	}
	return desc.Digest.String(), nil
}

// Labels implements Registry.
func (r *Remote) Labels(ctx context.Context, ref string) (map[string]string, error) {
	rf, err := name.ParseReference(ref, r.nameOpts()...)
	if err != nil {
		return nil, fmt.Errorf("parsing %q: %w", ref, err)
	}
	img, err := remote.Image(rf, r.remoteOpts(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ref, classify(err))
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("reading the config of %s: %w", ref, classify(err))
	}
	return cf.Config.Labels, nil
}
