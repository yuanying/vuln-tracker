package registry

import (
	"context"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrregistry "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func setup(t *testing.T) (string, *Remote) {
	t.Helper()
	srv := httptest.NewServer(ggcrregistry.New())
	t.Cleanup(srv.Close)
	host := strings.TrimPrefix(srv.URL, "http://")

	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg := cf.Config
	cfg.Labels = map[string]string{
		"org.opencontainers.image.source":   "https://github.com/yuanying/hshelf",
		"org.opencontainers.image.revision": "0123456789abcdef",
	}
	img, err = mutate.Config(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"1.0.0", "1.1.0", "main"} {
		ref, err := name.NewTag(host+"/yuanying/hshelf:"+tag, name.Insecure)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.Write(ref, img); err != nil {
			t.Fatal(err)
		}
	}
	return host, &Remote{Insecure: true}
}

func TestTags(t *testing.T) {
	host, r := setup(t)
	tags, err := r.Tags(context.Background(), host+"/yuanying/hshelf")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(tags)
	if !slices.Equal(tags, []string{"1.0.0", "1.1.0", "main"}) {
		t.Errorf("Tags = %v", tags)
	}
}

func TestDigestAndLabels(t *testing.T) {
	host, r := setup(t)
	ctx := context.Background()
	d, err := r.Digest(ctx, host+"/yuanying/hshelf:main")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d, "sha256:") {
		t.Errorf("Digest = %q", d)
	}
	labels, err := r.Labels(ctx, host+"/yuanying/hshelf@"+d)
	if err != nil {
		t.Fatal(err)
	}
	if labels["org.opencontainers.image.revision"] != "0123456789abcdef" {
		t.Errorf("Labels = %v", labels)
	}
}

func TestNotFound(t *testing.T) {
	host, r := setup(t)
	_, err := r.Digest(context.Background(), host+"/yuanying/hshelf:nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Digest of a missing tag: %v, want ErrNotFound", err)
	}
	_, err = r.Tags(context.Background(), host+"/yuanying/nothing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Tags of a missing repository: %v, want ErrNotFound", err)
	}
}
