// Package sources reads fleet-infra's security/image-sources.yaml, the table
// that fills in what an image's labels do not say (ADR 0002): the source of an
// image without org.opencontainers.image.source, and the tag pattern of a
// series the default rule cannot read.
//
// The file is optional. Its shape:
//
//	images:
//	- image: index.docker.io/longhornio/longhorn-engine   # <registry>/<repository>
//	  source: https://github.com/longhorn/longhorn-engine # optional
//	  tagPattern: '^v(\d+\.\d+\.\d+)$'                    # optional; group 1 is compared
package sources

import (
	"fmt"
	"regexp"

	"sigs.k8s.io/yaml"
)

// Path is where the table lives in fleet-infra.
const Path = "security/image-sources.yaml"

// Entry is one image's row.
type Entry struct {
	Source     string
	TagPattern *regexp.Regexp
}

// Table is the parsed file, keyed by image name.
type Table map[string]Entry

type file struct {
	Images []struct {
		Image      string `json:"image"`
		Source     string `json:"source,omitempty"`
		TagPattern string `json:"tagPattern,omitempty"`
	} `json:"images"`
}

// Parse reads the file. Empty input, which is how a missing file arrives, is
// an empty table.
func Parse(b []byte) (Table, error) {
	tbl := Table{}
	if len(b) == 0 {
		return tbl, nil
	}
	var f file
	if err := yaml.UnmarshalStrict(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", Path, err)
	}
	for i, img := range f.Images {
		if img.Image == "" {
			return nil, fmt.Errorf("%s: images[%d] has no image", Path, i)
		}
		if _, dup := tbl[img.Image]; dup {
			return nil, fmt.Errorf("%s: %s is listed twice", Path, img.Image)
		}
		e := Entry{Source: img.Source}
		if img.TagPattern != "" {
			re, err := regexp.Compile(img.TagPattern)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: tagPattern: %w", Path, img.Image, err)
			}
			e.TagPattern = re
		}
		tbl[img.Image] = e
	}
	return tbl, nil
}

// Lookup returns an image's row.
func (t Table) Lookup(image string) (Entry, bool) {
	e, ok := t[image]
	return e, ok
}
