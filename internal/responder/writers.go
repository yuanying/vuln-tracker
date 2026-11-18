package responder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Writable is the set of repositories vuln-responder can write, as fleet-infra's
// github-writer.json lists them (ADR 0016).
type Writable map[string]bool

// ParseWriterConfig reads github-writer.json. Only the owner and name of each
// entry of "repositories" are read; every other key is ignored. Empty input,
// which is how a missing file arrives, is an error: an empty list would make
// every source a gap.
func ParseWriterConfig(b []byte) (Writable, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("github-writer.json: missing or empty")
	}
	var f struct {
		Repositories *[]struct {
			Owner string `json:"owner"`
			Name  string `json:"name"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("github-writer.json: %w", err)
	}
	if f.Repositories == nil {
		return nil, errors.New("github-writer.json: no repositories")
	}
	w := Writable{}
	for i, r := range *f.Repositories {
		if r.Owner == "" || r.Name == "" {
			return nil, fmt.Errorf("github-writer.json: repositories[%d] needs an owner and a name", i)
		}
		w[strings.ToLower(r.Owner+"/"+r.Name)] = true
	}
	return w, nil
}

// Has says whether vuln-responder can write repo ("owner/name"), in any case.
func (w Writable) Has(repo string) bool {
	return w[strings.ToLower(repo)]
}
