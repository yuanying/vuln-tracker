// Package state is what the tracker has to remember across restarts (ADR
// 0006): when each vulnerability was first seen in each image, and what the
// last weekly digest saw, so the next one can say what changed.
package state

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// forgetAfter is how long a vulnerability has to be gone from production
// before its first-seen time is dropped (ADR 0005). Shorter gaps — a report
// being retaken, a version rolled back for a day — do not make it new again.
const forgetAfter = 30 * 24 * time.Hour

// Seen is when an image × vulnerability pair was first and last seen, in unix
// seconds.
type Seen struct {
	First int64 `json:"f"`
	Last  int64 `json:"l"`
}

// Entry is one finding as the last digest saw it.
type Entry struct {
	Stage    string `json:"s"`
	VexState string `json:"v"`
}

// Digest is what the last weekly digest saw.
type Digest struct {
	// SentAt is when it was sent, in unix seconds; 0 if never.
	SentAt int64 `json:"sentAt"`
	// Findings is keyed by finding key.
	Findings map[string]Entry `json:"findings"`
}

// State is everything kept in the ConfigMap.
type State struct {
	// Initialized is false until the first observation. That first one is
	// the tracker being installed, and what it sees is not new.
	Initialized bool            `json:"initialized"`
	Seen        map[string]Seen `json:"seen"`
	Digest      Digest          `json:"digest"`
}

// New returns an empty state.
func New() *State {
	return &State{Seen: map[string]Seen{}, Digest: Digest{Findings: map[string]Entry{}}}
}

// Observe records the image × vulnerability keys present in production now,
// and forgets keys that have been gone for too long.
func (s *State) Observe(now time.Time, keys []string) {
	ts := now.Unix()
	first := ts
	if !s.Initialized {
		first = 0
		s.Initialized = true
	}
	for _, k := range keys {
		seen, ok := s.Seen[k]
		if !ok {
			seen.First = first
		}
		seen.Last = ts
		s.Seen[k] = seen
	}
	cutoff := now.Add(-forgetAfter).Unix()
	for k, seen := range s.Seen {
		if seen.Last < cutoff {
			delete(s.Seen, k)
		}
	}
}

// FirstSeen returns when a key was first seen, in unix seconds, or -1 if it is
// not known.
func (s *State) FirstSeen(key string) int64 {
	seen, ok := s.Seen[key]
	if !ok {
		return -1
	}
	return seen.First
}

// Encode writes the state as gzipped JSON.
func Encode(s *State) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(s); err != nil {
		return nil, fmt.Errorf("encoding state: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("compressing state: %w", err)
	}
	return buf.Bytes(), nil
}

// Decode reads what Encode wrote.
func Decode(b []byte) (*State, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("decompressing state: %w", err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("decompressing state: %w", err)
	}
	s := New()
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("decoding state: %w", err)
	}
	if s.Seen == nil {
		s.Seen = map[string]Seen{}
	}
	if s.Digest.Findings == nil {
		s.Digest.Findings = map[string]Entry{}
	}
	return s, nil
}
