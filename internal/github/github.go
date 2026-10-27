// Package github reads the manifest repositories through the GitHub REST API
// (ADR 0007). Nothing is cloned: the tracker asks for the default branch's
// head and, only when it moved, downloads the tarball of that commit and
// keeps the files it reads — manifests and VEX documents.
package github

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

// maxFileSize bounds one file kept from a tarball. Manifests and VEX
// documents are far smaller; anything bigger is not one.
const maxFileSize = 4 << 20

// PullRequest is an open pull request, as far as the tracker cares.
type PullRequest struct {
	URL    string
	Title  string
	Body   string
	Author string
}

// Repositories is what the tracker reads from GitHub.
type Repositories interface {
	// Head returns the commit a branch points at.
	Head(ctx context.Context, repo, branch string) (string, error)
	// Files returns the manifests and VEX documents at a commit, keyed by
	// their path in the repository.
	Files(ctx context.Context, repo, sha string) (map[string][]byte, error)
	// OpenPullRequests lists a repository's open pull requests.
	OpenPullRequests(ctx context.Context, repo string) ([]PullRequest, error)
}

// Client talks to the GitHub REST API. Token, if set, needs only read access
// to the contents and pull requests of the repositories it reads.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

var _ Repositories = (*Client)(nil)

func (c *Client) get(ctx context.Context, p, accept string) (*http.Response, error) {
	base := c.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+p, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", p, err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s: %s", p, resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

// Head implements Repositories.
func (c *Client) Head(ctx context.Context, repo, branch string) (string, error) {
	resp, err := c.get(ctx, "/repos/"+repo+"/commits/"+branch, "application/vnd.github.sha")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", fmt.Errorf("reading the head of %s: %w", repo, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// keep says whether a file of the tarball is one the tracker reads.
func keep(p string) bool {
	switch path.Ext(p) {
	case ".yaml", ".yml":
		return true
	}
	return strings.HasSuffix(p, ".openvex.json")
}

// Files implements Repositories.
func (c *Client) Files(ctx context.Context, repo, sha string) (map[string][]byte, error) {
	resp, err := c.get(ctx, "/repos/"+repo+"/tarball/"+sha, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the tarball of %s: %w", repo, err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the tarball of %s: %w", repo, err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size > maxFileSize {
			continue
		}
		// Drop the top directory GitHub names after the commit.
		_, rel, ok := strings.Cut(hdr.Name, "/")
		if !ok || !keep(rel) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFileSize))
		if err != nil {
			return nil, fmt.Errorf("reading %s from the tarball of %s: %w", rel, repo, err)
		}
		files[rel] = b
	}
	return files, nil
}

type pullJSON struct {
	HTMLURL string  `json:"html_url"`
	Title   string  `json:"title"`
	Body    *string `json:"body"`
	User    struct {
		Login string `json:"login"`
	} `json:"user"`
}

// OpenPullRequests implements Repositories. One page of 100 is read; a
// repository with more open pull requests than that has bigger problems.
func (c *Client) OpenPullRequests(ctx context.Context, repo string) ([]PullRequest, error) {
	resp, err := c.get(ctx, "/repos/"+repo+"/pulls?state=open&per_page=100", "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var raw []pullJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("reading the pull requests of %s: %w", repo, err)
	}
	prs := make([]PullRequest, 0, len(raw))
	for _, p := range raw {
		pr := PullRequest{URL: p.HTMLURL, Title: p.Title, Author: p.User.Login}
		if p.Body != nil {
			pr.Body = *p.Body
		}
		prs = append(prs, pr)
	}
	return prs, nil
}
