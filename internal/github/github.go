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
	"strconv"
	"strings"
)

// maxFileSize bounds one file kept from a tarball. Manifests and VEX
// documents are far smaller; anything bigger is not one.
const maxFileSize = 4 << 20

// States of a pull request, as the API answers them (ADR 0015).
const (
	StateOpen   = "open"
	StateMerged = "merged"
	StateClosed = "closed"
)

// PullRequest is a pull request, as far as the tracker cares.
type PullRequest struct {
	URL string
	// Repository is "owner/name".
	Repository string
	Number     int
	// State is StateOpen, StateMerged or StateClosed (closed unmerged).
	State   string
	Title   string
	Body    string
	Author  string
	HeadRef string
	HeadSHA string
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
	// PullRequest reads one pull request, open or not.
	PullRequest(ctx context.Context, repo string, number int) (PullRequest, error)
	// PullRequestFiles lists the paths a pull request changes.
	PullRequestFiles(ctx context.Context, repo string, number int) ([]string, error)
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
	HTMLURL  string  `json:"html_url"`
	Number   int     `json:"number"`
	State    string  `json:"state"`
	MergedAt *string `json:"merged_at"`
	Title    string  `json:"title"`
	Body     *string `json:"body"`
	User     struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
}

func (p pullJSON) pullRequest(repo string) PullRequest {
	pr := PullRequest{
		URL: p.HTMLURL, Repository: repo, Number: p.Number, State: StateOpen,
		Title: p.Title, Author: p.User.Login, HeadRef: p.Head.Ref, HeadSHA: p.Head.SHA,
	}
	switch {
	case p.MergedAt != nil && *p.MergedAt != "":
		pr.State = StateMerged
	case p.State == "closed":
		pr.State = StateClosed
	}
	if p.Body != nil {
		pr.Body = *p.Body
	}
	return pr
}

func (c *Client) getJSON(ctx context.Context, p string, v any) error {
	resp, err := c.get(ctx, p, "application/vnd.github+json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(v); err != nil {
		return fmt.Errorf("reading %s: %w", p, err)
	}
	return nil
}

// OpenPullRequests implements Repositories. One page of 100 is read; a
// repository with more open pull requests than that has bigger problems.
func (c *Client) OpenPullRequests(ctx context.Context, repo string) ([]PullRequest, error) {
	var raw []pullJSON
	if err := c.getJSON(ctx, "/repos/"+repo+"/pulls?state=open&per_page=100", &raw); err != nil {
		return nil, err
	}
	prs := make([]PullRequest, 0, len(raw))
	for _, p := range raw {
		prs = append(prs, p.pullRequest(repo))
	}
	return prs, nil
}

// PullRequest implements Repositories.
func (c *Client) PullRequest(ctx context.Context, repo string, number int) (PullRequest, error) {
	var raw pullJSON
	if err := c.getJSON(ctx, "/repos/"+repo+"/pulls/"+strconv.Itoa(number), &raw); err != nil {
		return PullRequest{}, err
	}
	return raw.pullRequest(repo), nil
}

// PullRequestFiles implements Repositories. One page of 100 is read: enough
// to tell a pull request that changes only VEX documents from one that does
// more.
func (c *Client) PullRequestFiles(ctx context.Context, repo string, number int) ([]string, error) {
	var raw []struct {
		Filename string `json:"filename"`
	}
	if err := c.getJSON(ctx, "/repos/"+repo+"/pulls/"+strconv.Itoa(number)+"/files?per_page=100", &raw); err != nil {
		return nil, err
	}
	files := make([]string, 0, len(raw))
	for _, f := range raw {
		files = append(files, f.Filename)
	}
	return files, nil
}

// ParsePullRequestURL reads the repository and number from a pull request's
// URL on github.com.
func ParsePullRequestURL(u string) (string, int, bool) {
	rest, ok := strings.CutPrefix(u, "https://github.com/")
	if !ok {
		return "", 0, false
	}
	rest, _, _ = strings.Cut(rest, "#")
	parts := strings.Split(rest, "/")
	if len(parts) < 4 || parts[0] == "" || parts[1] == "" || parts[2] != "pull" {
		return "", 0, false
	}
	n, err := strconv.Atoi(parts[3])
	if err != nil || n <= 0 {
		return "", 0, false
	}
	return parts[0] + "/" + parts[1], n, true
}
