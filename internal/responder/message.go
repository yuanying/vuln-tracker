// Package responder asks vuln-responder, an agent of fraction-agents, to
// triage the new fixable Critical findings nobody has annotated, and to bump
// the versions of those a new version fixes, one target at a time, over A2A
// 1.0 (ADR 0009, ADR 0011).
package responder

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/yuanying/vuln-tracker/internal/annotation"
)

// Kind names the shape of the data part. A new shape gets a new kind; keys
// added to it do not, as unknown keys are ignored.
const Kind = "vuln-triage/v1"

// What a finding is asked about (ADR 0011).
const (
	// TriggerTriage asks for the finding to be analyzed and handled.
	TriggerTriage = "triage"
	// TriggerBump asks for the version in fleet-infra to be raised to the
	// version the finding is gone from.
	TriggerBump = "bump"
)

// Target is what one request is about: a source repository of images built
// here, or an image from elsewhere.
type Target struct {
	// Type is "source" or "image".
	Type string
	// Repository is "<owner>/<repo>" for a source.
	Repository string
	// Image is "<registry>/<repository>" for an image.
	Image string
}

// Name is the repository or the image.
func (t Target) Name() string {
	if t.Type == "source" {
		return t.Repository
	}
	return t.Image
}

// Key identifies the target in the state.
func (t Target) Key() string {
	return t.Type + ":" + t.Name()
}

// Workload is where an image runs.
type Workload struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Container string `json:"container"`
}

// Finding is one finding as the data part carries it.
type Finding struct {
	VulnerabilityID  string `json:"vulnerabilityID"`
	Severity         string `json:"severity"`
	Package          string `json:"package"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	Stage            string `json:"stage"`
	VexState         string `json:"vexState"`
	Image            string `json:"image"`
	Tag              string `json:"tag"`
	Digest           string `json:"digest"`
	// Trigger is TriggerTriage or TriggerBump.
	Trigger string `json:"trigger"`
	// FixedInTag and FixedInDigest are the version the vulnerability is
	// gone from, for a bump.
	FixedInTag    string `json:"fixedInTag,omitempty"`
	FixedInDigest string `json:"fixedInDigest,omitempty"`
	// RenovatePRs are open Renovate pull requests that name the image.
	RenovatePRs []string   `json:"renovatePRs,omitempty"`
	Workloads   []Workload `json:"workloads"`
}

// Key is what is remembered as asked: tags and digests do not enter it, so a
// new version carrying the same vulnerability is not asked about again. A
// bump's key carries the stage, so a finding is asked about once more as its
// stage reaches a fixed version.
func (f Finding) Key() string {
	k := f.Image + "|" + f.VulnerabilityID + "|" + f.Package
	if f.Trigger == TriggerBump {
		k += "|" + f.Stage
	}
	return k
}

// Wanted is a target with the findings to ask about.
type Wanted struct {
	Target   Target
	Findings []Finding
}

// PayloadTarget is the target as the data part carries it: the field that
// does not apply is null.
type PayloadTarget struct {
	Type       string  `json:"type"`
	Repository *string `json:"repository"`
	Image      *string `json:"image"`
}

// Payload is the data part of a request.
type Payload struct {
	Kind      string        `json:"kind"`
	Mode      string        `json:"mode"`
	Target    PayloadTarget `json:"target"`
	Findings  []Finding     `json:"findings"`
	Dashboard string        `json:"dashboard"`
	// VexFile is the VEX document of the first image; each finding names
	// its own image.
	VexFile string `json:"vexFile"`
}

func sortFindings(fs []Finding) []Finding {
	out := append([]Finding(nil), fs...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Image != out[j].Image {
			return out[i].Image < out[j].Image
		}
		if out[i].VulnerabilityID != out[j].VulnerabilityID {
			return out[i].VulnerabilityID < out[j].VulnerabilityID
		}
		return out[i].Package < out[j].Package
	})
	return out
}

// Build writes the request for a target: the text part for people and the
// model, and the data part for code.
func Build(w Wanted, mode, dashboard string) (string, Payload) {
	findings := sortFindings(w.Findings)
	p := Payload{Kind: Kind, Mode: mode, Target: PayloadTarget{Type: w.Target.Type}, Findings: findings, Dashboard: dashboard}
	if w.Target.Type == "source" {
		p.Target.Repository = &w.Target.Repository
	} else {
		p.Target.Image = &w.Target.Image
	}
	if len(findings) > 0 {
		p.VexFile = annotation.PathFor(findings[0].Image)
	} else if w.Target.Type == "image" {
		p.VexFile = annotation.PathFor(w.Target.Image)
	}

	var triage, bump []Finding
	for _, f := range findings {
		if f.Trigger == TriggerBump {
			bump = append(bump, f)
		} else {
			triage = append(triage, f)
		}
	}

	var b strings.Builder
	if w.Target.Type == "source" {
		fmt.Fprintf(&b, "ソースのリポジトリ %s から作ったイメージの、Critical の脆弱性について頼みたい。", w.Target.Repository)
	} else {
		fmt.Fprintf(&b, "fleet-infra で使っている外のイメージ %s の、Critical の脆弱性について頼みたい。", w.Target.Image)
	}
	fmt.Fprintf(&b, "mode: %s\n", mode)
	if len(triage) > 0 {
		b.WriteString("\n修正版のある Critical の脆弱性が新しく見つかった。注釈（VEX）も対応もまだ無い。解析して対応を判断してほしい。\n")
		b.WriteString("発見:\n")
		for _, f := range triage {
			fmt.Fprintf(&b, "- %s（%s）%s %s → %s。%s:%s（%s）、段階 %s\n",
				f.VulnerabilityID, f.Severity, f.Package, f.InstalledVersion, f.FixedVersion, f.Image, f.Tag, f.Digest, f.Stage)
			writeDetails(&b, f)
		}
	}
	if len(bump) > 0 {
		b.WriteString("\n直った版が出た。fleet-infra（か k8s-manifests-fraction）に書かれたこのイメージの版を、その版に上げる PR を出してほしい。")
		b.WriteString("注釈が付いていれば、版上げで要らなくなる注釈の扱いも判断してほしい。\n")
		b.WriteString("発見:\n")
		for _, f := range bump {
			fmt.Fprintf(&b, "- %s（%s）%s %s。%s:%s（%s）、段階 %s、注釈 %s。直った版: %s:%s（%s）\n",
				f.VulnerabilityID, f.Severity, f.Package, f.InstalledVersion, f.Image, f.Tag, f.Digest, f.Stage, f.VexState,
				f.Image, f.FixedInTag, f.FixedInDigest)
			writeDetails(&b, f)
		}
		if slices.ContainsFunc(bump, func(f Finding) bool { return len(f.RenovatePRs) > 0 }) {
			b.WriteString("Renovate の PR が開いている。それで足りるなら新しい PR は出さず、その URL を返事に書く。\n")
		}
	}
	if p.VexFile != "" {
		fmt.Fprintf(&b, "\nVEX のファイル: fleet-infra の %s（イメージごとに security/vex/<image>.openvex.json）\n", p.VexFile)
	}
	if dashboard != "" {
		fmt.Fprintf(&b, "ダッシュボード: %s\n", dashboard)
	}
	b.WriteString("\n返事: 判断の要約を書く。PR を出したら、その URL を書く。判断できなければ PR を出さずに理由を書く。\n")
	b.WriteString("同じ中身を data の part（kind " + Kind + "）にも付けた。\n")
	return b.String(), p
}

// writeDetails writes where a finding's image runs and its Renovate pull
// requests.
func writeDetails(b *strings.Builder, f Finding) {
	for _, wl := range f.Workloads {
		fmt.Fprintf(b, "  - 動いている場所: %s/%s/%s（コンテナ %s）\n", wl.Namespace, wl.Kind, wl.Name, wl.Container)
	}
	for _, u := range f.RenovatePRs {
		fmt.Fprintf(b, "  - Renovate の PR: %s\n", u)
	}
}
