// Package digest builds the weekly digest and sends it to Slack (ADR 0006):
// what appeared since the last digest, what advanced, what was fixed in
// production, and annotations past their review-by date.
package digest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yuanying/vuln-tracker/internal/annotation"
	"github.com/yuanying/vuln-tracker/internal/stage"
	"github.com/yuanying/vuln-tracker/internal/state"
)

// maxText keeps a message well inside what an Incoming Webhook accepts.
const maxText = 35000

// Item is one finding as the digest sees it.
type Item struct {
	// Key is the finding's key: "<image>@<digest>|<vulnerability>|<package>".
	Key             string
	Image           string
	Tag             string
	VulnerabilityID string
	Package         string
	Severity        string
	Stage           string
	// PrevStage is the stage in the last digest, for advanced findings.
	PrevStage  string
	Fixable    bool
	VexState   string
	ReviewBy   string
	Reason     string
	VexExpired bool
	FirstSeen  int64
}

// Report is one digest.
type Report struct {
	New      []Item
	Advanced []Item
	Expired  []Item
	// Gone counts, by image, the findings in the last digest that are no
	// longer in production.
	Gone map[string]int
	// Counts is the number of findings in each stage.
	Counts map[string]int

	items []Item
}

// Build compares the findings now with what the last digest saw.
func Build(items []Item, prev state.Digest) Report {
	r := Report{Gone: map[string]int{}, Counts: map[string]int{}, items: items}
	current := map[string]bool{}
	for _, it := range items {
		current[it.Key] = true
		r.Counts[it.Stage]++
		if it.FirstSeen > prev.SentAt {
			r.New = append(r.New, it)
		}
		if p, ok := prev.Findings[it.Key]; ok && stage.Advanced(stage.Stage(p.Stage), stage.Stage(it.Stage)) {
			it.PrevStage = p.Stage
			r.Advanced = append(r.Advanced, it)
		}
		if it.VexExpired {
			r.Expired = append(r.Expired, it)
		}
	}
	for k := range prev.Findings {
		if !current[k] {
			img, _, _ := strings.Cut(k, "@")
			r.Gone[img]++
		}
	}
	for _, list := range [][]Item{r.New, r.Advanced, r.Expired} {
		sort.Slice(list, func(i, j int) bool {
			if list[i].Image != list[j].Image {
				return list[i].Image < list[j].Image
			}
			return list[i].VulnerabilityID < list[j].VulnerabilityID
		})
	}
	return r
}

// Snapshot is what to remember for the next digest.
func (r Report) Snapshot() map[string]state.Entry {
	out := make(map[string]state.Entry, len(r.items))
	for _, it := range r.items {
		out[it.Key] = state.Entry{Stage: it.Stage, VexState: it.VexState}
	}
	return out
}

// Options shape the rendered message.
type Options struct {
	// DashboardURL is linked from every section.
	DashboardURL string
	// VEXBaseURL is prepended to the path of an image's VEX document in
	// fleet-infra (ADR 0004), e.g.
	// "https://github.com/yuanying/fleet-infra/blob/main/".
	VEXBaseURL string
	// MaxItems is how many findings a section lists before summarising.
	MaxItems int
}

// Render writes the digest as Slack mrkdwn.
func Render(r Report, o Options) string {
	if o.MaxItems <= 0 {
		o.MaxItems = 15
	}
	var b strings.Builder
	b.WriteString("*脆弱性の週次ダイジェスト*")
	if o.DashboardURL != "" {
		fmt.Fprintf(&b, "　<%s|ダッシュボード>", o.DashboardURL)
	}
	b.WriteString("\n\n*段階ごとの件数*\n")
	for _, s := range stage.All() {
		if n := r.Counts[string(s)]; n > 0 {
			fmt.Fprintf(&b, "• `%s`: %d\n", s, n)
		}
	}

	section := func(title string, items []Item, line func(Item) string) {
		fmt.Fprintf(&b, "\n*%s*（%d 件）\n", title, len(items))
		if len(items) == 0 {
			b.WriteString("なし\n")
			return
		}
		for i, it := range items {
			if i == o.MaxItems {
				fmt.Fprintf(&b, "…and %d more", len(items)-o.MaxItems)
				if o.DashboardURL != "" {
					fmt.Fprintf(&b, "（<%s|ダッシュボード>）", o.DashboardURL)
				}
				b.WriteString("\n")
				break
			}
			b.WriteString("• " + line(it) + "\n")
		}
	}
	head := func(it Item) string {
		fixable := ""
		if !it.Fixable {
			fixable = "・修正版なし"
		}
		return fmt.Sprintf("`%s:%s` %s（%s %s%s）", it.Image, it.Tag, it.VulnerabilityID, it.Severity, it.Package, fixable)
	}
	section("新しく出たもの", r.New, func(it Item) string {
		s := head(it) + " `" + it.Stage + "`"
		if it.VexState != "none" && it.VexState != "" {
			s += " 注釈 " + it.VexState
		}
		return s
	})
	section("段階が進んだもの", r.Advanced, func(it Item) string {
		return fmt.Sprintf("%s `%s` → `%s`", head(it), it.PrevStage, it.Stage)
	})

	fmt.Fprintf(&b, "\n*本番で直ったもの*\n")
	if len(r.Gone) == 0 {
		b.WriteString("なし\n")
	} else {
		imgs := make([]string, 0, len(r.Gone))
		for img := range r.Gone {
			imgs = append(imgs, img)
		}
		sort.Strings(imgs)
		for _, img := range imgs {
			fmt.Fprintf(&b, "• `%s`: %d 件\n", img, r.Gone[img])
		}
	}

	section("注釈の期限切れ", r.Expired, func(it Item) string {
		s := fmt.Sprintf("%s 注釈 %s・期限 %s", head(it), it.VexState, it.ReviewBy)
		if o.VEXBaseURL != "" {
			s += fmt.Sprintf("（<%s%s|VEX>）", o.VEXBaseURL, annotation.PathFor(it.Image))
		}
		if it.Reason != "" {
			s += "\n　" + oneLine(it.Reason)
		}
		return s
	})

	out := b.String()
	if len(out) > maxText {
		out = out[:maxText] + "\n…（長すぎるので省略）"
	}
	return out
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

// Schedule is a weekly time in a time zone.
type Schedule struct {
	Weekday  time.Weekday
	Hour     int
	Minute   int
	Location *time.Location
}

var weekdays = map[string]time.Weekday{
	"Sun": time.Sunday, "Mon": time.Monday, "Tue": time.Tuesday, "Wed": time.Wednesday,
	"Thu": time.Thursday, "Fri": time.Friday, "Sat": time.Saturday,
}

// ParseSchedule reads "Mon 09:00".
func ParseSchedule(s string, loc *time.Location) (Schedule, error) {
	day, hm, ok := strings.Cut(s, " ")
	wd, known := weekdays[day]
	if !ok || !known {
		return Schedule{}, fmt.Errorf("schedule %q: want a weekday (Mon…Sun), a space and HH:MM", s)
	}
	t, err := time.Parse("15:04", hm)
	if err != nil {
		return Schedule{}, fmt.Errorf("schedule %q: %w", s, err)
	}
	return Schedule{Weekday: wd, Hour: t.Hour(), Minute: t.Minute(), Location: loc}, nil
}

// Next returns the first scheduled time strictly after t.
func (s Schedule) Next(t time.Time) time.Time {
	loc := s.Location
	if loc == nil {
		loc = time.UTC
	}
	lt := t.In(loc)
	cand := time.Date(lt.Year(), lt.Month(), lt.Day(), s.Hour, s.Minute, 0, 0, loc)
	cand = cand.AddDate(0, 0, (int(s.Weekday)-int(cand.Weekday())+7)%7)
	if !cand.After(t) {
		cand = cand.AddDate(0, 0, 7)
	}
	return cand
}

// Slack posts to an Incoming Webhook.
type Slack struct {
	WebhookURL string
	HTTP       *http.Client
}

// Send posts one message.
func (s *Slack) Send(ctx context.Context, text string) error {
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building the Slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	hc := s.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// The URL is the credential; do not let it reach the logs.
		return fmt.Errorf("posting to Slack: %w", redact(err, s.WebhookURL))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("posting to Slack: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

func redact(err error, secret string) error {
	if secret == "" {
		return err
	}
	return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), secret, "<webhook>"))
}
