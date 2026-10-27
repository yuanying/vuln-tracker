package responder

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/yuanying/vuln-tracker/internal/state"
)

const (
	// BackoffBase is the wait after the first failure; it doubles with
	// every failure after it.
	BackoffBase = 10 * time.Minute
	// MaxAttempts is the failure in a row at which a set of findings is
	// given up on.
	MaxAttempts = 5
	// summaryRunes bounds the summary kept for the digest.
	summaryRunes = 200
)

// Requester asks vuln-responder about one target at a time (ADR 0009).
type Requester struct {
	Client A2A
	// Mode is the data part's mode: "vex-only" or "fix".
	Mode string
	// DashboardURL is handed along in every request.
	DashboardURL string
	// TaskTimeout is how long a task is waited for.
	TaskTimeout time.Duration
	Log         logr.Logger
}

// terminal says whether a state is final, and whether it counts as done:
// done findings are not asked about again, failed ones are retried.
func terminal(st string) (final, done bool) {
	switch st {
	case "completed", "canceled":
		return true, true
	case "failed", "rejected", "error", "timeout":
		return true, false
	}
	return false, false
}

// Running says whether a request still waits for its task.
func Running(r state.Request) bool {
	if r.TaskID == "" || r.State == "" {
		return false
	}
	final, _ := terminal(r.State)
	return !final
}

// Step does one thing: looks at the running request if there is one, or
// else sends the first request that is due. It updates records in place and
// reports whether it changed them.
func (r *Requester) Step(ctx context.Context, now time.Time, wanted []Wanted, records map[string]state.Request) bool {
	keys := make([]string, 0, len(records))
	for k := range records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if Running(records[k]) {
			return r.poll(ctx, now, k, records)
		}
	}

	wanted = slices.Clone(wanted)
	sort.Slice(wanted, func(i, j int) bool { return wanted[i].Target.Key() < wanted[j].Target.Key() })
	for _, w := range wanted {
		k := w.Target.Key()
		rec := records[k]
		if rec.NextAttempt > now.Unix() || !hasNew(w.Findings, rec.Asked) {
			continue
		}
		r.send(ctx, now, w, records)
		return true
	}
	return false
}

func hasNew(fs []Finding, asked []string) bool {
	for _, f := range fs {
		if !slices.Contains(asked, f.Key()) {
			return true
		}
	}
	return false
}

func (r *Requester) send(ctx context.Context, now time.Time, w Wanted, records map[string]state.Request) {
	k := w.Target.Key()
	rec := records[k]
	rec.TargetType, rec.Target = w.Target.Type, w.Target.Name()
	rec.Sending = nil
	for _, f := range w.Findings {
		if !slices.Contains(rec.Sending, f.Key()) {
			rec.Sending = append(rec.Sending, f.Key())
		}
	}
	sort.Strings(rec.Sending)
	rec.PR, rec.Summary, rec.TaskID = "", "", ""
	rec.SentAt, rec.UpdatedAt = now.Unix(), now.Unix()

	text, data := Build(w, r.Mode, r.DashboardURL)
	task, err := r.Client.Send(ctx, Message{ContextID: rec.ContextID, Text: text, Data: data})
	var rpcErr *RPCError
	if err != nil && rec.ContextID != "" && errors.As(err, &rpcErr) {
		// vuln-responder numbers contexts and forgets unused ones; start
		// a new one.
		r.Log.Info("vuln-responder refused the target's context; starting a new one", "target", k, "contextId", rec.ContextID, "error", err.Error())
		task, err = r.Client.Send(ctx, Message{Text: text, Data: data})
	}
	if err != nil {
		r.Log.Error(err, "asking vuln-responder", "target", k)
		records[k] = fail(rec, now, "error")
		return
	}
	r.Log.Info("asked vuln-responder", "target", k, "task", task.ID, "contextId", task.ContextID, "findings", len(rec.Sending))
	rec.TaskID, rec.ContextID, rec.State = task.ID, task.ContextID, task.State
	records[k] = r.settle(rec, now, task)
}

func (r *Requester) poll(ctx context.Context, now time.Time, k string, records map[string]state.Request) bool {
	rec := records[k]
	if r.TaskTimeout > 0 && now.Sub(time.Unix(rec.SentAt, 0)) > r.TaskTimeout {
		r.Log.Info("gave up waiting for vuln-responder", "target", k, "task", rec.TaskID)
		records[k] = fail(rec, now, "timeout")
		return true
	}
	task, err := r.Client.Get(ctx, rec.TaskID)
	if err != nil {
		var rpcErr *RPCError
		if !errors.As(err, &rpcErr) {
			// The network; look again next time.
			r.Log.Error(err, "looking at a vuln-responder task", "target", k, "task", rec.TaskID)
			return false
		}
		r.Log.Error(err, "vuln-responder no longer knows the task", "target", k, "task", rec.TaskID)
		records[k] = fail(rec, now, "error")
		return true
	}
	if task.State == rec.State {
		return false
	}
	rec.State, rec.UpdatedAt = task.State, now.Unix()
	records[k] = r.settle(rec, now, task)
	return true
}

// settle records a task that has ended.
func (r *Requester) settle(rec state.Request, now time.Time, task Task) state.Request {
	final, done := terminal(task.State)
	switch {
	case !final:
		return rec
	case done:
		rec.Asked = union(rec.Asked, rec.Sending)
		rec.Sending, rec.Attempts, rec.NextAttempt = nil, 0, 0
		rec.PR, rec.Summary = PullRequestURL(task.Texts), Summary(task.Texts)
		rec.UpdatedAt = now.Unix()
		r.Log.Info("vuln-responder finished", "target", rec.TargetType+":"+rec.Target, "state", task.State, "pr", rec.PR)
		return rec
	default:
		r.Log.Info("vuln-responder did not finish", "target", rec.TargetType+":"+rec.Target, "state", task.State, "reply", Summary(task.Texts))
		return fail(rec, now, task.State)
	}
}

// fail records a failure and when to try again, giving the findings up after
// MaxAttempts.
func fail(rec state.Request, now time.Time, st string) state.Request {
	rec.State, rec.UpdatedAt = st, now.Unix()
	rec.Attempts++
	if rec.Attempts >= MaxAttempts {
		rec.Asked = union(rec.Asked, rec.Sending)
		rec.Sending, rec.Attempts, rec.NextAttempt = nil, 0, 0
		return rec
	}
	rec.NextAttempt = now.Add(BackoffBase << (rec.Attempts - 1)).Unix()
	return rec
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

var pullRequestRE = regexp.MustCompile(`https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[0-9]+`)

// PullRequestURL is the first GitHub pull request named in the reply.
func PullRequestURL(texts []string) string {
	for _, t := range texts {
		if u := pullRequestRE.FindString(t); u != "" {
			return u
		}
	}
	return ""
}

// Summary is the first line of the reply that is not blank.
func Summary(texts []string) string {
	for _, t := range texts {
		for _, line := range strings.Split(t, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if r := []rune(line); len(r) > summaryRunes {
				line = string(r[:summaryRunes]) + "…"
			}
			return line
		}
	}
	return ""
}
