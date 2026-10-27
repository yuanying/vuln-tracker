package responder

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Message is one request to send.
type Message struct {
	// ContextID continues a context vuln-responder numbered; empty starts a
	// new one.
	ContextID string
	Text      string
	// Data becomes a data part when not nil.
	Data any
}

// Task is a task as the requester needs it.
type Task struct {
	ID        string
	ContextID string
	// State is the A2A state in lower case, e.g. "working", "completed".
	State string
	// Texts are the texts of the reply: the artifacts' parts first, then
	// the status message. Data parts are written as JSON.
	Texts []string
}

// A2A is the part of an A2A server the requester uses.
type A2A interface {
	Send(ctx context.Context, m Message) (Task, error)
	Get(ctx context.Context, id string) (Task, error)
}

// RPCError is an error the A2A server answered with.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("A2A error %d: %s", e.Code, e.Message)
}

// Client speaks A2A 1.0 JSON-RPC over HTTP: SendMessage and GetTask, which is
// all the requester needs (ADR 0009).
type Client struct {
	// URL is the agent's JSON-RPC endpoint.
	URL string
	// TokenFile holds a ServiceAccount token for the a2a audience. It is
	// read for every request: the kubelet replaces it before it expires.
	TokenFile string
	HTTP      *http.Client

	id atomic.Int64
}

type wirePart struct {
	Text      *string         `json:"text,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	MediaType string          `json:"mediaType,omitempty"`
}

type wireMessage struct {
	MessageID string     `json:"messageId,omitempty"`
	Role      string     `json:"role,omitempty"`
	ContextID string     `json:"contextId,omitempty"`
	Parts     []wirePart `json:"parts"`
}

type wireTask struct {
	ID        string `json:"id"`
	ContextID string `json:"contextId"`
	Status    struct {
		State   string       `json:"state"`
		Message *wireMessage `json:"message"`
	} `json:"status"`
	Artifacts []struct {
		Parts []wirePart `json:"parts"`
	} `json:"artifacts"`
}

func (w wireTask) task() Task {
	t := Task{ID: w.ID, ContextID: w.ContextID, State: normalizeState(w.Status.State)}
	add := func(parts []wirePart) {
		for _, p := range parts {
			switch {
			case p.Text != nil:
				t.Texts = append(t.Texts, *p.Text)
			case len(p.Data) > 0:
				t.Texts = append(t.Texts, string(p.Data))
			}
		}
	}
	for _, a := range w.Artifacts {
		add(a.Parts)
	}
	if w.Status.Message != nil {
		add(w.Status.Message.Parts)
	}
	return t
}

// normalizeState turns "TASK_STATE_INPUT_REQUIRED" into "input-required".
func normalizeState(s string) string {
	s = strings.TrimPrefix(s, "TASK_STATE_")
	if s == "" {
		return "unspecified"
	}
	return strings.ReplaceAll(strings.ToLower(s), "_", "-")
}

func messageID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Send sends a message and returns the task it started, without waiting for
// it.
func (c *Client) Send(ctx context.Context, m Message) (Task, error) {
	text := m.Text
	msg := wireMessage{
		MessageID: messageID(),
		Role:      "ROLE_USER",
		ContextID: m.ContextID,
		Parts:     []wirePart{{Text: &text, MediaType: "text/plain"}},
	}
	if m.Data != nil {
		data, err := json.Marshal(m.Data)
		if err != nil {
			return Task{}, fmt.Errorf("encoding the data part: %w", err)
		}
		msg.Parts = append(msg.Parts, wirePart{Data: data, MediaType: "application/json"})
	}
	params := map[string]any{"message": msg, "configuration": map[string]any{"returnImmediately": true}}
	var result struct {
		Task    *wireTask       `json:"task"`
		Message json.RawMessage `json:"message"`
	}
	if err := c.call(ctx, "SendMessage", params, &result); err != nil {
		return Task{}, err
	}
	if result.Task == nil {
		return Task{}, errors.New("SendMessage: the agent answered with a message, not a task")
	}
	return result.Task.task(), nil
}

// Get returns a task as it stands.
func (c *Client) Get(ctx context.Context, id string) (Task, error) {
	var result wireTask
	if err := c.call(ctx, "GetTask", map[string]any{"id": id}, &result); err != nil {
		return Task{}, err
	}
	return result.task(), nil
}

func (c *Client) call(ctx context.Context, method string, params, result any) error {
	raw, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return fmt.Errorf("%s: reading the token: %w", method, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("%s: the token file %s is empty", method, c.TokenFile)
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id.Add(1), "method": method, "params": params})
	if err != nil {
		return fmt.Errorf("%s: encoding the request: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: building the request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("A2A-Version", "1.0")
	req.Header.Set("Authorization", "Bearer "+token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("%s: reading the response: %w", method, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s: %s", method, resp.Status, strings.TrimSpace(string(raw[:min(len(raw), 256)])))
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *RPCError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%s: decoding the response: %w", method, err)
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return fmt.Errorf("%s: decoding the result: %w", method, err)
	}
	return nil
}
