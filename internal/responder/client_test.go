package responder

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// rpcServer is a fake A2A 1.0 host speaking JSON-RPC over HTTP. It answers
// each method with what reply returns, and keeps what it was sent.
type rpcServer struct {
	mu       sync.Mutex
	requests []map[string]any
	headers  []http.Header
	reply    func(method string, params map[string]any) (status int, body string)
}

func (s *rpcServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.headers = append(s.headers, r.Header.Clone())
	s.mu.Unlock()
	params, _ := req["params"].(map[string]any)
	status, body := s.reply(req["method"].(string), params)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func tokenFile(t *testing.T, token string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const taskJSON = `{"id":"task-1","contextId":"ctx-1","status":{"state":"TASK_STATE_SUBMITTED"}}`

func TestClientSend(t *testing.T) {
	srv := &rpcServer{reply: func(string, map[string]any) (int, string) {
		return 200, `{"jsonrpc":"2.0","id":1,"result":{"task":` + taskJSON + `}}`
	}}
	hs := httptest.NewServer(srv)
	defer hs.Close()
	tf := tokenFile(t, "tok-1")
	c := &Client{URL: hs.URL, TokenFile: tf}

	task, err := c.Send(context.Background(), Message{Text: "hello", Data: map[string]any{"kind": "vuln-triage/v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if task.ID != "task-1" || task.ContextID != "ctx-1" || task.State != "submitted" {
		t.Errorf("task = %+v", task)
	}

	h := srv.headers[0]
	if h.Get("Authorization") != "Bearer tok-1" || h.Get("A2A-Version") != "1.0" || h.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %v", h)
	}
	req := srv.requests[0]
	if req["jsonrpc"] != "2.0" || req["method"] != "SendMessage" {
		t.Errorf("request = %v", req)
	}
	params := req["params"].(map[string]any)
	if cfg := params["configuration"].(map[string]any); cfg["returnImmediately"] != true {
		t.Errorf("configuration = %v", cfg)
	}
	msg := params["message"].(map[string]any)
	if msg["role"] != "ROLE_USER" || msg["messageId"] == "" || msg["messageId"] == nil {
		t.Errorf("message = %v", msg)
	}
	if _, ok := msg["contextId"]; ok {
		t.Error("a message without a context must leave contextId out, so the host numbers one")
	}
	parts := msg["parts"].([]any)
	if len(parts) != 2 {
		t.Fatalf("parts = %v", parts)
	}
	text, data := parts[0].(map[string]any), parts[1].(map[string]any)
	if text["text"] != "hello" || text["mediaType"] != "text/plain" {
		t.Errorf("text part = %v", text)
	}
	if data["mediaType"] != "application/json" || data["data"].(map[string]any)["kind"] != "vuln-triage/v1" {
		t.Errorf("data part = %v", data)
	}

	// The projected token is replaced by the kubelet; it is read again for
	// every request.
	if err := os.WriteFile(tf, []byte("tok-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(context.Background(), Message{ContextID: "ctx-1", Text: "again"}); err != nil {
		t.Fatal(err)
	}
	if got := srv.headers[1].Get("Authorization"); got != "Bearer tok-2" {
		t.Errorf("second request carried %q", got)
	}
	msg = srv.requests[1]["params"].(map[string]any)["message"].(map[string]any)
	if msg["contextId"] != "ctx-1" {
		t.Errorf("contextId = %v", msg["contextId"])
	}
	if msg["messageId"] == srv.requests[0]["params"].(map[string]any)["message"].(map[string]any)["messageId"] {
		t.Error("every message needs its own messageId")
	}
	if n := len(msg["parts"].([]any)); n != 1 {
		t.Errorf("a message without data has %d parts", n)
	}
}

func TestClientGet(t *testing.T) {
	srv := &rpcServer{reply: func(method string, params map[string]any) (int, string) {
		if method != "GetTask" || params["id"] != "task-1" {
			return 200, `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Task not found"}}`
		}
		return 200, `{"jsonrpc":"2.0","id":1,"result":{
			"id":"task-1","contextId":"ctx-1",
			"status":{"state":"TASK_STATE_COMPLETED","message":{"role":"ROLE_AGENT","parts":[{"text":"done"}]}},
			"artifacts":[{"name":"response","parts":[
				{"text":"VEX の PR を出した。\nhttps://github.com/yuanying/fleet-infra/pull/240"},
				{"data":{"summary":"s","sources":[{"url":"https://github.com/yuanying/fleet-infra/pull/240"}]},"mediaType":"application/json"}
			]}]}}`
	}}
	hs := httptest.NewServer(srv)
	defer hs.Close()
	c := &Client{URL: hs.URL, TokenFile: tokenFile(t, "tok")}

	task, err := c.Get(context.Background(), "task-1")
	if err != nil {
		t.Fatal(err)
	}
	if task.State != "completed" || task.ContextID != "ctx-1" {
		t.Errorf("task = %+v", task)
	}
	joined := strings.Join(task.Texts, "\n")
	for _, want := range []string{"VEX の PR を出した。", "done", `"summary":"s"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("texts %q lack %q", task.Texts, want)
		}
	}
	// The artifact's text comes first: it is the reply.
	if !strings.HasPrefix(task.Texts[0], "VEX の PR") {
		t.Errorf("first text = %q", task.Texts[0])
	}

	_, err = c.Get(context.Background(), "task-x")
	var rpcErr *RPCError
	if !errors.As(err, &rpcErr) || rpcErr.Code != -32001 {
		t.Errorf("err = %v, want an RPCError", err)
	}
}

func TestClientStates(t *testing.T) {
	for in, want := range map[string]string{
		"TASK_STATE_SUBMITTED":      "submitted",
		"TASK_STATE_WORKING":        "working",
		"TASK_STATE_INPUT_REQUIRED": "input-required",
		"TASK_STATE_COMPLETED":      "completed",
		"TASK_STATE_FAILED":         "failed",
		"TASK_STATE_CANCELED":       "canceled",
		"TASK_STATE_REJECTED":       "rejected",
		"TASK_STATE_AUTH_REQUIRED":  "auth-required",
		"":                          "unspecified",
	} {
		if got := normalizeState(in); got != want {
			t.Errorf("normalizeState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientErrors(t *testing.T) {
	status, body := 401, `{"error":"no token"}`
	srv := &rpcServer{reply: func(string, map[string]any) (int, string) { return status, body }}
	hs := httptest.NewServer(srv)
	defer hs.Close()
	c := &Client{URL: hs.URL, TokenFile: tokenFile(t, "secret-token")}

	_, err := c.Send(context.Background(), Message{Text: "x"})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("err = %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "secret-token") {
		t.Error("the token reached the error")
	}

	// A message instead of a task is not what a triage request expects.
	status, body = 200, `{"jsonrpc":"2.0","id":1,"result":{"message":{"role":"ROLE_AGENT","parts":[{"text":"hi"}]}}}`
	if _, err := c.Send(context.Background(), Message{Text: "x"}); err == nil {
		t.Error("a message result was accepted as a task")
	}

	// No token file: nothing is sent.
	before := len(srv.requests)
	c.TokenFile = filepath.Join(t.TempDir(), "missing")
	if _, err := c.Send(context.Background(), Message{Text: "x"}); err == nil {
		t.Error("sent without a token")
	}
	if len(srv.requests) != before {
		t.Error("a request went out without a token")
	}
}
