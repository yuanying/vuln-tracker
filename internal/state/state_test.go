package state

import (
	"context"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var t0 = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// The first observation after an empty state is the tracker being installed:
// what is already there is not new (ADR 0005).
func TestFirstObservationIsNotNew(t *testing.T) {
	s := New()
	s.Observe(t0, []string{"a|CVE-1", "b|CVE-2"})
	if got := s.FirstSeen("a|CVE-1"); got != 0 {
		t.Errorf("FirstSeen = %d, want 0", got)
	}
	s.Observe(t0.Add(time.Hour), []string{"a|CVE-1", "b|CVE-2", "c|CVE-3"})
	if got := s.FirstSeen("a|CVE-1"); got != 0 {
		t.Errorf("FirstSeen(a) moved to %d", got)
	}
	if got, want := s.FirstSeen("c|CVE-3"), t0.Add(time.Hour).Unix(); got != want {
		t.Errorf("FirstSeen(c) = %d, want %d", got, want)
	}
}

func TestForgetAfterThirtyDays(t *testing.T) {
	s := New()
	s.Observe(t0, nil)
	s.Observe(t0, []string{"a|CVE-1"})
	// Gone for 29 days, then back: still the old first-seen.
	s.Observe(t0.Add(29*24*time.Hour), nil)
	s.Observe(t0.Add(29*24*time.Hour+time.Minute), []string{"a|CVE-1"})
	if got := s.FirstSeen("a|CVE-1"); got != t0.Unix() {
		t.Errorf("FirstSeen = %d, want %d", got, t0.Unix())
	}
	// Gone for 31 days: forgotten, so new again when it returns.
	later := t0.Add(29*24*time.Hour + time.Minute + 31*24*time.Hour)
	s.Observe(later, nil)
	s.Observe(later.Add(time.Minute), []string{"a|CVE-1"})
	if got := s.FirstSeen("a|CVE-1"); got != later.Add(time.Minute).Unix() {
		t.Errorf("FirstSeen = %d, want %d", got, later.Add(time.Minute).Unix())
	}
}

func TestUnknownKey(t *testing.T) {
	if got := New().FirstSeen("x"); got != -1 {
		t.Errorf("FirstSeen of an unknown key = %d, want -1", got)
	}
}

func TestEncodeDecode(t *testing.T) {
	s := New()
	s.Observe(t0, []string{"a|CVE-1"})
	s.Digest = Digest{SentAt: t0.Unix(), Findings: map[string]Entry{"k": {Stage: "unfixed", VexState: "none"}}}
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Initialized || got.FirstSeen("a|CVE-1") != 0 || got.Digest.SentAt != t0.Unix() || got.Digest.Findings["k"].Stage != "unfixed" {
		t.Errorf("round trip lost something: %+v", got)
	}
	if _, err := Decode([]byte("not gzip")); err == nil {
		t.Error("Decode of garbage succeeded")
	}
}

// The requests to vuln-responder survive a restart (ADR 0009).
func TestEncodeDecodeRequests(t *testing.T) {
	s := New()
	s.Requests["source:yuanying/hshelf"] = Request{
		TargetType: "source", Target: "yuanying/hshelf", ContextID: "ctx-1", TaskID: "task-1", State: "working",
		Asked: []string{"a|CVE-1|json"}, Sending: []string{"a|CVE-1|json", "a|CVE-2|json"},
		PR: "https://github.com/yuanying/fleet-infra/pull/1", Summary: "s", Attempts: 2, NextAttempt: 5, SentAt: 3, UpdatedAt: 4,
	}
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Requests, s.Requests) {
		t.Errorf("round trip: %+v", got.Requests)
	}
	// A state written before requests existed decodes with none.
	old := New()
	old.Requests = nil
	b, _ = Encode(old)
	if got, _ := Decode(b); got.Requests == nil {
		t.Error("Requests is nil after decoding an older state")
	}
}

func TestDecodeGarbage(t *testing.T) {
	if _, err := Decode([]byte("not gzip")); err == nil {
		t.Error("Decode of garbage succeeded")
	}
}

func newClient(objs ...client.Object) client.Client {
	sch := runtime.NewScheme()
	_ = corev1.AddToScheme(sch)
	return fake.NewClientBuilder().WithScheme(sch).WithObjects(objs...).Build()
}

func TestConfigMapStore(t *testing.T) {
	ctx := context.Background()
	c := newClient()
	st := &ConfigMapStore{Client: c, Namespace: "vuln-tracker", Name: "vuln-tracker-state"}

	s, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.Initialized {
		t.Error("a missing ConfigMap should load as an empty state")
	}
	s.Observe(t0, []string{"a|CVE-1"})
	if err := st.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Observe(t0.Add(time.Hour), []string{"a|CVE-1", "b|CVE-2"})
	if err := st.Save(ctx, s); err != nil {
		t.Fatal(err)
	}

	var cm corev1.ConfigMap
	if err := c.Get(ctx, client.ObjectKey{Namespace: "vuln-tracker", Name: "vuln-tracker-state"}, &cm); err != nil {
		t.Fatal(err)
	}
	if _, ok := cm.BinaryData[DataKey]; !ok {
		t.Errorf("ConfigMap has no %s: %v", DataKey, cm.BinaryData)
	}
	again, err := (&ConfigMapStore{Client: c, Namespace: "vuln-tracker", Name: "vuln-tracker-state"}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again.FirstSeen("b|CVE-2") != t0.Add(time.Hour).Unix() {
		t.Errorf("reloaded state lost b: %+v", again)
	}
}

// A ConfigMap someone broke by hand is started over rather than wedging the
// tracker; what was in it is lost, which ADR 0006 already accepts for a
// deleted ConfigMap.
func TestConfigMapStoreCorrupt(t *testing.T) {
	c := newClient(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "st"},
		BinaryData: map[string][]byte{DataKey: []byte("garbage")},
	})
	st := &ConfigMapStore{Client: c, Namespace: "ns", Name: "st"}
	s, err := st.Load(context.Background())
	if err == nil {
		t.Error("Load of a corrupt ConfigMap reported no error")
	}
	if s == nil || s.Initialized {
		t.Errorf("Load should still hand back an empty state, got %+v", s)
	}
	if err := st.Save(context.Background(), New()); err != nil {
		t.Errorf("Save over a corrupt ConfigMap: %v", err)
	}
}
