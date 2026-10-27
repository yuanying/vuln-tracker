package state

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DataKey is the binaryData key the state is kept under.
const DataKey = "state.json.gz"

// ConfigMapStore keeps the state in one ConfigMap in the tracker's namespace.
// The tracker creates it; the manifests do not ship it, since only the
// tracker writes what is in it.
//
// Client should read straight from the API server: the tracker's RBAC names
// this one ConfigMap, which a cache-backed list could not be granted.
type ConfigMapStore struct {
	Client    client.Client
	Namespace string
	Name      string

	resourceVersion string
	exists          bool
}

// Load reads the state. A missing ConfigMap is an empty state. A ConfigMap
// that cannot be decoded is reported, and an empty state is handed back too,
// so the tracker starts over instead of stopping; the next Save replaces it.
func (s *ConfigMapStore) Load(ctx context.Context) (*State, error) {
	var cm corev1.ConfigMap
	err := s.Client.Get(ctx, client.ObjectKey{Namespace: s.Namespace, Name: s.Name}, &cm)
	if apierrors.IsNotFound(err) {
		s.exists = false
		return New(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading ConfigMap %s/%s: %w", s.Namespace, s.Name, err)
	}
	s.exists, s.resourceVersion = true, cm.ResourceVersion
	b, ok := cm.BinaryData[DataKey]
	if !ok {
		return New(), nil
	}
	st, err := Decode(b)
	if err != nil {
		return New(), fmt.Errorf("ConfigMap %s/%s: %w", s.Namespace, s.Name, err)
	}
	return st, nil
}

// Save writes the state. Updates carry the resourceVersion last read or
// written, so a second writer — which the single replica and the Recreate
// strategy should rule out — is refused rather than overwritten.
func (s *ConfigMapStore) Save(ctx context.Context, st *State) error {
	b, err := Encode(st)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: s.Namespace,
			Name:      s.Name,
			Labels:    map[string]string{"app.kubernetes.io/name": "vuln-tracker"},
		},
		BinaryData: map[string][]byte{DataKey: b},
	}
	if !s.exists {
		if err := s.Client.Create(ctx, cm); err != nil {
			return fmt.Errorf("creating ConfigMap %s/%s: %w", s.Namespace, s.Name, err)
		}
	} else {
		cm.ResourceVersion = s.resourceVersion
		if err := s.Client.Update(ctx, cm); err != nil {
			return fmt.Errorf("updating ConfigMap %s/%s: %w", s.Namespace, s.Name, err)
		}
	}
	s.exists, s.resourceVersion = true, cm.ResourceVersion
	return nil
}
