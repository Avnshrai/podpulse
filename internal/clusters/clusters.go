// Package clusters is the bring-your-own-kubeconfig registry.
//
// Flow:
//
//   1. Admin POSTs a kubeconfig YAML to /v1/clusters.
//   2. PodPulse parses + validates it (tries `kubectl get nodes`).
//   3. Stores the kubeconfig + apiserver URL in Postgres.
//   4. The cluster becomes selectable in the UI for user onboarding.
//   5. When users are onboarded against this cluster, PodPulse uses
//      the stored kubeconfig to create the SA + Role + RoleBinding
//      in the target cluster's `kube-rbac` plumbing.
//   6. The /k8s/{cluster_id}/* proxy uses the stored apiserver URL +
//      CA to forward kubectl traffic.
//
// The kubeconfig is stored as raw YAML. Encryption-at-rest is on the
// roadmap (envelope-encrypt with a key from a K8s Secret) — for now
// the DB user has restricted access and Postgres' on-disk encryption
// is the only protection.
package clusters

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/podpulse/podpulse/internal/db"
)

// Cluster is one registered Kubernetes target.
type Cluster struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	APIServerURL  string    `json:"apiserver_url"`
	Description   string    `json:"description,omitempty"`
	OrgID         uuid.UUID `json:"-"`               // tenant scope; never returned to wire
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by,omitempty"`
}

// Store persists clusters and caches their built K8s clients.
//
// Postgres is optional: when d is nil the Store still works fully —
// just in-memory, lost on restart. The DB-backed path is identical
// otherwise.
type Store struct {
	d *db.DB

	mu      sync.RWMutex
	clients map[uuid.UUID]*kubernetes.Clientset
	configs map[uuid.UUID]string // raw kubeconfig YAML for proxy lookups
	urls    map[uuid.UUID]string // apiserver URL

	// rows is the in-memory mirror used both for fast reads and as the
	// authoritative store when d == nil.
	rows map[uuid.UUID]Cluster
}

func New(d *db.DB) *Store {
	return &Store{
		d:       d,
		clients: map[uuid.UUID]*kubernetes.Clientset{},
		configs: map[uuid.UUID]string{},
		urls:    map[uuid.UUID]string{},
		rows:    map[uuid.UUID]Cluster{},
	}
}

// Register validates a kubeconfig (must list nodes) and persists it.
// orgID may be uuid.Nil for single-tenant mode; multi-tenant callers
// MUST pass the caller's org id so the row is filterable.
func (s *Store) Register(ctx context.Context, orgID uuid.UUID, name, kubeconfigYAML, description, createdBy string) (*Cluster, error) {
	if name == "" {
		return nil, errors.New("cluster name required")
	}
	if kubeconfigYAML == "" {
		return nil, errors.New("kubeconfig is empty")
	}

	cs, server, err := buildClient([]byte(kubeconfigYAML))
	if err != nil {
		return nil, fmt.Errorf("invalid kubeconfig: %w", err)
	}
	if err := healthCheck(ctx, cs); err != nil {
		return nil, fmt.Errorf("kubeconfig works structurally but the cluster is unreachable: %w", err)
	}

	// Reject duplicate names within the same org.
	s.mu.RLock()
	for _, c := range s.rows {
		if c.Name == name && c.OrgID == orgID {
			s.mu.RUnlock()
			return nil, fmt.Errorf("a cluster named %q is already registered in this organization", name)
		}
	}
	s.mu.RUnlock()

	row := &Cluster{
		ID:           uuid.New(),
		Name:         name,
		APIServerURL: server,
		Description:  description,
		OrgID:        orgID,
		CreatedAt:    time.Now(),
		CreatedBy:    createdBy,
	}
	if s.d != nil {
		var orgArg any = orgID
		if orgID == uuid.Nil {
			orgArg = nil
		}
		_, err := s.d.Pool.Exec(ctx, `
			INSERT INTO clusters (id, org_id, name, apiserver_url, kubeconfig, description, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			row.ID, orgArg, row.Name, row.APIServerURL, kubeconfigYAML, description, createdBy)
		if err != nil {
			return nil, fmt.Errorf("persist cluster: %w", err)
		}
	}

	s.mu.Lock()
	s.clients[row.ID] = cs
	s.configs[row.ID] = kubeconfigYAML
	s.urls[row.ID] = server
	s.rows[row.ID] = *row
	s.mu.Unlock()
	return row, nil
}

// LoadAll repopulates the in-memory caches (clients + rows) from the
// DB on startup. No-op when running without a DB.
func (s *Store) LoadAll(ctx context.Context) error {
	if s.d == nil {
		return nil
	}
	rows, err := s.d.Pool.Query(ctx, `
		SELECT id, COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid),
		       name, apiserver_url, kubeconfig, COALESCE(description,''),
		       created_at, COALESCE(created_by,'')
		FROM clusters`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var c Cluster
		var cfgYAML string
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Name, &c.APIServerURL, &cfgYAML,
			&c.Description, &c.CreatedAt, &c.CreatedBy); err != nil {
			continue
		}
		cs, _, err := buildClient([]byte(cfgYAML))
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.clients[c.ID] = cs
		s.configs[c.ID] = cfgYAML
		s.urls[c.ID] = c.APIServerURL
		s.rows[c.ID] = c
		s.mu.Unlock()
	}
	return rows.Err()
}

// List returns clusters scoped to the calling org. Pass uuid.Nil for
// single-tenant mode (returns all clusters with no org).
func (s *Store) List(ctx context.Context, orgID uuid.UUID) ([]*Cluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Cluster, 0, len(s.rows))
	for _, c := range s.rows {
		if !sameOrg(c.OrgID, orgID) {
			continue
		}
		copy := c
		out = append(out, &copy)
	}
	return out, nil
}

// Get returns one cluster by ID, scoped by org. Returns "not found"
// (not "forbidden") when an org tries to access a cluster from another
// org, to avoid leaking cluster existence across tenants.
func (s *Store) Get(ctx context.Context, orgID, id uuid.UUID) (*Cluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.rows[id]
	if !ok || !sameOrg(c.OrgID, orgID) {
		return nil, errors.New("not found")
	}
	return &c, nil
}

// Delete removes a cluster, scoped to the org. Same isolation as Get.
func (s *Store) Delete(ctx context.Context, orgID, id uuid.UUID) error {
	s.mu.RLock()
	c, ok := s.rows[id]
	s.mu.RUnlock()
	if !ok || !sameOrg(c.OrgID, orgID) {
		return errors.New("not found")
	}
	if s.d != nil {
		if _, err := s.d.Pool.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, id); err != nil {
			return err
		}
	}
	s.mu.Lock()
	delete(s.clients, id)
	delete(s.configs, id)
	delete(s.urls, id)
	delete(s.rows, id)
	s.mu.Unlock()
	return nil
}

// sameOrg returns true when callerOrg matches the row's OrgID, OR
// callerOrg is uuid.Nil (single-tenant fallback / legacy in-cluster
// mode where no auth is configured).
func sameOrg(rowOrg, callerOrg uuid.UUID) bool {
	if callerOrg == uuid.Nil {
		return true
	}
	return rowOrg == callerOrg
}

// Client returns the cached typed client for a cluster.
func (s *Store) Client(id uuid.UUID) (*kubernetes.Clientset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cs, ok := s.clients[id]
	return cs, ok
}

// APIServerURL returns the cluster's apiserver endpoint (used by /k8s proxy).
func (s *Store) APIServerURL(id uuid.UUID) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.urls[id]
	return u, ok
}

// KubeconfigYAML returns the raw stored kubeconfig (used by /k8s proxy
// to extract the cluster's CA bundle for TLS validation).
func (s *Store) KubeconfigYAML(id uuid.UUID) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	y, ok := s.configs[id]
	return y, ok
}

// --- helpers ---

func buildClient(kubeconfigYAML []byte) (*kubernetes.Clientset, string, error) {
	cfg, err := clientcmd.RESTConfigFromKubeConfig(kubeconfigYAML)
	if err != nil {
		return nil, "", err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}
	return cs, cfg.Host, nil
}

func healthCheck(ctx context.Context, cs *kubernetes.Clientset) error {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Listing namespaces is cheap and works for any reasonable scope.
	_, err := cs.CoreV1().Namespaces().List(c, metav1.ListOptions{Limit: 1})
	if err != nil {
		// If the user gave us a kubeconfig that can list nodes but not
		// namespaces, fall back to that.
		_, err2 := cs.CoreV1().Nodes().List(c, metav1.ListOptions{Limit: 1})
		if err2 != nil {
			return err
		}
	}
	_ = corev1.NamespaceDefault // import keeper
	return nil
}
