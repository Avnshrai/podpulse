// Package users implements the lightweight user-onboarding feature:
// create a ServiceAccount in the cluster with a chosen scope, generate
// the matching Role/RoleBinding YAML, and emit a kubeconfig the
// human can hand to a new teammate.
//
// Three scopes are supported (the common asks):
//
//   viewer      get/list/watch on workloads + logs in the chosen namespace
//   developer   viewer + create/update/delete on workloads (no Secret edits)
//   admin       full access in the chosen namespace (still namespaced — never
//               cluster-admin, by design)
//
// PodPulse never grants cluster-admin via this flow; cluster-wide
// permission must be granted out-of-band.
package users

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Scope string

const (
	ScopeViewer    Scope = "viewer"
	ScopeDeveloper Scope = "developer"
	ScopeAdmin     Scope = "admin"
)

// User is one onboarded teammate.
type User struct {
	Name        string    `json:"name"`
	Namespace   string    `json:"namespace"`
	Scope       Scope     `json:"scope"`
	ClusterID   string    `json:"cluster_id,omitempty"` // empty = in-cluster
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	Description string    `json:"description,omitempty"`

	// Server-populated artifacts.
	ServiceAccount string `json:"service_account"`
	Role           string `json:"role"`
	RoleBinding    string `json:"role_binding"`
}

// ClusterClientLookup returns the typed K8s client + apiserver URL
// for the cluster identified by clusterID. Used by the cluster-scoped
// onboarding path (BYO kubeconfig). Pass nil to disable cluster-scoped
// onboarding and only support the in-cluster default flow.
type ClusterClientLookup func(clusterID string) (cs kubernetes.Interface, apiserverURL string, ok bool)

// Manager owns the onboarding flow.
type Manager struct {
	mu     sync.RWMutex
	cs     kubernetes.Interface
	users  map[userKey]User // (cluster_id, name) → user; cluster_id="" for in-cluster
	server string           // apiserver URL injected into kubeconfigs

	// ClusterLookup, when set, enables /v1/clusters/{id}/users.
	// The Manager will create SAs in the looked-up cluster instead of
	// the in-process one.
	ClusterLookup ClusterClientLookup

	// InsecureTLS makes generated kubeconfigs skip TLS verification.
	// Required when the user reaches PodPulse via plain HTTP (e.g. an
	// SSH tunnel to localhost:8080) — kubectl otherwise refuses an
	// http:// server URL. Set false in production with TLS termination
	// via Ingress + cert-manager.
	InsecureTLS bool
}

type userKey struct{ cluster, name string }

func NewManager(cs kubernetes.Interface, apiServer string) *Manager {
	return &Manager{
		cs:     cs,
		users:  map[userKey]User{},
		server: apiServer,
	}
}

// Onboard creates the ServiceAccount + Role + RoleBinding in the
// in-cluster K8s. For BYO clusters use OnboardInCluster.
func (m *Manager) Onboard(ctx context.Context, u User) (User, error) {
	return m.onboard(ctx, u, m.cs)
}

// OnboardInCluster creates the SA + Role + RoleBinding in the cluster
// identified by u.ClusterID, using the kubeconfig stored at registration.
func (m *Manager) OnboardInCluster(ctx context.Context, u User) (User, error) {
	if u.ClusterID == "" {
		return m.Onboard(ctx, u)
	}
	if m.ClusterLookup == nil {
		return User{}, errors.New("cluster lookup not configured")
	}
	cs, _, ok := m.ClusterLookup(u.ClusterID)
	if !ok {
		return User{}, errors.New("unknown cluster_id")
	}
	return m.onboard(ctx, u, cs)
}

func (m *Manager) onboard(ctx context.Context, u User, cs kubernetes.Interface) (User, error) {
	if cs == nil {
		return User{}, errors.New("kubernetes client unavailable")
	}
	u.Name = sanitize(u.Name)
	u.Namespace = sanitize(u.Namespace)
	if u.Name == "" || u.Namespace == "" {
		return User{}, errors.New("name and namespace are required")
	}
	if u.Scope == "" {
		u.Scope = ScopeViewer
	}
	saName := "podpulse-user-" + u.Name
	roleName := "podpulse-user-" + u.Name + "-" + string(u.Scope)
	bindingName := roleName + "-binding"

	// 1. ServiceAccount.
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saName,
			Namespace: u.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "podpulse", "podpulse.io/onboarded-user": u.Name},
		},
	}
	if _, err := cs.CoreV1().ServiceAccounts(u.Namespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return User{}, fmt.Errorf("create serviceaccount: %w", err)
	}

	// 2. Role for the chosen scope.
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleName,
			Namespace: u.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "podpulse"},
		},
		Rules: rulesFor(u.Scope),
	}
	if _, err := cs.RbacV1().Roles(u.Namespace).Create(ctx, role, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return User{}, fmt.Errorf("create role: %w", err)
		}
		if _, err := cs.RbacV1().Roles(u.Namespace).Update(ctx, role, metav1.UpdateOptions{}); err != nil {
			return User{}, fmt.Errorf("update role: %w", err)
		}
	}

	// 3. RoleBinding.
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      bindingName,
			Namespace: u.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "podpulse"},
		},
		Subjects: []rbacv1.Subject{{
			Kind: "ServiceAccount", Name: saName, Namespace: u.Namespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: roleName,
		},
	}
	if _, err := cs.RbacV1().RoleBindings(u.Namespace).Create(ctx, rb, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return User{}, fmt.Errorf("create rolebinding: %w", err)
	}

	u.CreatedAt = time.Now()
	u.ServiceAccount = saName
	u.Role = roleName
	u.RoleBinding = bindingName

	m.mu.Lock()
	m.users[userKey{u.ClusterID, u.Name}] = u
	m.mu.Unlock()
	return u, nil
}

// Remove deletes the SA / Role / RoleBinding for (clusterID, name).
// clusterID="" targets the in-cluster default flow.
func (m *Manager) Remove(ctx context.Context, clusterID, name string) error {
	m.mu.RLock()
	u, ok := m.users[userKey{clusterID, name}]
	m.mu.RUnlock()
	if !ok {
		return errors.New("user not found")
	}
	cs := m.cs
	if clusterID != "" && m.ClusterLookup != nil {
		if c, _, ok := m.ClusterLookup(clusterID); ok {
			cs = c
		}
	}
	if cs != nil {
		_ = cs.RbacV1().RoleBindings(u.Namespace).Delete(ctx, u.RoleBinding, metav1.DeleteOptions{})
		_ = cs.RbacV1().Roles(u.Namespace).Delete(ctx, u.Role, metav1.DeleteOptions{})
		_ = cs.CoreV1().ServiceAccounts(u.Namespace).Delete(ctx, u.ServiceAccount, metav1.DeleteOptions{})
	}
	m.mu.Lock()
	delete(m.users, userKey{clusterID, name})
	m.mu.Unlock()
	return nil
}

// List returns all onboarded users (across all clusters).
func (m *Manager) List() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	return out
}

// ListForCluster returns onboarded users for a specific cluster.
func (m *Manager) ListForCluster(clusterID string) []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []User{}
	for k, u := range m.users {
		if k.cluster == clusterID {
			out = append(out, u)
		}
	}
	return out
}

// Get returns one user by (clusterID, name).
func (m *Manager) Get(clusterID, name string) (User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[userKey{clusterID, name}]
	return u, ok
}

// Kubeconfig generates a kubeconfig for the user (clusterID="" for
// the in-cluster legacy flow). The server URL is the PodPulse /k8s
// proxy plus, for BYO clusters, the /<cluster_id>/ segment so kubectl
// traffic routes to the right apiserver.
func (m *Manager) Kubeconfig(ctx context.Context, clusterID, name string, ttlSeconds int64) (string, error) {
	u, ok := m.Get(clusterID, name)
	if !ok {
		return "", errors.New("user not found")
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 3600
	}

	cs := m.cs
	if clusterID != "" && m.ClusterLookup != nil {
		if c, _, ok := m.ClusterLookup(clusterID); ok {
			cs = c
		}
	}
	if cs == nil {
		return "", errors.New("kubernetes client unavailable for this cluster")
	}

	// TokenRequest is the modern way (since 1.22) to mint short-lived
	// SA tokens.
	tr, err := cs.CoreV1().ServiceAccounts(u.Namespace).CreateToken(ctx, u.ServiceAccount,
		&authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{ExpirationSeconds: &ttlSeconds}},
		metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}

	// Server URL: base + /k8s + /<cluster_id> (if any). The Kubeconfig
	// generator embeds this verbatim, so kubectl posts to the right
	// path.
	server := strings.TrimRight(m.server, "/")
	if clusterID != "" {
		server = server + "/" + clusterID
	}

	// If the kubeconfig points at PodPulse over plain HTTP (the typical
	// SSH-tunnel case), emit insecure-skip-tls-verify and omit the CA.
	if m.InsecureTLS {
		return renderKubeconfigInsecure(u, server, tr.Status.Token), nil
	}
	clusterCA, err := m.clusterCA(ctx, cs)
	if err != nil {
		return "", err
	}
	return renderKubeconfig(u, server, clusterCA, tr.Status.Token), nil
}

// clusterCA grabs the cluster's CA bundle from the kube-root-ca.crt
// ConfigMap (auto-mounted in every namespace).
func (m *Manager) clusterCA(ctx context.Context, cs kubernetes.Interface) (string, error) {
	cm, err := cs.CoreV1().ConfigMaps("default").Get(ctx, "kube-root-ca.crt", metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("read cluster CA: %w", err)
	}
	ca, ok := cm.Data["ca.crt"]
	if !ok {
		return "", errors.New("kube-root-ca.crt missing ca.crt key")
	}
	return base64.StdEncoding.EncodeToString([]byte(ca)), nil
}

// rulesFor returns the PolicyRules for the given scope.
func rulesFor(scope Scope) []rbacv1.PolicyRule {
	read := []string{"get", "list", "watch"}
	mutate := []string{"get", "list", "watch", "create", "update", "patch", "delete"}
	switch scope {
	case ScopeAdmin:
		return []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: mutate},
			{APIGroups: []string{"apps", "batch", "extensions", "networking.k8s.io"}, Resources: []string{"*"}, Verbs: mutate},
		}
	case ScopeDeveloper:
		return []rbacv1.PolicyRule{
			// Workloads (mutate).
			{APIGroups: []string{"apps", "batch"}, Resources: []string{"*"}, Verbs: mutate},
			{APIGroups: []string{""}, Resources: []string{"pods", "pods/log", "pods/exec", "services", "configmaps"}, Verbs: mutate},
			// Read-only on Secrets (no edits).
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: read},
			// Networking and events (read).
			{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"*"}, Verbs: read},
			{APIGroups: []string{""}, Resources: []string{"events", "namespaces", "nodes"}, Verbs: read},
		}
	default: // viewer
		return []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods", "pods/log", "services", "events", "configmaps", "namespaces"}, Verbs: read},
			{APIGroups: []string{"apps", "batch"}, Resources: []string{"*"}, Verbs: read},
			{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"*"}, Verbs: read},
		}
	}
}

func renderKubeconfig(u User, server, caB64, token string) string {
	cluster := "podpulse-cluster"
	contextName := u.Name + "@" + cluster
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %s
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: %s
  context:
    cluster: %s
    namespace: %s
    user: %s
current-context: %s
users:
- name: %s
  user:
    token: %s
`, cluster, server, caB64,
		contextName, cluster, u.Namespace, u.Name,
		contextName, u.Name, token)
}

// renderKubeconfigInsecure: same shape but with TLS verification
// disabled, for use when the user reaches PodPulse via http:// or a
// self-signed cert. kubectl otherwise refuses anything but TLS.
func renderKubeconfigInsecure(u User, server, token string) string {
	cluster := "podpulse-cluster"
	contextName := u.Name + "@" + cluster
	return fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: %s
  cluster:
    server: %s
    insecure-skip-tls-verify: true
contexts:
- name: %s
  context:
    cluster: %s
    namespace: %s
    user: %s
current-context: %s
users:
- name: %s
  user:
    token: %s
`, cluster, server,
		contextName, cluster, u.Namespace, u.Name,
		contextName, u.Name, token)
}

func sanitize(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			out = append(out, c)
		}
	}
	return string(out)
}

// randomToken — leftover helper from an earlier iteration; harmless.
func randomToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
