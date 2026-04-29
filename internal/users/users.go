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
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	Description string    `json:"description,omitempty"`

	// Server-populated artifacts.
	ServiceAccount string `json:"service_account"`
	Role           string `json:"role"`
	RoleBinding    string `json:"role_binding"`
}

// Manager owns the onboarding flow.
type Manager struct {
	mu     sync.RWMutex
	cs     kubernetes.Interface
	users  map[string]User // name → user
	server string          // K8s api-server URL for kubeconfig
}

func NewManager(cs kubernetes.Interface, apiServer string) *Manager {
	return &Manager{
		cs:     cs,
		users:  map[string]User{},
		server: apiServer,
	}
}

// Onboard creates the ServiceAccount + Role + RoleBinding in the
// cluster and returns the full User record (incl. generated kubeconfig
// will be served separately).
func (m *Manager) Onboard(ctx context.Context, u User) (User, error) {
	if m.cs == nil {
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
	if _, err := m.cs.CoreV1().ServiceAccounts(u.Namespace).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
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
	if _, err := m.cs.RbacV1().Roles(u.Namespace).Create(ctx, role, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return User{}, fmt.Errorf("create role: %w", err)
		}
		// Update the existing role to match desired rules.
		if _, err := m.cs.RbacV1().Roles(u.Namespace).Update(ctx, role, metav1.UpdateOptions{}); err != nil {
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
	if _, err := m.cs.RbacV1().RoleBindings(u.Namespace).Create(ctx, rb, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return User{}, fmt.Errorf("create rolebinding: %w", err)
	}

	u.CreatedAt = time.Now()
	u.ServiceAccount = saName
	u.Role = roleName
	u.RoleBinding = bindingName

	m.mu.Lock()
	m.users[u.Name] = u
	m.mu.Unlock()
	return u, nil
}

// Remove deletes the SA / Role / RoleBinding.
func (m *Manager) Remove(ctx context.Context, name string) error {
	m.mu.RLock()
	u, ok := m.users[name]
	m.mu.RUnlock()
	if !ok {
		return errors.New("user not found")
	}
	_ = m.cs.RbacV1().RoleBindings(u.Namespace).Delete(ctx, u.RoleBinding, metav1.DeleteOptions{})
	_ = m.cs.RbacV1().Roles(u.Namespace).Delete(ctx, u.Role, metav1.DeleteOptions{})
	_ = m.cs.CoreV1().ServiceAccounts(u.Namespace).Delete(ctx, u.ServiceAccount, metav1.DeleteOptions{})
	m.mu.Lock()
	delete(m.users, name)
	m.mu.Unlock()
	return nil
}

// List returns all onboarded users.
func (m *Manager) List() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	return out
}

// Get returns one user by name.
func (m *Manager) Get(name string) (User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[name]
	return u, ok
}

// Kubeconfig generates a kubeconfig for the user. We mint a short-lived
// TokenRequest (1h) — far safer than mounting the legacy SA token
// secret.
func (m *Manager) Kubeconfig(ctx context.Context, name string, ttlSeconds int64) (string, error) {
	u, ok := m.Get(name)
	if !ok {
		return "", errors.New("user not found")
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 3600
	}
	clusterCA, err := m.clusterCA(ctx)
	if err != nil {
		return "", err
	}

	// TokenRequest is the modern way (since 1.22) to mint short-lived
	// SA tokens.
	tr, err := m.cs.CoreV1().ServiceAccounts(u.Namespace).CreateToken(ctx, u.ServiceAccount,
		&authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{ExpirationSeconds: &ttlSeconds}},
		metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}

	return renderKubeconfig(u, m.server, clusterCA, tr.Status.Token), nil
}

// clusterCA grabs the cluster's CA bundle from the kube-root-ca.crt
// ConfigMap (auto-mounted in every namespace).
func (m *Manager) clusterCA(ctx context.Context) (string, error) {
	cm, err := m.cs.CoreV1().ConfigMaps("default").Get(ctx, "kube-root-ca.crt", metav1.GetOptions{})
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
