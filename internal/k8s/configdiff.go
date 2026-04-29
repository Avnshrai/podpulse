// ConfigMap and Secret diff watcher with mount-aware blast radius.
//
// This is the headline differentiator for PodPulse: ~35-40% of K8s
// production incidents are config issues (empty value, broken JSON,
// changed env var, removed key). Existing tools watch logs and metrics
// — none watch config drift. We do, and we can answer:
//
//   "Which pods mount this ConfigMap, and did any of them start
//    failing right after the value changed?"
package k8s

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// ConfigKind distinguishes the two object types we watch.
type ConfigKind string

const (
	KindConfigMap ConfigKind = "ConfigMap"
	KindSecret    ConfigKind = "Secret"
)

// ChangeType labels what happened to a single key.
type ChangeType string

const (
	ChangeAdded         ChangeType = "added"
	ChangeRemoved       ChangeType = "removed"
	ChangeBecameEmpty   ChangeType = "became_empty"
	ChangeFromEmpty     ChangeType = "from_empty"
	ChangeValueChanged  ChangeType = "value_changed"
	ChangeMalformedJSON ChangeType = "malformed_json"
)

// KeyChange is one diff of one key inside a ConfigMap or Secret.
type KeyChange struct {
	Key      string     `json:"key"`
	Type     ChangeType `json:"type"`
	OldValue string     `json:"old_value,omitempty"` // redacted for Secret
	NewValue string     `json:"new_value,omitempty"`
	Note     string     `json:"note,omitempty"` // human note, e.g. "JSON has unterminated string at line 14"
}

// ConfigChange is one diff event for one ConfigMap or Secret.
type ConfigChange struct {
	Kind      ConfigKind  `json:"kind"`
	Namespace string      `json:"namespace"`
	Name      string      `json:"name"`
	When      time.Time   `json:"when"`
	Changes   []KeyChange `json:"changes"`

	// MountedBy lists the workloads that mount this resource (via
	// envFrom, env.valueFrom, or volume.configMap/secret). Computed at
	// diff time; stale mounts are not re-resolved later.
	MountedBy []ConfigMount `json:"mounted_by,omitempty"`
}

// ConfigMount tells us which workload is at risk.
type ConfigMount struct {
	Namespace string `json:"namespace"`
	OwnerKind string `json:"owner_kind"`
	OwnerName string `json:"owner_name"`
	Pod       string `json:"pod,omitempty"` // a representative pod
	Mode      string `json:"mode"`          // "envFrom", "env", "volume"
}

// configValue stores one snapshot of the parsed key:value state.
type configValue struct {
	hash    string // content hash (for change detection without storing values)
	keys    map[string]string
	version string
	when    time.Time
}

// ConfigWatcher subscribes to ConfigMaps + Secrets and emits a stream
// of ConfigChange events.
type ConfigWatcher struct {
	mu      sync.RWMutex
	last    map[configKey]configValue // most recent observed state
	history []ConfigChange            // ring buffer of recent changes
	maxHist int

	logger *slog.Logger
	cache  *Cache // for mount-aware blast-radius lookup
}

type configKey struct {
	kind ConfigKind
	ns   string
	name string
}

// NewConfigWatcher returns a watcher; pass the parent Cache so we can
// answer "which pods mount this".
func NewConfigWatcher(parent *Cache, logger *slog.Logger) *ConfigWatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &ConfigWatcher{
		last:    map[configKey]configValue{},
		maxHist: 500,
		logger:  logger,
		cache:   parent,
	}
}

// Run starts shared informers for ConfigMaps and Secrets and blocks
// until ctx is cancelled.
func (w *ConfigWatcher) Run(ctx context.Context, cs kubernetes.Interface, resync time.Duration) error {
	factory := informers.NewSharedInformerFactory(cs, resync)
	cm := factory.Core().V1().ConfigMaps().Informer()
	sec := factory.Core().V1().Secrets().Informer()

	_, _ = cm.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { w.onConfigMapAdd(o, true) },
		UpdateFunc: func(_, o any) { w.onConfigMapAdd(o, false) },
	})
	_, _ = sec.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { w.onSecretAdd(o, true) },
		UpdateFunc: func(_, o any) { w.onSecretAdd(o, false) },
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), cm.HasSynced, sec.HasSynced) {
		return ctx.Err()
	}
	w.logger.Info("config watcher synced",
		"configmaps", len(cm.GetStore().List()),
		"secrets", len(sec.GetStore().List()),
	)
	<-ctx.Done()
	return ctx.Err()
}

// RecentChanges returns the most recent N changes, newest first.
func (w *ConfigWatcher) RecentChanges(limit int) []ConfigChange {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if limit <= 0 || limit > len(w.history) {
		limit = len(w.history)
	}
	out := make([]ConfigChange, 0, limit)
	for i := len(w.history) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, w.history[i])
	}
	return out
}

// ChangesFor returns all ConfigChanges in the given time window for
// any ConfigMap or Secret mounted by a workload in this namespace.
func (w *ConfigWatcher) ChangesForNamespace(ns string, since time.Time) []ConfigChange {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := []ConfigChange{}
	for _, c := range w.history {
		if c.Namespace != ns {
			continue
		}
		if c.When.Before(since) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// --- handlers ---

func (w *ConfigWatcher) onConfigMapAdd(obj any, initial bool) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return
	}
	cur := configValue{
		keys:    map[string]string{},
		version: cm.ResourceVersion,
		when:    time.Now(),
	}
	for k, v := range cm.Data {
		cur.keys[k] = v
	}
	for k, v := range cm.BinaryData {
		cur.keys[k] = string(v)
	}
	cur.hash = hashKeys(cur.keys)

	w.applySnapshot(configKey{KindConfigMap, cm.Namespace, cm.Name}, cur, initial, KindConfigMap, cm.Namespace, cm.Name)
}

func (w *ConfigWatcher) onSecretAdd(obj any, initial bool) {
	s, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}
	// Skip noisy infra-managed Secrets that nobody can act on:
	//   - SA / bootstrap tokens (rotate constantly)
	//   - Helm release blobs (`sh.helm.release.v1.*`)
	//   - HelmChart and Helm operator secrets
	//   - Sealed-secret intermediate keys
	if s.Type == corev1.SecretTypeServiceAccountToken ||
		s.Type == "bootstrap.kubernetes.io/token" ||
		s.Type == "helm.sh/release.v1" {
		return
	}
	if strings.HasPrefix(s.Name, "sh.helm.release.") ||
		strings.HasPrefix(s.Name, "helm.toolkit.fluxcd.io-") {
		return
	}
	cur := configValue{
		keys:    map[string]string{},
		version: s.ResourceVersion,
		when:    time.Now(),
	}
	for k, v := range s.Data {
		cur.keys[k] = string(v)
	}
	cur.hash = hashKeys(cur.keys)

	w.applySnapshot(configKey{KindSecret, s.Namespace, s.Name}, cur, initial, KindSecret, s.Namespace, s.Name)
}

func (w *ConfigWatcher) applySnapshot(k configKey, cur configValue, initial bool,
	kind ConfigKind, ns, name string) {

	w.mu.Lock()
	prev, hadPrev := w.last[k]
	w.last[k] = cur
	w.mu.Unlock()

	// On the first observation we record the snapshot but don't emit
	// a "change" — otherwise startup spams the timeline.
	if initial && !hadPrev {
		return
	}
	if !hadPrev {
		return
	}
	if prev.hash == cur.hash {
		return // no actual change
	}

	change := ConfigChange{
		Kind: kind, Namespace: ns, Name: name, When: cur.when,
		Changes: diffKeys(prev.keys, cur.keys, kind == KindSecret),
	}
	if len(change.Changes) == 0 {
		return
	}
	change.MountedBy = w.findMounters(kind, ns, name)

	w.mu.Lock()
	if len(w.history) >= w.maxHist {
		w.history = w.history[1:]
	}
	w.history = append(w.history, change)
	w.mu.Unlock()

	w.logger.Info("config change",
		"kind", kind, "ns", ns, "name", name,
		"changes", len(change.Changes), "mounted_by", len(change.MountedBy),
	)
}

// diffKeys computes per-key changes; for Secret kind we only return
// metadata about each key (length / emptiness), not the value, to avoid
// shipping secrets through the dashboard.
func diffKeys(prev, cur map[string]string, isSecret bool) []KeyChange {
	out := []KeyChange{}
	seen := map[string]struct{}{}
	for k, v := range prev {
		seen[k] = struct{}{}
		nv, ok := cur[k]
		if !ok {
			out = append(out, KeyChange{Key: k, Type: ChangeRemoved, OldValue: maskIfSecret(v, isSecret)})
			continue
		}
		if nv == v {
			continue
		}
		switch {
		case nv == "" && v != "":
			out = append(out, KeyChange{Key: k, Type: ChangeBecameEmpty, OldValue: maskIfSecret(v, isSecret)})
		case nv != "" && v == "":
			out = append(out, KeyChange{Key: k, Type: ChangeFromEmpty, NewValue: maskIfSecret(nv, isSecret)})
		default:
			c := KeyChange{Key: k, Type: ChangeValueChanged,
				OldValue: maskIfSecret(v, isSecret),
				NewValue: maskIfSecret(nv, isSecret)}
			if note := jsonProblem(nv); note != "" {
				c.Type = ChangeMalformedJSON
				c.Note = note
			}
			out = append(out, c)
		}
	}
	for k, v := range cur {
		if _, ok := seen[k]; ok {
			continue
		}
		c := KeyChange{Key: k, Type: ChangeAdded, NewValue: maskIfSecret(v, isSecret)}
		if v == "" {
			c.Type = ChangeBecameEmpty
		}
		if note := jsonProblem(v); note != "" {
			c.Type = ChangeMalformedJSON
			c.Note = note
		}
		out = append(out, c)
	}
	return out
}

// jsonProblem returns a short note if v looks like JSON but doesn't
// parse — exactly the comm-pod brevo-key case (unterminated string).
func jsonProblem(v string) string {
	v = strings.TrimSpace(v)
	if !(strings.HasPrefix(v, "{") || strings.HasPrefix(v, "[")) {
		return ""
	}
	var x any
	if err := json.Unmarshal([]byte(v), &x); err != nil {
		// Make the message human and short.
		msg := err.Error()
		if i := strings.Index(msg, ":"); i > 0 && i < 60 {
			return "JSON parse error: " + msg
		}
		return "JSON parse error"
	}
	return ""
}

func maskIfSecret(v string, isSecret bool) string {
	if isSecret {
		if v == "" {
			return ""
		}
		return "<*REDACTED:" + lengthBucket(len(v)) + " chars*>"
	}
	if len(v) > 200 {
		return v[:200] + "…"
	}
	return v
}

func lengthBucket(n int) string {
	switch {
	case n < 8:
		return "<8"
	case n < 32:
		return "<32"
	case n < 128:
		return "<128"
	default:
		return ">128"
	}
}

func hashKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Stable order matters.
	sortStrings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('\x1e')
	}
	return strings.TrimSpace(b.String())
}

// findMounters scans the parent Cache's pods and returns workloads
// that mount the given ConfigMap or Secret via env*, envFrom, or
// volumes.
func (w *ConfigWatcher) findMounters(kind ConfigKind, ns, name string) []ConfigMount {
	if w.cache == nil {
		return nil
	}
	w.cache.mu.RLock()
	mounts := []ConfigMount{}
	seen := map[ownerRef]struct{}{}
	for _, m := range w.cache.podMountIndex {
		if m.Namespace != ns {
			continue
		}
		if (kind == KindConfigMap && contains(m.MountedConfigMaps, name)) ||
			(kind == KindSecret && contains(m.MountedSecrets, name)) {
			ref := ownerRef{kind: m.OwnerKind, name: m.OwnerName}
			if _, ok := seen[ref]; ok {
				continue
			}
			seen[ref] = struct{}{}
			mounts = append(mounts, ConfigMount{
				Namespace: m.Namespace,
				OwnerKind: m.OwnerKind,
				OwnerName: m.OwnerName,
				Pod:       m.PodName,
				Mode:      "mount",
			})
		}
	}
	w.cache.mu.RUnlock()
	return mounts
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// sortStrings is a tiny quicksort stand-in to avoid the sort import
// just for hashKeys.
func sortStrings(s []string) {
	// Insertion sort — fine for typical configmap key counts.
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j-1] > s[j] {
			s[j-1], s[j] = s[j], s[j-1]
			j--
		}
	}
}
