// Cluster audit watcher.
//
// Every K8s object carries `metadata.managedFields[]` — a server-side
// recording of which user/serviceaccount last set which fields, with
// the timestamp. PodPulse mines this passively (no audit-webhook
// configuration required) to answer:
//
//   "Who edited this Deployment? Which Secret did kubectl-bob change
//    in the last hour? Who deleted this pod?"
//
// We watch the resources humans actually mutate: Deployments,
// StatefulSets, DaemonSets, Pods (delete events), ConfigMaps, Secrets.
// Each Update is diffed against the previous version we have cached
// (resource versions); the most recent FieldsV1 manager wins as the
// "actor" of that update.
package k8s

import (
	"context"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// AuditAction describes what the user did.
type AuditAction string

const (
	ActionCreate AuditAction = "create"
	ActionUpdate AuditAction = "update"
	ActionDelete AuditAction = "delete"
)

// AuditEvent is one recorded mutation.
type AuditEvent struct {
	When      time.Time   `json:"when"`
	Actor     string      `json:"actor"`     // user / serviceaccount name
	ActorType string      `json:"actor_type"` // User | ServiceAccount | Controller
	Action    AuditAction `json:"action"`
	Kind      string      `json:"kind"`
	Namespace string      `json:"namespace,omitempty"`
	Name      string      `json:"name"`
	Fields    []string    `json:"fields,omitempty"` // top-level field paths touched
	Risk      string      `json:"risk,omitempty"`   // info | medium | high
	Note      string      `json:"note,omitempty"`
}

// AuditWatcher records mutations to important resources.
type AuditWatcher struct {
	mu      sync.RWMutex
	events  []AuditEvent
	maxItems int
	logger  *slog.Logger
}

func NewAuditWatcher(logger *slog.Logger) *AuditWatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuditWatcher{maxItems: 2000, logger: logger}
}

func (w *AuditWatcher) Run(ctx context.Context, cs kubernetes.Interface, resync time.Duration) error {
	factory := informers.NewSharedInformerFactory(cs, resync)
	deploys := factory.Apps().V1().Deployments().Informer()
	statefuls := factory.Apps().V1().StatefulSets().Informer()
	daemons := factory.Apps().V1().DaemonSets().Informer()
	pods := factory.Core().V1().Pods().Informer()
	cms := factory.Core().V1().ConfigMaps().Informer()
	secrets := factory.Core().V1().Secrets().Informer()

	add := func(name, kind string) func(any) {
		return func(o any) { w.recordCreate(o, kind) }
	}
	upd := func(kind string) func(any, any) {
		return func(old, cur any) { w.recordUpdate(old, cur, kind) }
	}
	del := func(kind string) func(any) {
		return func(o any) { w.recordDelete(o, kind) }
	}

	type pair struct {
		inf  cache.SharedIndexInformer
		kind string
	}
	for _, p := range []pair{
		{deploys, "Deployment"},
		{statefuls, "StatefulSet"},
		{daemons, "DaemonSet"},
		{pods, "Pod"},
		{cms, "ConfigMap"},
		{secrets, "Secret"},
	} {
		inf := p.inf
		k := p.kind
		_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    add(k, k),
			UpdateFunc: upd(k),
			DeleteFunc: del(k),
		})
	}

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(),
		deploys.HasSynced, statefuls.HasSynced, daemons.HasSynced,
		pods.HasSynced, cms.HasSynced, secrets.HasSynced) {
		return ctx.Err()
	}
	w.logger.Info("audit watcher synced")
	<-ctx.Done()
	return ctx.Err()
}

// Recent returns the N most recent events newest-first, optionally
// filtered by actor / namespace / kind / time-window.
type AuditFilter struct {
	Limit     int
	Actor     string
	Namespace string
	Kind      string
	Action    AuditAction
	Since     time.Time
	OnlyHumans bool // skip controller / system actors
}

func (w *AuditWatcher) Query(f AuditFilter) []AuditEvent {
	w.mu.RLock()
	defer w.mu.RUnlock()
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	out := make([]AuditEvent, 0, limit)
	for i := len(w.events) - 1; i >= 0 && len(out) < limit; i-- {
		e := w.events[i]
		if !f.Since.IsZero() && e.When.Before(f.Since) {
			continue
		}
		if f.Actor != "" && e.Actor != f.Actor {
			continue
		}
		if f.Namespace != "" && e.Namespace != f.Namespace {
			continue
		}
		if f.Kind != "" && e.Kind != f.Kind {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		if f.OnlyHumans && e.ActorType != "User" {
			continue
		}
		out = append(out, e)
	}
	return out
}

// Actors returns counts of distinct actors and their last-seen time.
type ActorStat struct {
	Actor     string    `json:"actor"`
	ActorType string    `json:"actor_type"`
	Events    int       `json:"events"`
	LastSeen  time.Time `json:"last_seen"`
}

func (w *AuditWatcher) Actors() []ActorStat {
	w.mu.RLock()
	defer w.mu.RUnlock()
	idx := map[string]*ActorStat{}
	for _, e := range w.events {
		s, ok := idx[e.Actor]
		if !ok {
			s = &ActorStat{Actor: e.Actor, ActorType: e.ActorType}
			idx[e.Actor] = s
		}
		s.Events++
		if e.When.After(s.LastSeen) {
			s.LastSeen = e.When
		}
	}
	out := make([]ActorStat, 0, len(idx))
	for _, s := range idx {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// --- recording ---

func (w *AuditWatcher) recordCreate(obj any, kind string) {
	m := getObjectMeta(obj)
	if m == nil {
		return
	}
	// Skip noisy auto-replicaset / pod creation churn driven by
	// controllers — only record human-driven creates.
	actor, atype := actorFromManagedFields(m, w.now())
	if atype != "User" {
		return
	}
	if w.tooNoisy(kind, m.Name) {
		return
	}
	w.append(AuditEvent{
		When: m.CreationTimestamp.Time, Actor: actor, ActorType: atype,
		Action: ActionCreate, Kind: kind, Namespace: m.Namespace, Name: m.Name,
		Risk: "medium",
	})
}

func (w *AuditWatcher) recordUpdate(oldObj, curObj any, kind string) {
	prev := getObjectMeta(oldObj)
	cur := getObjectMeta(curObj)
	if prev == nil || cur == nil {
		return
	}
	if prev.ResourceVersion == cur.ResourceVersion {
		return // no actual change
	}
	if w.tooNoisy(kind, cur.Name) {
		return
	}
	actor, atype := actorFromManagedFields(cur, w.now())
	if actor == "" {
		return
	}
	fields := changedFields(prev, cur)
	risk := riskFor(kind, fields)
	w.append(AuditEvent{
		When: w.now(), Actor: actor, ActorType: atype,
		Action: ActionUpdate, Kind: kind, Namespace: cur.Namespace, Name: cur.Name,
		Fields: fields, Risk: risk,
	})
}

func (w *AuditWatcher) recordDelete(obj any, kind string) {
	// Pods deleted by their controller are not interesting; only
	// surface direct deletes (rare for CMs/Secrets/Deployments).
	m := getObjectMeta(obj)
	if m == nil {
		return
	}
	if w.tooNoisy(kind, m.Name) {
		return
	}
	actor, atype := actorFromManagedFields(m, w.now())
	if atype != "User" {
		return
	}
	w.append(AuditEvent{
		When: w.now(), Actor: actor, ActorType: atype,
		Action: ActionDelete, Kind: kind, Namespace: m.Namespace, Name: m.Name,
		Risk: "high",
	})
}

func (w *AuditWatcher) append(e AuditEvent) {
	if e.When.IsZero() {
		e.When = w.now()
	}
	w.mu.Lock()
	if len(w.events) >= w.maxItems {
		w.events = w.events[1:]
	}
	w.events = append(w.events, e)
	w.mu.Unlock()
}

func (w *AuditWatcher) now() time.Time { return time.Now() }

// tooNoisy filters out auto-managed names that flood the audit log.
func (w *AuditWatcher) tooNoisy(kind, name string) bool {
	if kind == "Secret" {
		if strings.HasPrefix(name, "sh.helm.release.") ||
			strings.HasPrefix(name, "default-token-") ||
			strings.Contains(name, "-token-") {
			return true
		}
	}
	if kind == "ConfigMap" {
		if strings.HasPrefix(name, "kube-root-ca.crt") {
			return true
		}
	}
	return false
}

// --- helpers ---

func getObjectMeta(obj any) *metav1.ObjectMeta {
	switch x := obj.(type) {
	case *appsv1.Deployment:
		return &x.ObjectMeta
	case *appsv1.StatefulSet:
		return &x.ObjectMeta
	case *appsv1.DaemonSet:
		return &x.ObjectMeta
	case *corev1.Pod:
		return &x.ObjectMeta
	case *corev1.ConfigMap:
		return &x.ObjectMeta
	case *corev1.Secret:
		return &x.ObjectMeta
	case cache.DeletedFinalStateUnknown:
		return getObjectMeta(x.Obj)
	}
	return nil
}

// actorFromManagedFields picks the manager whose timestamp is newest.
// Maps the Manager string to either "User" / "ServiceAccount" /
// "Controller" using common-name heuristics.
func actorFromManagedFields(m *metav1.ObjectMeta, now time.Time) (string, string) {
	if len(m.ManagedFields) == 0 {
		return "system", "Controller"
	}
	var newest *metav1.ManagedFieldsEntry
	for i := range m.ManagedFields {
		e := &m.ManagedFields[i]
		if newest == nil || e.Time != nil && newest.Time != nil && e.Time.After(newest.Time.Time) {
			newest = e
		}
	}
	if newest == nil {
		return "unknown", "Controller"
	}
	mgr := newest.Manager
	atype := classifyManager(mgr)
	return mgr, atype
}

func classifyManager(mgr string) string {
	low := strings.ToLower(mgr)
	switch {
	case strings.HasPrefix(low, "kube-controller-manager"),
		strings.HasPrefix(low, "kube-scheduler"),
		strings.HasPrefix(low, "deployment-controller"),
		strings.HasPrefix(low, "replicaset-controller"),
		strings.HasPrefix(low, "kubelet"),
		strings.HasPrefix(low, "k3s"):
		return "Controller"
	case strings.HasPrefix(low, "system:"),
		strings.HasPrefix(low, "kube-"),
		strings.Contains(low, "operator"):
		return "Controller"
	case strings.HasPrefix(low, "kubectl"),
		strings.HasPrefix(low, "okteto"),
		strings.HasPrefix(low, "argocd"),
		strings.HasPrefix(low, "flux"),
		strings.HasPrefix(low, "helm"),
		strings.HasPrefix(low, "terraform"):
		return "User" // human-initiated tooling
	case strings.Contains(low, "controller"):
		return "Controller"
	}
	return "User"
}

// changedFields returns the top-level field paths that differ between
// two object versions. Cheap heuristic: compare the FieldsV1 sets in
// the most recent managedFields entry on each side.
func changedFields(prev, cur *metav1.ObjectMeta) []string {
	if cur == nil || len(cur.ManagedFields) == 0 {
		return nil
	}
	// Pick the cur side's newest entry.
	var newest *metav1.ManagedFieldsEntry
	for i := range cur.ManagedFields {
		e := &cur.ManagedFields[i]
		if e.FieldsV1 == nil {
			continue
		}
		if newest == nil || (e.Time != nil && newest.Time != nil && e.Time.After(newest.Time.Time)) {
			newest = e
		}
	}
	if newest == nil || newest.FieldsV1 == nil {
		return nil
	}
	// FieldsV1 is opaque JSON — extract the top-level keys it touches.
	raw := newest.FieldsV1.Raw
	keys := topLevelFieldKeys(raw)
	return keys
}

// topLevelFieldKeys parses the FieldsV1 JSON well enough to surface the
// `f:spec`, `f:metadata`, etc. it touched. Doesn't try to descend.
func topLevelFieldKeys(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	s := string(raw)
	out := []string{}
	for {
		i := strings.Index(s, `"f:`)
		if i < 0 {
			break
		}
		s = s[i+3:]
		j := strings.Index(s, `"`)
		if j < 0 {
			break
		}
		k := s[:j]
		// Only collect first-level keys (no `.` indicates top-level).
		if !strings.Contains(k, "/") {
			if !contains(out, k) {
				out = append(out, k)
			}
		}
		s = s[j+1:]
	}
	return out
}

// riskFor labels the operation's blast-radius.
func riskFor(kind string, fields []string) string {
	for _, f := range fields {
		if f == "spec" {
			switch kind {
			case "Deployment", "StatefulSet", "DaemonSet":
				return "high"
			case "Secret":
				return "high"
			case "ConfigMap":
				return "medium"
			}
		}
		if f == "data" {
			switch kind {
			case "Secret":
				return "high"
			case "ConfigMap":
				return "medium"
			}
		}
	}
	return "info"
}
