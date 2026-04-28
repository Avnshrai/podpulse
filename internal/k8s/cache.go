// Pod / ReplicaSet / Service caches, populated by shared informers.
//
// PodCache answers "given a (namespace, pod-name) what *Deployment-level*
// workload is it part of, and what image/digest is it running?" — needed
// to enrich raw log lines from the tailer with workload identity.
//
// RolloutCache answers "when did this workload last roll out, with what
// image and (when available) commit SHA?" — feeds the RCA engine and the
// "Recent deployments" sidebar.
package k8s

import (
	"context"
	"log/slog"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/podpulse/podpulse/internal/types"
)

// PodMeta is the per-pod information we extract via informers.
type PodMeta struct {
	Namespace   string
	OwnerKind   string // Deployment, StatefulSet, DaemonSet, Job, ReplicaSet (orphan), or empty
	OwnerName   string
	PodName     string
	Image       string
	ImageDigest string
	Node        string
	Phase       string // Running, Pending, ...
	Restarts    int32  // sum across containers
}

// Rollout is what we expose to the RCA engine and the dashboard.
type Rollout struct {
	When   time.Time
	Image  string
	Digest string
	Commit string // from org.opencontainers.image.revision when known
}

// ServiceMeta is what the dashboard's Services page lists.
type ServiceMeta struct {
	Namespace string
	Name      string
	Type      string
	ClusterIP string
	Ports     []string
	Selector  map[string]string
}

// Cache aggregates all informer-derived state.
type Cache struct {
	mu       sync.RWMutex
	pods     map[podKey]PodMeta            // (ns, pod) → metadata
	rollouts map[types.Workload]Rollout    // most recent rollout per workload
	rsOwners map[podKey]ownerRef           // (ns, ReplicaSet name) → owning Deployment
	services map[podKey]ServiceMeta        // (ns, svc-name) → metadata
	logger   *slog.Logger
}

type podKey struct{ ns, name string }
type ownerRef struct{ kind, name string }

// Run starts shared informers for Pods, ReplicaSets and Services and
// blocks until ctx is cancelled.
func (c *Cache) Run(ctx context.Context, cs kubernetes.Interface, resync time.Duration) error {
	if c.logger == nil {
		c.logger = slog.Default()
	}
	factory := informers.NewSharedInformerFactory(cs, resync)

	podInformer := factory.Core().V1().Pods().Informer()
	rsInformer := factory.Apps().V1().ReplicaSets().Informer()
	svcInformer := factory.Core().V1().Services().Informer()

	// Important: the RS informer must be registered first so that by
	// the time we process a Pod, its parent ReplicaSet is already in
	// our rsOwners map for the Deployment lookup. We re-walk pods on
	// RS Add anyway as a backstop.
	_, _ = rsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onRSAdd,
		UpdateFunc: func(_, obj any) { c.onRSAdd(obj) },
	})
	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onPodAdd,
		UpdateFunc: func(_, obj any) { c.onPodAdd(obj) },
		DeleteFunc: c.onPodDelete,
	})
	_, _ = svcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onSvcAdd,
		UpdateFunc: func(_, obj any) { c.onSvcAdd(obj) },
		DeleteFunc: c.onSvcDelete,
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(),
		podInformer.HasSynced, rsInformer.HasSynced, svcInformer.HasSynced) {
		return ctx.Err()
	}

	// After sync, re-process all pods so any RS→Deployment resolution
	// that wasn't yet available during their initial Add now resolves.
	for _, obj := range podInformer.GetStore().List() {
		c.onPodAdd(obj)
	}

	c.logger.Info("k8s informers synced",
		"pods", len(podInformer.GetStore().List()),
		"replicasets", len(rsInformer.GetStore().List()),
		"services", len(svcInformer.GetStore().List()),
	)
	<-ctx.Done()
	return ctx.Err()
}

// NewCache returns an empty Cache.
func NewCache(logger *slog.Logger) *Cache {
	if logger == nil {
		logger = slog.Default()
	}
	return &Cache{
		pods:     map[podKey]PodMeta{},
		rollouts: map[types.Workload]Rollout{},
		rsOwners: map[podKey]ownerRef{},
		services: map[podKey]ServiceMeta{},
		logger:   logger,
	}
}

// LookupPod returns metadata for (namespace, pod-name) if it's known.
func (c *Cache) LookupPod(namespace, pod string) (PodMeta, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.pods[podKey{namespace, pod}]
	return m, ok
}

// PodsSnapshot returns a copy of every PodMeta the cache currently holds.
func (c *Cache) PodsSnapshot() []PodMeta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]PodMeta, 0, len(c.pods))
	for _, m := range c.pods {
		out = append(out, m)
	}
	return out
}

// ServicesSnapshot returns a copy of every ServiceMeta in the cache.
func (c *Cache) ServicesSnapshot() []ServiceMeta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ServiceMeta, 0, len(c.services))
	for _, s := range c.services {
		out = append(out, s)
	}
	return out
}

// RolloutsSnapshot returns every (workload, rollout) pair.
func (c *Cache) RolloutsSnapshot() map[types.Workload]Rollout {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[types.Workload]Rollout, len(c.rollouts))
	for k, v := range c.rollouts {
		out[k] = v
	}
	return out
}

// RecentRollout returns the most recent rollout we've observed for the
// workload, or a zero Rollout if none.
func (c *Cache) RecentRollout(w types.Workload) Rollout {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rollouts[w]
}

// --- handlers ---

func (c *Cache) onPodAdd(obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	meta := PodMeta{
		Namespace: p.Namespace,
		PodName:   p.Name,
		Node:      p.Spec.NodeName,
		Phase:     string(p.Status.Phase),
	}
	if len(p.Spec.Containers) > 0 {
		meta.Image = p.Spec.Containers[0].Image
	}
	for _, st := range p.Status.ContainerStatuses {
		if st.ImageID != "" && meta.ImageDigest == "" {
			meta.ImageDigest = extractDigest(st.ImageID)
		}
		meta.Restarts += st.RestartCount
	}

	owner := c.resolveOwner(p.Namespace, p.OwnerReferences)
	meta.OwnerKind = owner.kind
	meta.OwnerName = owner.name

	c.mu.Lock()
	c.pods[podKey{p.Namespace, p.Name}] = meta
	c.mu.Unlock()
}

func (c *Cache) onPodDelete(obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	c.mu.Lock()
	delete(c.pods, podKey{p.Namespace, p.Name})
	c.mu.Unlock()
}

func (c *Cache) onRSAdd(obj any) {
	rs, ok := obj.(*appsv1.ReplicaSet)
	if !ok {
		return
	}
	parent := directOwner(rs.OwnerReferences)

	c.mu.Lock()
	c.rsOwners[podKey{rs.Namespace, rs.Name}] = parent
	c.mu.Unlock()

	wl := types.Workload{Namespace: rs.Namespace, Kind: parent.kind, Name: parent.name}
	if wl.Name == "" {
		// Orphan RS — track it as its own workload.
		wl = types.Workload{Namespace: rs.Namespace, Kind: "ReplicaSet", Name: rs.Name}
	}

	when := rs.CreationTimestamp.Time
	if when.IsZero() {
		return
	}
	var image string
	if len(rs.Spec.Template.Spec.Containers) > 0 {
		image = rs.Spec.Template.Spec.Containers[0].Image
	}
	commit := rs.Spec.Template.Annotations["org.opencontainers.image.revision"]
	if commit == "" {
		commit = rs.Annotations["org.opencontainers.image.revision"]
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.rollouts[wl]; ok && !when.After(existing.When) {
		return
	}
	c.rollouts[wl] = Rollout{When: when, Image: image, Commit: commit}
}

func (c *Cache) onSvcAdd(obj any) {
	s, ok := obj.(*corev1.Service)
	if !ok {
		return
	}
	meta := ServiceMeta{
		Namespace: s.Namespace,
		Name:      s.Name,
		Type:      string(s.Spec.Type),
		ClusterIP: s.Spec.ClusterIP,
		Selector:  s.Spec.Selector,
	}
	for _, p := range s.Spec.Ports {
		port := ""
		if p.Name != "" {
			port = p.Name + ":"
		}
		port += fmtPort(p.Port, p.Protocol)
		meta.Ports = append(meta.Ports, port)
	}
	c.mu.Lock()
	c.services[podKey{s.Namespace, s.Name}] = meta
	c.mu.Unlock()
}

func (c *Cache) onSvcDelete(obj any) {
	s, ok := obj.(*corev1.Service)
	if !ok {
		return
	}
	c.mu.Lock()
	delete(c.services, podKey{s.Namespace, s.Name})
	c.mu.Unlock()
}

// resolveOwner walks the owner-reference chain to find the
// Deployment-level (or top-level controller) workload for a Pod. If the
// pod is owned by a ReplicaSet, we look up the RS in rsOwners to get
// its parent Deployment — which is the user-meaningful workload.
func (c *Cache) resolveOwner(ns string, refs []metav1.OwnerReference) ownerRef {
	for _, r := range refs {
		switch r.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			return ownerRef{kind: r.Kind, name: r.Name}
		}
	}
	// Pods directly owned by a ReplicaSet: hop one level up.
	for _, r := range refs {
		if r.Kind == "ReplicaSet" {
			c.mu.RLock()
			parent, ok := c.rsOwners[podKey{ns, r.Name}]
			c.mu.RUnlock()
			if ok && parent.kind != "" {
				return parent
			}
			return ownerRef{kind: "ReplicaSet", name: r.Name}
		}
	}
	return ownerRef{}
}

// directOwner returns the immediate top-level owner reference, used for
// ReplicaSets resolving their parent Deployment.
func directOwner(refs []metav1.OwnerReference) ownerRef {
	for _, r := range refs {
		switch r.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			return ownerRef{kind: r.Kind, name: r.Name}
		}
	}
	return ownerRef{}
}

func extractDigest(imageID string) string {
	for i := len(imageID) - 1; i >= 0; i-- {
		if imageID[i] == '@' {
			return imageID[i+1:]
		}
	}
	return ""
}

func fmtPort(port int32, proto corev1.Protocol) string {
	p := "TCP"
	if proto != "" {
		p = string(proto)
	}
	out := ""
	out += itoa(int(port))
	out += "/"
	out += p
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
