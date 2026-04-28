// Pod and rollout caches, populated by shared informers.
//
// PodCache answers "given a (namespace, pod-name) what workload is it
// part of, and what image/digest is it running?" — needed to enrich raw
// log lines from the tailer with workload identity.
//
// RolloutCache answers "when did this workload last roll out, with what
// image and (when available) commit SHA?" — feeds the RCA engine.
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
}

// Rollout is what we expose to the RCA engine.
type Rollout struct {
	When   time.Time
	Image  string
	Digest string
	Commit string // from container image label org.opencontainers.image.revision when known
}

// Cache aggregates pod and rollout state.
type Cache struct {
	mu       sync.RWMutex
	pods     map[podKey]PodMeta              // (ns, pod) → metadata
	rollouts map[types.Workload]Rollout      // most recent rollout per workload
	owners   map[ownerRef]ownerRef           // ReplicaSet → Deployment owner (resolved once)
	logger   *slog.Logger
}

type podKey struct{ ns, name string }
type ownerRef struct{ kind, ns, name string }

// Run starts shared informers for Pods and ReplicaSets and blocks until
// ctx is cancelled. Both informers populate this Cache.
func (c *Cache) Run(ctx context.Context, cs kubernetes.Interface, resync time.Duration) error {
	if c.logger == nil {
		c.logger = slog.Default()
	}
	factory := informers.NewSharedInformerFactory(cs, resync)

	podInformer := factory.Core().V1().Pods().Informer()
	rsInformer := factory.Apps().V1().ReplicaSets().Informer()

	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onPodAdd,
		UpdateFunc: func(_, obj any) { c.onPodAdd(obj) },
		DeleteFunc: c.onPodDelete,
	})
	_, _ = rsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onRSAdd,
		UpdateFunc: func(_, obj any) { c.onRSAdd(obj) },
	})

	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced, rsInformer.HasSynced) {
		return ctx.Err()
	}
	c.logger.Info("k8s informers synced",
		"pods", len(podInformer.GetStore().List()),
		"replicasets", len(rsInformer.GetStore().List()),
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
		owners:   map[ownerRef]ownerRef{},
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
	}
	if len(p.Spec.Containers) > 0 {
		meta.Image = p.Spec.Containers[0].Image
	}
	for _, st := range p.Status.ContainerStatuses {
		if st.ImageID != "" {
			meta.ImageDigest = extractDigest(st.ImageID)
			break
		}
	}
	owner := topOwner(p.OwnerReferences)
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
	owner := topOwner(rs.OwnerReferences)
	wl := types.Workload{
		Namespace: rs.Namespace,
		Kind:      owner.kind,
		Name:      owner.name,
	}
	if wl.Name == "" {
		wl.Kind = "ReplicaSet"
		wl.Name = rs.Name
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

// topOwner returns the most informative owner reference: prefer
// Deployment over ReplicaSet (we don't follow RS→Deployment resolution
// from owner refs alone — the ReplicaSet handler already records the
// Deployment-level rollout).
func topOwner(refs []metav1.OwnerReference) ownerRef {
	for _, r := range refs {
		if r.Kind == "Deployment" || r.Kind == "StatefulSet" || r.Kind == "DaemonSet" || r.Kind == "Job" || r.Kind == "CronJob" {
			return ownerRef{kind: r.Kind, name: r.Name}
		}
	}
	for _, r := range refs {
		if r.Kind == "ReplicaSet" {
			// Fall back to the RS itself; the rollout cache uses the
			// ReplicaSet's own owner (a Deployment) when present.
			return ownerRef{kind: r.Kind, name: r.Name}
		}
	}
	return ownerRef{}
}

// extractDigest pulls the sha256 part out of a container image ID, which
// is typically of the form "registry/repo@sha256:abc..." or
// "docker-pullable://registry/repo@sha256:abc...".
func extractDigest(imageID string) string {
	const sep = "@"
	for i := len(imageID) - 1; i >= 0; i-- {
		if imageID[i] == sep[0] {
			return imageID[i+1:]
		}
	}
	return ""
}
