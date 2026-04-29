// K8s Events watcher with reason categorization.
//
// Half of K8s production incidents leave both a log line and an event.
// PodPulse joins them: when an OOMKilled event fires, we don't show it
// as an isolated row in an "Events" tab — we surface it as a
// "Crash loop detected" issue with a memory-pressure narrative.
package k8s

import (
	"context"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// EventCategory groups the K8s event reasons we care about.
type EventCategory string

const (
	CategoryOOM           EventCategory = "oom"           // OOMKilled
	CategoryCrashLoop     EventCategory = "crash_loop"    // BackOff
	CategoryFailedMount   EventCategory = "failed_mount"  // FailedMount, FailedAttachVolume
	CategoryUnscheduled   EventCategory = "unscheduled"   // FailedScheduling
	CategoryUnhealthy     EventCategory = "unhealthy"     // Unhealthy probes
	CategoryImagePull     EventCategory = "image_pull"    // Failed (image pull)
	CategoryEvicted       EventCategory = "evicted"       // Evicted
	CategoryNodeIssue     EventCategory = "node_issue"    // NodeNotReady, etc.
	CategoryOther         EventCategory = "other"
)

// CategorizedEvent is one K8s event with a normalized category.
type CategorizedEvent struct {
	When      time.Time     `json:"when"`
	LastSeen  time.Time     `json:"last_seen"`
	Count     int32         `json:"count"`
	Type      string        `json:"type"`     // Normal | Warning
	Reason    string        `json:"reason"`
	Message   string        `json:"message"`
	Namespace string        `json:"namespace"`
	Object    string        `json:"object"`   // kind/name (e.g. Pod/foo-abc)
	Pod       string        `json:"pod,omitempty"`
	Node      string        `json:"node,omitempty"`
	Category  EventCategory `json:"category"`
}

// EventWatcher tracks recent Warning events.
type EventWatcher struct {
	mu      sync.RWMutex
	recent  []CategorizedEvent // ring buffer, newest at end
	maxItems int
	logger  *slog.Logger
}

func NewEventWatcher(logger *slog.Logger) *EventWatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &EventWatcher{maxItems: 1000, logger: logger}
}

func (w *EventWatcher) Run(ctx context.Context, cs kubernetes.Interface, resync time.Duration) error {
	factory := informers.NewSharedInformerFactory(cs, resync)
	inf := factory.Core().V1().Events().Informer()
	_, _ = inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    w.onEvent,
		UpdateFunc: func(_, o any) { w.onEvent(o) },
	})
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return ctx.Err()
	}
	w.logger.Info("event watcher synced", "events", len(inf.GetStore().List()))
	<-ctx.Done()
	return ctx.Err()
}

// Recent returns the N most recent events newest-first, optionally
// filtered by category and time window.
func (w *EventWatcher) Recent(limit int, category EventCategory, since time.Time, namespace string) []CategorizedEvent {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	out := make([]CategorizedEvent, 0, limit)
	for i := len(w.recent) - 1; i >= 0 && len(out) < limit; i-- {
		e := w.recent[i]
		if !since.IsZero() && e.LastSeen.Before(since) {
			continue
		}
		if category != "" && e.Category != category {
			continue
		}
		if namespace != "" && e.Namespace != namespace {
			continue
		}
		out = append(out, e)
	}
	return out
}

// EventsForPod returns recent events touching a specific pod.
func (w *EventWatcher) EventsForPod(ns, pod string, since time.Time) []CategorizedEvent {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := []CategorizedEvent{}
	for _, e := range w.recent {
		if e.Namespace != ns {
			continue
		}
		if e.Pod != pod {
			continue
		}
		if !since.IsZero() && e.LastSeen.Before(since) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (w *EventWatcher) onEvent(obj any) {
	ev, ok := obj.(*corev1.Event)
	if !ok {
		return
	}
	// Skip Normal events — too noisy and rarely actionable.
	if ev.Type != corev1.EventTypeWarning {
		return
	}
	cat := categorize(ev.Reason, ev.Message)
	c := CategorizedEvent{
		When:      ev.FirstTimestamp.Time,
		LastSeen:  ev.LastTimestamp.Time,
		Count:     ev.Count,
		Type:      ev.Type,
		Reason:    ev.Reason,
		Message:   ev.Message,
		Namespace: ev.InvolvedObject.Namespace,
		Object:    ev.InvolvedObject.Kind + "/" + ev.InvolvedObject.Name,
		Category:  cat,
	}
	if c.LastSeen.IsZero() {
		c.LastSeen = c.When
	}
	if c.LastSeen.IsZero() {
		c.LastSeen = ev.EventTime.Time
	}
	if c.LastSeen.IsZero() {
		c.LastSeen = time.Now()
	}
	if ev.InvolvedObject.Kind == "Pod" {
		c.Pod = ev.InvolvedObject.Name
	}
	c.Node = ev.Source.Host

	w.mu.Lock()
	if len(w.recent) >= w.maxItems {
		w.recent = w.recent[1:]
	}
	w.recent = append(w.recent, c)
	w.mu.Unlock()
}

// categorize maps a K8s event Reason to one of our buckets.
func categorize(reason, msg string) EventCategory {
	switch reason {
	case "OOMKilling", "OOMKilled":
		return CategoryOOM
	case "BackOff", "CrashLoopBackOff":
		return CategoryCrashLoop
	case "FailedMount", "FailedAttachVolume", "VolumeFailedMount":
		return CategoryFailedMount
	case "FailedScheduling":
		return CategoryUnscheduled
	case "Unhealthy", "ProbeWarning":
		return CategoryUnhealthy
	case "Failed", "ErrImagePull", "ImagePullBackOff", "ImageInspectError":
		return CategoryImagePull
	case "Evicted", "ExceededGracePeriod":
		return CategoryEvicted
	case "NodeNotReady", "NodeNotSchedulable", "NodeUnschedulable":
		return CategoryNodeIssue
	}
	return CategoryOther
}
