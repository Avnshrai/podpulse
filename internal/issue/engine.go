// Issue engine: continuously turns the raw signal streams (ConfigMap
// diffs, K8s events, log anomalies) into ranked Issue records and
// computes the "what changed before this" timeline that every Issue
// carries.
package issue

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/podpulse/podpulse/internal/anomaly"
	"github.com/podpulse/podpulse/internal/k8s"
	"github.com/podpulse/podpulse/internal/types"
)

// Engine maintains the live set of Issues. It pulls from the K8s
// watchers and the existing anomaly store on every tick.
type Engine struct {
	mu sync.RWMutex
	all map[string]*Issue // id → issue

	cw *k8s.ConfigWatcher
	ew *k8s.EventWatcher
	cache *k8s.Cache
	store *anomaly.Store

	dedupWindow time.Duration
	maxItems    int
}

func NewEngine(cw *k8s.ConfigWatcher, ew *k8s.EventWatcher, cache *k8s.Cache, store *anomaly.Store) *Engine {
	return &Engine{
		all:         map[string]*Issue{},
		cw:          cw,
		ew:          ew,
		cache:       cache,
		store:       store,
		dedupWindow: 15 * time.Minute,
		maxItems:    2000,
	}
}

// Refresh recomputes the Issue list from current signal sources.
// Called on a 5-second tick by the detector main loop.
func (e *Engine) Refresh() {
	now := time.Now()

	// 1. Surface ConfigIssues from recent config diffs.
	if e.cw != nil {
		for _, c := range e.cw.RecentChanges(200) {
			if !isInteresting(c) {
				continue
			}
			id := configIssueID(c)
			e.mu.Lock()
			cur, exists := e.all[id]
			e.mu.Unlock()
			if exists && now.Sub(cur.UpdatedAt) < e.dedupWindow {
				continue
			}
			iss := buildConfigIssue(c, now)
			e.attachTimeline(iss, now)
			e.attachConfigFixSteps(iss)
			e.put(iss)
		}
	}

	// 2. Surface CrashLoop / Scheduling Issues from K8s events.
	if e.ew != nil {
		windowStart := now.Add(-15 * time.Minute)
		for _, ev := range e.ew.Recent(200, "", windowStart, "") {
			iss := buildEventIssue(ev, now, e.cache)
			if iss == nil {
				continue
			}
			id := iss.ID
			e.mu.Lock()
			cur, exists := e.all[id]
			e.mu.Unlock()
			if exists && now.Sub(cur.UpdatedAt) < e.dedupWindow {
				// Just bump the count.
				cur.UpdatedAt = ev.LastSeen
				continue
			}
			e.attachTimeline(iss, now)
			e.attachEventFixSteps(iss, ev)
			e.put(iss)
		}
	}

	// 3. Mirror the existing anomaly store entries as TypeLogAnomaly
	//    Issues so the dashboard's single Issues list is complete.
	if e.store != nil {
		for _, a := range e.store.All() {
			id := "log:" + a.ID
			e.mu.RLock()
			_, exists := e.all[id]
			e.mu.RUnlock()
			if exists {
				continue
			}
			iss := logAnomalyToIssue(a, id)
			e.attachTimeline(iss, now)
			e.attachLogFixSteps(iss, a)
			e.put(iss)
		}
	}

	// 4. GC: drop issues older than 6h.
	cutoff := now.Add(-6 * time.Hour)
	e.mu.Lock()
	for id, iss := range e.all {
		if iss.UpdatedAt.Before(cutoff) {
			delete(e.all, id)
		}
	}
	if len(e.all) > e.maxItems {
		// Keep most-recent maxItems.
		list := make([]*Issue, 0, len(e.all))
		for _, x := range e.all {
			list = append(list, x)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].UpdatedAt.After(list[j].UpdatedAt) })
		for _, x := range list[e.maxItems:] {
			delete(e.all, x.ID)
		}
	}
	e.mu.Unlock()
}

func (e *Engine) put(iss *Issue) {
	if iss == nil || iss.ID == "" {
		return
	}
	e.mu.Lock()
	e.all[iss.ID] = iss
	e.mu.Unlock()
}

// All returns every live Issue, newest first.
func (e *Engine) All() []*Issue {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Issue, 0, len(e.all))
	for _, iss := range e.all {
		out = append(out, iss)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

// Get returns one Issue by ID.
func (e *Engine) Get(id string) (*Issue, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	iss, ok := e.all[id]
	return iss, ok
}

// SetState transitions an Issue's State.
func (e *Engine) SetState(id, state string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	iss, ok := e.all[id]
	if !ok {
		return false
	}
	iss.State = state
	iss.UpdatedAt = time.Now()
	return true
}

// --- ConfigIssue construction ---

// isInteresting filters out noise — we only surface diffs that look
// like they could break a workload.
func isInteresting(c k8s.ConfigChange) bool {
	for _, ch := range c.Changes {
		switch ch.Type {
		case k8s.ChangeBecameEmpty, k8s.ChangeMalformedJSON, k8s.ChangeRemoved:
			return true
		}
	}
	// A plain value-change is interesting only if the workload has
	// pods restarting recently — but that crossover happens upstream
	// in the engine's "what changed" join, so for now we surface
	// every diff but rank value_changed lower.
	return true
}

func configIssueID(c k8s.ConfigChange) string {
	return fmt.Sprintf("cfg:%s/%s/%s/%d", c.Kind, c.Namespace, c.Name, c.When.Unix())
}

func buildConfigIssue(c k8s.ConfigChange, now time.Time) *Issue {
	iss := &Issue{
		ID:        configIssueID(c),
		Type:      TypeConfigIssue,
		FiredAt:   c.When,
		UpdatedAt: now,
		State:     "active",
		Workload: types.Workload{
			Namespace: c.Namespace,
			Kind:      string(c.Kind),
			Name:      c.Name,
		},
		ConfigIssue: &ConfigIssueBody{
			Kind: c.Kind, Name: c.Name, Changes: c.Changes, Mounts: c.MountedBy,
		},
		AffectedPods: len(c.MountedBy),
	}

	// Headline + severity from the worst change kind.
	worst := worstChangeType(c.Changes)
	iss.HumanHeadline = configHeadline(c, worst)
	iss.TechnicalHeadline = describeChanges(c.Changes)
	iss.ShortStory = configShortStory(c, worst)
	iss.WhatHappened = configNarrative(c, worst)
	iss.LikelyCause = configCause(worst)
	iss.Severity = configSeverity(worst, len(c.MountedBy))
	iss.Impact = impactFromMounts(len(c.MountedBy))
	iss.Confidence = configConfidence(worst, len(c.MountedBy))
	iss.ConfidenceFactors = configConfidenceFactors(c, worst)
	iss.Urgency = "active"
	return iss
}

func worstChangeType(changes []k8s.KeyChange) k8s.ChangeType {
	rank := map[k8s.ChangeType]int{
		k8s.ChangeMalformedJSON: 4,
		k8s.ChangeBecameEmpty:   3,
		k8s.ChangeRemoved:       2,
		k8s.ChangeValueChanged:  1,
		k8s.ChangeFromEmpty:     1,
		k8s.ChangeAdded:         0,
	}
	worst := k8s.ChangeAdded
	r := -1
	for _, ch := range changes {
		if v := rank[ch.Type]; v > r {
			r = v
			worst = ch.Type
		}
	}
	return worst
}

func configHeadline(c k8s.ConfigChange, worst k8s.ChangeType) string {
	switch worst {
	case k8s.ChangeMalformedJSON:
		return fmt.Sprintf("Malformed value in %s/%s", c.Kind, c.Name)
	case k8s.ChangeBecameEmpty:
		return fmt.Sprintf("Empty config value in %s/%s", c.Kind, c.Name)
	case k8s.ChangeRemoved:
		return fmt.Sprintf("Config key removed from %s/%s", c.Kind, c.Name)
	case k8s.ChangeValueChanged, k8s.ChangeFromEmpty:
		return fmt.Sprintf("Config value changed in %s/%s", c.Kind, c.Name)
	}
	return fmt.Sprintf("Config change in %s/%s", c.Kind, c.Name)
}

func describeChanges(changes []k8s.KeyChange) string {
	if len(changes) == 0 {
		return ""
	}
	var parts []string
	for i, ch := range changes {
		if i >= 3 {
			parts = append(parts, fmt.Sprintf("+%d more", len(changes)-i))
			break
		}
		switch ch.Type {
		case k8s.ChangeBecameEmpty:
			parts = append(parts, ch.Key+" is empty")
		case k8s.ChangeMalformedJSON:
			parts = append(parts, ch.Key+" has invalid JSON")
		case k8s.ChangeRemoved:
			parts = append(parts, ch.Key+" removed")
		case k8s.ChangeValueChanged:
			parts = append(parts, ch.Key+" changed")
		case k8s.ChangeFromEmpty:
			parts = append(parts, ch.Key+" populated")
		case k8s.ChangeAdded:
			parts = append(parts, ch.Key+" added")
		}
	}
	return strings.Join(parts, ", ")
}

func configShortStory(c k8s.ConfigChange, worst k8s.ChangeType) string {
	if len(c.MountedBy) == 0 {
		return fmt.Sprintf("No workloads currently mount this %s.", strings.ToLower(string(c.Kind)))
	}
	first := c.MountedBy[0]
	if len(c.MountedBy) == 1 {
		return fmt.Sprintf("Affecting 1 workload (%s) in %s.", first.OwnerName, first.Namespace)
	}
	return fmt.Sprintf("Affecting %d workloads in %s, including %s.",
		len(c.MountedBy), c.Namespace, first.OwnerName)
}

func configNarrative(c k8s.ConfigChange, worst k8s.ChangeType) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The %s %q was modified at %s. ", c.Kind, c.Name, c.When.Format("3:04 PM"))
	switch worst {
	case k8s.ChangeMalformedJSON:
		b.WriteString("At least one value is no longer valid JSON, which means consumers parsing it will throw at startup. ")
	case k8s.ChangeBecameEmpty:
		b.WriteString("A previously-populated key is now empty. Clients that read this key may fall back to defaults silently. ")
	case k8s.ChangeRemoved:
		b.WriteString("A key was removed. Pods expecting it will see undefined env / missing file. ")
	case k8s.ChangeValueChanged:
		b.WriteString("A value was changed. ")
	}
	if len(c.MountedBy) > 0 {
		b.WriteString(fmt.Sprintf("%d workload(s) mount this — they need to restart to pick up the change.", len(c.MountedBy)))
	}
	return b.String()
}

func configCause(worst k8s.ChangeType) string {
	switch worst {
	case k8s.ChangeMalformedJSON:
		return "An edit to this value left the JSON unparseable."
	case k8s.ChangeBecameEmpty:
		return "A previously-set value was cleared (intentional or accidental)."
	case k8s.ChangeRemoved:
		return "Key was removed; consumers that required it will fail."
	case k8s.ChangeValueChanged:
		return "Value was changed; if it points at infra (URL, host) the new value may be wrong."
	}
	return "Configuration drift."
}

func configSeverity(worst k8s.ChangeType, nMounts int) types.Severity {
	switch {
	case worst == k8s.ChangeMalformedJSON && nMounts > 0:
		return types.SeverityHigh
	case worst == k8s.ChangeBecameEmpty && nMounts > 0:
		return types.SeverityHigh
	case worst == k8s.ChangeRemoved && nMounts > 0:
		return types.SeverityMedium
	case nMounts >= 5:
		return types.SeverityMedium
	}
	return types.SeverityLow
}

func impactFromMounts(n int) types.ImpactLevel {
	switch {
	case n == 0:
		return types.ImpactLow
	case n == 1:
		return types.ImpactLow
	case n <= 3:
		return types.ImpactMedium
	case n <= 10:
		return types.ImpactHigh
	}
	return types.ImpactCritical
}

func configConfidence(worst k8s.ChangeType, nMounts int) int {
	switch worst {
	case k8s.ChangeMalformedJSON:
		return 95
	case k8s.ChangeBecameEmpty:
		return 88
	case k8s.ChangeRemoved:
		return 80
	case k8s.ChangeValueChanged:
		if nMounts > 0 {
			return 65
		}
		return 50
	}
	return 60
}

func configConfidenceFactors(c k8s.ConfigChange, worst k8s.ChangeType) []string {
	out := []string{}
	switch worst {
	case k8s.ChangeMalformedJSON:
		out = append(out, "JSON parser cannot decode the new value — clients will throw at startup")
	case k8s.ChangeBecameEmpty:
		out = append(out, "Key transitioned from a value to empty string")
	case k8s.ChangeRemoved:
		out = append(out, "Key was deleted from the resource")
	case k8s.ChangeValueChanged:
		out = append(out, "Value differs from previous revision")
	}
	if n := len(c.MountedBy); n > 0 {
		out = append(out, fmt.Sprintf("%d workload(s) currently mount this resource", n))
	}
	return out
}

// --- Event-driven Issue construction (CrashLoop / Scheduling) ---

func buildEventIssue(ev k8s.CategorizedEvent, now time.Time, cache *k8s.Cache) *Issue {
	switch ev.Category {
	case k8s.CategoryOOM, k8s.CategoryCrashLoop, k8s.CategoryFailedMount,
		k8s.CategoryUnhealthy, k8s.CategoryImagePull:
		// fall through
	case k8s.CategoryUnscheduled:
		return buildSchedulingIssue(ev, now, cache)
	default:
		return nil
	}

	wl := podWorkload(cache, ev.Namespace, ev.Pod)
	id := fmt.Sprintf("evt:%s/%s/%s/%s", ev.Namespace, ev.Pod, ev.Reason, ev.LastSeen.Truncate(time.Minute).Format("150405"))

	iss := &Issue{
		ID:        id,
		Type:      TypeCrashLoop,
		FiredAt:   ev.LastSeen,
		UpdatedAt: now,
		State:     "active",
		Workload:  wl,
		Pod:       ev.Pod,
		AffectedPods: 1,
		CrashLoop: &CrashLoopBody{
			Reason: ev.Reason, Restarts: ev.Count,
			LastEvent: ev.Message, Category: ev.Category,
		},
	}

	switch ev.Category {
	case k8s.CategoryOOM:
		iss.HumanHeadline = "Out-of-memory kill in " + wl.Name
		iss.TechnicalHeadline = "Container exceeded memory limit and was killed"
		iss.ShortStory = "1 pod hit its memory limit and was OOM-killed."
		iss.WhatHappened = "The pod's working-set memory crossed the container's resources.limits.memory boundary. The kernel OOM killer terminated the container; kubelet restarted it."
		iss.LikelyCause = "Memory limit too low for the workload's working set, or a memory leak in the latest version."
		iss.Severity = types.SeverityHigh
		iss.Confidence = 95
	case k8s.CategoryCrashLoop:
		iss.HumanHeadline = "Crash loop in " + wl.Name
		iss.TechnicalHeadline = "Container is restarting repeatedly"
		iss.ShortStory = fmt.Sprintf("Pod %s has restarted %d times in this window.", ev.Pod, ev.Count)
		iss.WhatHappened = "The container exits non-zero and is restarted by kubelet, exits again, and so on. The cause is in the previous container's logs."
		iss.LikelyCause = "Startup error: missing config, dependency unreachable, or panic on boot."
		iss.Severity = types.SeverityHigh
		iss.Confidence = 92
	case k8s.CategoryFailedMount:
		iss.HumanHeadline = "Failed to mount config/secret in " + wl.Name
		iss.TechnicalHeadline = "kubelet cannot mount a referenced ConfigMap or Secret"
		iss.ShortStory = "Pod is stuck waiting for a volume that doesn't exist or can't be attached."
		iss.WhatHappened = "Pod spec references a ConfigMap/Secret/PVC that is missing, deleted, or has the wrong key. Pod will not start until this is fixed."
		iss.LikelyCause = "ConfigMap or Secret named in spec.volumes was deleted, renamed, or never created."
		iss.Severity = types.SeverityHigh
		iss.Confidence = 95
	case k8s.CategoryUnhealthy:
		iss.HumanHeadline = "Probe failures in " + wl.Name
		iss.TechnicalHeadline = "Liveness or readiness probe is failing"
		iss.ShortStory = ev.Message
		iss.LikelyCause = "Application not responding on probe endpoint, or probe path/port misconfigured."
		iss.Severity = types.SeverityMedium
		iss.Confidence = 80
	case k8s.CategoryImagePull:
		iss.HumanHeadline = "Image pull failure in " + wl.Name
		iss.TechnicalHeadline = "Cannot pull container image"
		iss.ShortStory = ev.Message
		iss.LikelyCause = "Image name typo, missing tag, or imagePullSecret expired/invalid."
		iss.Severity = types.SeverityHigh
		iss.Confidence = 95
	}

	iss.Impact = types.ImpactLow
	if ev.Count >= 5 {
		iss.Impact = types.ImpactMedium
	}
	if ev.Count >= 20 {
		iss.Impact = types.ImpactHigh
	}
	iss.Urgency = "active"
	if ev.Count > 10 {
		iss.Urgency = "worsening"
	}
	return iss
}

func buildSchedulingIssue(ev k8s.CategorizedEvent, now time.Time, cache *k8s.Cache) *Issue {
	wl := podWorkload(cache, ev.Namespace, ev.Pod)
	id := fmt.Sprintf("sch:%s/%s/%s", ev.Namespace, ev.Pod, ev.LastSeen.Truncate(time.Minute).Format("150405"))
	return &Issue{
		ID:        id,
		Type:      TypeScheduling,
		FiredAt:   ev.LastSeen,
		UpdatedAt: now,
		State:     "active",
		Workload:  wl,
		Pod:       ev.Pod,
		HumanHeadline:     "Pod cannot be scheduled in " + wl.Name,
		TechnicalHeadline: "Scheduler cannot place this pod",
		ShortStory:        ev.Message,
		WhatHappened:      "The kube-scheduler was unable to find a node that satisfies the pod's resource requests, taints/tolerations, affinity, or topology constraints.",
		LikelyCause:       "Cluster lacks a node with sufficient CPU/memory, or pod has incompatible nodeSelector / taints.",
		Severity:          types.SeverityHigh,
		Impact:            types.ImpactMedium,
		Confidence:        95,
		AffectedPods:      1,
		Scheduling:        &SchedulingBody{Reason: ev.Reason, Message: ev.Message},
	}
}

func podWorkload(cache *k8s.Cache, ns, pod string) types.Workload {
	if cache == nil {
		return types.Workload{Namespace: ns, Kind: "Pod", Name: pod}
	}
	if m, ok := cache.LookupPod(ns, pod); ok && m.OwnerName != "" {
		return types.Workload{Namespace: ns, Kind: m.OwnerKind, Name: m.OwnerName}
	}
	return types.Workload{Namespace: ns, Kind: "Pod", Name: pod}
}

// --- Log anomaly mirror ---

func logAnomalyToIssue(a *anomaly.Stored, id string) *Issue {
	iss := &Issue{
		ID:                id,
		Type:              TypeLogAnomaly,
		Severity:          a.Severity,
		Impact:            a.Impact,
		State:             string(a.State),
		FiredAt:           a.FiredAt,
		UpdatedAt:         a.UpdatedAt,
		HumanHeadline:     a.HumanHeadline,
		TechnicalHeadline: a.TechnicalHeadline,
		ShortStory:        a.ShortStory,
		WhatHappened:      a.WhatHappened,
		LikelyCause:       a.LikelyCause,
		Confidence:        a.Confidence,
		ConfidenceFactors: a.ConfidenceFactors,
		Urgency:           a.Urgency,
		Workload:          a.Workload,
		AffectedPods:      a.AffectedPods,
		LogAnomaly: &LogAnomalyBody{
			Template:           a.Template,
			Sample:             a.Sample,
			Variants:           a.Variants,
			FirstSeenInVersion: a.FirstSeenInVersion,
			Image:              a.Image,
			ImageDigest:        a.ImageDigest,
			BeforeAfter:        a.BeforeAfter,
		},
	}
	if iss.HumanHeadline == "" {
		iss.HumanHeadline = a.Headline
	}
	if iss.UpdatedAt.IsZero() {
		iss.UpdatedAt = iss.FiredAt
	}
	return iss
}

// --- Timeline + suggested fix ---

// attachTimeline pulls the "what changed in the last hour" slice for
// the issue's namespace: deployments, configmap diffs, and (for
// log anomalies) the first-error point.
func (e *Engine) attachTimeline(iss *Issue, now time.Time) {
	since := iss.FiredAt.Add(-1 * time.Hour)
	tl := []TimelineEvent{}

	// Recent deployments for this workload.
	if e.cache != nil {
		r := e.cache.RecentRollout(iss.Workload)
		if !r.When.IsZero() && !r.When.Before(since) {
			label := "Deployment rolled out"
			detail := r.Image
			if r.Commit != "" {
				detail += " · commit " + shortSHA(r.Commit)
			}
			tl = append(tl, TimelineEvent{When: r.When, Kind: "deploy", Label: label, Detail: detail})
		}
	}
	// Recent config changes in same namespace.
	if e.cw != nil {
		for _, c := range e.cw.ChangesForNamespace(iss.Workload.Namespace, since) {
			lbl := string(c.Kind) + " " + c.Name + " changed"
			detail := describeChanges(c.Changes)
			tl = append(tl, TimelineEvent{When: c.When, Kind: "config_change", Label: lbl, Detail: detail})
		}
	}
	// The error/event itself.
	switch iss.Type {
	case TypeLogAnomaly:
		tl = append(tl, TimelineEvent{When: iss.FiredAt, Kind: "error_observed", Label: "First error observed"})
	case TypeConfigIssue:
		tl = append(tl, TimelineEvent{When: iss.FiredAt, Kind: "config_change", Label: "This config issue detected"})
	default:
		tl = append(tl, TimelineEvent{When: iss.FiredAt, Kind: "event", Label: "K8s event observed: " + safeReason(iss)})
	}
	sort.Slice(tl, func(i, j int) bool { return tl[i].When.Before(tl[j].When) })
	iss.Timeline = tl
}

func safeReason(iss *Issue) string {
	if iss.CrashLoop != nil {
		return iss.CrashLoop.Reason
	}
	if iss.Scheduling != nil {
		return iss.Scheduling.Reason
	}
	return "unknown"
}

func shortSHA(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

// --- Suggested fix builders ---

func (e *Engine) attachConfigFixSteps(iss *Issue) {
	if iss.ConfigIssue == nil {
		return
	}
	c := iss.ConfigIssue
	steps := []FixStep{}

	// Step 1: show the offending values inline.
	bullets := []string{}
	for _, ch := range c.Changes {
		switch ch.Type {
		case k8s.ChangeBecameEmpty:
			bullets = append(bullets, fmt.Sprintf("• %s — was %q, now empty", ch.Key, truncate(ch.OldValue, 60)))
		case k8s.ChangeMalformedJSON:
			bullets = append(bullets, fmt.Sprintf("• %s — %s", ch.Key, ch.Note))
		case k8s.ChangeRemoved:
			bullets = append(bullets, fmt.Sprintf("• %s — removed (was %q)", ch.Key, truncate(ch.OldValue, 60)))
		case k8s.ChangeValueChanged:
			bullets = append(bullets, fmt.Sprintf("• %s — %q → %q", ch.Key, truncate(ch.OldValue, 40), truncate(ch.NewValue, 40)))
		}
	}
	if len(bullets) > 0 {
		steps = append(steps, FixStep{
			Title:  "Review the offending keys",
			Answer: strings.Join(bullets, "\n"),
			Why:    "These are the keys that changed. The bullet that's empty/malformed is almost certainly the cause.",
		})
	}

	// Step 2: show which workloads will need a restart.
	if len(c.Mounts) > 0 {
		var b strings.Builder
		for i, m := range c.Mounts {
			if i >= 5 {
				fmt.Fprintf(&b, "+%d more\n", len(c.Mounts)-i)
				break
			}
			fmt.Fprintf(&b, "• %s/%s\n", m.OwnerKind, m.OwnerName)
		}
		steps = append(steps, FixStep{
			Title:  "Pods that mount this resource",
			Answer: strings.TrimSpace(b.String()),
			Why:    "Pods don't pick up ConfigMap/Secret changes automatically — they need a restart after you fix the value.",
		})
	}

	// Step 3: how to fix it.
	steps = append(steps, FixStep{
		Title:   "Edit the resource",
		Command: fmt.Sprintf("kubectl edit %s %s -n %s", strings.ToLower(string(c.Kind)), c.Name, iss.Workload.Namespace),
		Why:     "Edit the value directly, or update the upstream source (Helm values, ArgoCD app, secret store) and re-sync.",
	})

	// Step 4: roll the dependent workloads.
	if len(c.Mounts) > 0 {
		first := c.Mounts[0]
		steps = append(steps, FixStep{
			Title:   "Restart the dependent workload after fixing",
			Command: fmt.Sprintf("kubectl rollout restart %s/%s -n %s",
				strings.ToLower(first.OwnerKind), first.OwnerName, first.Namespace),
			Why: "ConfigMap/Secret changes require a pod restart for env vars; volume mounts pick up updates after restart.",
		})
	}
	iss.SuggestedFix = steps
}

func (e *Engine) attachEventFixSteps(iss *Issue, ev k8s.CategorizedEvent) {
	steps := []FixStep{}
	switch ev.Category {
	case k8s.CategoryOOM:
		steps = append(steps,
			FixStep{Title: "Check current memory usage",
				Command: fmt.Sprintf("kubectl top pod -n %s -l app=%s", ev.Namespace, iss.Workload.Name),
				Why:     "If the pod is consistently near limit, raise resources.limits.memory."},
			FixStep{Title: "Read the previous container's last logs",
				Command: fmt.Sprintf("kubectl logs -n %s %s --previous --tail=200", ev.Namespace, ev.Pod),
				Why:     "OOM-killed containers often log the operation that allocated the spike."},
			FixStep{Title: "Bump memory limit",
				Command: "Edit deployment spec: resources.limits.memory: '<new>Mi'",
				Why:     "If the working set is genuinely larger, the limit must accommodate it."},
		)
	case k8s.CategoryCrashLoop:
		steps = append(steps,
			FixStep{Title: "Read the previous container's logs",
				Command: fmt.Sprintf("kubectl logs -n %s %s --previous --tail=200", ev.Namespace, ev.Pod),
				Why:     "The death cause is in the previous-instance log buffer."},
			FixStep{Title: "Inspect pod status",
				Command: fmt.Sprintf("kubectl describe pod %s -n %s", ev.Pod, ev.Namespace),
				Why:     "ExitCode and reason are surfaced in containerStatuses."},
		)
	case k8s.CategoryFailedMount:
		steps = append(steps,
			FixStep{Title: "Inspect the pod's referenced volumes",
				Command: fmt.Sprintf("kubectl get pod %s -n %s -o yaml | grep -A4 volumes:", ev.Pod, ev.Namespace),
				Why:     "Find the ConfigMap/Secret/PVC name the pod expects."},
			FixStep{Title: "Verify the resource exists",
				Command: fmt.Sprintf("kubectl get configmap,secret,pvc -n %s", ev.Namespace),
				Why:     "FailedMount means the named resource is missing or unreachable."},
		)
	case k8s.CategoryImagePull:
		steps = append(steps,
			FixStep{Title: "See the exact registry error",
				Command: fmt.Sprintf("kubectl describe pod %s -n %s | tail -20", ev.Pod, ev.Namespace),
				Why:     "Events on the pod include the registry's response (manifest unknown, unauthorized, etc.)."},
			FixStep{Title: "Check imagePullSecrets",
				Command: fmt.Sprintf("kubectl get sa -n %s -o yaml | grep imagePullSecrets -A2", ev.Namespace),
				Why:     "If the registry token rotated, the pod can't authenticate."},
		)
	case k8s.CategoryUnhealthy:
		steps = append(steps,
			FixStep{Title: "Try the probe endpoint manually",
				Command: fmt.Sprintf("kubectl exec -n %s %s -- wget -O- http://localhost:<probe-port><probe-path>", ev.Namespace, ev.Pod),
				Why:     "Confirms whether the app is responding on the probe path/port at all."},
		)
	}
	iss.SuggestedFix = steps
}

func (e *Engine) attachLogFixSteps(iss *Issue, a *anomaly.Stored) {
	if a == nil {
		return
	}
	steps := []FixStep{}
	for _, s := range a.Suggestions {
		steps = append(steps, FixStep{Title: s.Title, Command: s.Command, Why: s.Why})
	}
	iss.SuggestedFix = steps
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
