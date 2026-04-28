// Package templates implements PodPulse's headline anomaly: "new error
// template seen on this workload, first observed under image-digest X."
//
// The warm-up gate is on the workload (not on each (workload, image-
// digest) pair) — otherwise every rollout would reset the warm-up and
// suppress exactly the case we want to detect: a new error appearing
// right after a deploy.
//
// Cold-start gating: even after MinHistory time has passed, we wait
// until at least MinLines lines have been observed for a workload
// before firing. This kills the "first install sees 50 workloads, each
// fires 5 'new template' alerts" flood that otherwise dominates the
// dashboard.
//
// Per-template pod tracking: as more pods of the same workload emit
// the same anomalous template, AffectedPods rises. The api package
// uses this to bump severity on existing anomalies in the store.
package templates

import (
	"fmt"
	"sync"
	"time"

	"github.com/podpulse/podpulse/internal/detect/drain3"
	"github.com/podpulse/podpulse/internal/types"
)

var (
	MinHistory = 5 * time.Minute
	MinLines   = 200
)

type tplKey struct {
	w    types.Workload
	clID int
}

type baseline struct {
	miner      *drain3.Miner
	firstSeen  time.Time
	lines      int
	known      map[int]struct{}
	digestSeen map[int]map[string]struct{} // cluster ID → image-digests where it has appeared
}

// Observation is the side data Observe returns alongside the optional
// Anomaly. The api package uses these to bump pod counts on existing
// anomalies in the store as more pods join the same template.
type Observation struct {
	// MatchedKnown is true if the line matched an existing template
	// (i.e. not a new cluster creation). The api package can use this
	// to bump pod counts on prior anomalies.
	MatchedKnown bool
	// Workload + Template identify the (workload, error pattern) the
	// line belongs to — for bumping prior anomaly pod counts.
	Workload    types.Workload
	Template    string
	ImageDigest string
}

type Detector struct {
	mu        sync.Mutex
	baselines map[types.Workload]*baseline
	// pod-set per (workload, clusterID) over a 30-min rolling window;
	// supports AffectedPods bumping.
	pods map[tplKey]map[string]time.Time
	now  func() time.Time
}

func New() *Detector {
	return &Detector{
		baselines: map[types.Workload]*baseline{},
		pods:      map[tplKey]map[string]time.Time{},
		now:       time.Now,
	}
}

// Observe ingests one line and returns:
//   - an Anomaly if a brand-new template was found AND warm-up + MinLines
//     gates have passed; nil otherwise.
//   - an Observation with workload/template even when no anomaly fires,
//     so callers can update AffectedPods on prior anomalies.
func (d *Detector) Observe(line types.LogLine) (*types.Anomaly, Observation) {
	wl := types.Workload{
		Namespace: line.Namespace,
		Kind:      line.OwnerKind,
		Name:      line.OwnerName,
	}
	if wl.Name == "" {
		wl.Name = line.Pod
	}

	d.mu.Lock()
	b, ok := d.baselines[wl]
	if !ok {
		b = &baseline{
			miner:      drain3.New(),
			firstSeen:  d.now(),
			known:      map[int]struct{}{},
			digestSeen: map[int]map[string]struct{}{},
		}
		d.baselines[wl] = b
	}
	cluster, isNewCluster := b.miner.Add(line.Message)
	if cluster == nil {
		d.mu.Unlock()
		return nil, Observation{Workload: wl, ImageDigest: line.ImageDigest}
	}
	b.lines++
	_, alreadyKnown := b.known[cluster.ID]
	if isNewCluster {
		b.known[cluster.ID] = struct{}{}
	}

	digestSet, ok := b.digestSeen[cluster.ID]
	if !ok {
		digestSet = map[string]struct{}{}
		b.digestSeen[cluster.ID] = digestSet
	}
	priorVersionCount := len(digestSet)
	if line.ImageDigest != "" {
		digestSet[line.ImageDigest] = struct{}{}
	}
	// FirstSeenInVersion: this template hadn't been seen on any other
	// digest before — it's new in the current rollout.
	firstSeenInVersion := priorVersionCount == 0 && line.ImageDigest != ""

	// Per-template pod tracking.
	key := tplKey{wl, cluster.ID}
	pods, ok := d.pods[key]
	if !ok {
		pods = map[string]time.Time{}
		d.pods[key] = pods
	}
	if line.Pod != "" {
		pods[line.Pod] = d.now()
	}
	d.gcPods(key, 30*time.Minute)
	affectedPods := len(pods)

	warmUp := d.now().Sub(b.firstSeen) < MinHistory
	belowMinLines := b.lines < MinLines
	tplFmt := cluster.Format()
	d.mu.Unlock()

	obs := Observation{
		MatchedKnown: !isNewCluster,
		Workload:     wl,
		Template:     tplFmt,
		ImageDigest:  line.ImageDigest,
	}

	if !isNewCluster || alreadyKnown || warmUp || belowMinLines {
		return nil, obs
	}

	a := &types.Anomaly{
		ID:                 fmt.Sprintf("nt-%d-%d", time.Now().UnixNano(), cluster.ID),
		Kind:               types.AnomalyNewTemplate,
		FiredAt:            d.now(),
		Workload:           wl,
		ImageDigest:        line.ImageDigest,
		Image:              line.Image,
		Template:           tplFmt,
		Sample:             []string{line.Message},
		AffectedPods:       affectedPods,
		FirstSeenInVersion: firstSeenInVersion,
	}
	return a, obs
}

// PodCount returns the unique-pod count for (workload, template) over
// the last 30 minutes. Returns 0 if not tracked.
func (d *Detector) PodCount(w types.Workload, template string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, pods := range d.pods {
		if k.w != w {
			continue
		}
		// Match by template formatted string.
		if b, ok := d.baselines[w]; ok {
			for _, c := range b.miner.Clusters() {
				if c.ID == k.clID && c.Format() == template {
					return len(pods)
				}
			}
		}
	}
	return 0
}

func (d *Detector) gcPods(key tplKey, retain time.Duration) {
	cutoff := d.now().Add(-retain)
	pods := d.pods[key]
	for p, t := range pods {
		if t.Before(cutoff) {
			delete(pods, p)
		}
	}
}
