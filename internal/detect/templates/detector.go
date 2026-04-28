// Package templates implements PodPulse's headline anomaly: "new error
// template seen on this workload, first observed under image-digest X."
//
// The warm-up gate is on the workload (not on each (workload, image-
// digest) pair) — otherwise every rollout would reset the warm-up and
// suppress exactly the case we want to detect: a new error appearing
// right after a deploy. Image-digest is tracked as an attribute of the
// alert ("first seen in this version") rather than as a baseline scope.
package templates

import (
	"fmt"
	"sync"
	"time"

	"github.com/podpulse/podpulse/internal/detect/drain3"
	"github.com/podpulse/podpulse/internal/types"
)

// MinHistory is the warm-up window: we wait this long after first seeing
// a workload before any new template on it can fire. Otherwise the very
// first line of any workload would alert.
var MinHistory = 30 * time.Second

type baseline struct {
	miner     *drain3.Miner
	firstSeen time.Time
	known     map[int]struct{} // cluster IDs we've ever observed under this workload
}

// Detector is goroutine-safe.
type Detector struct {
	mu        sync.Mutex
	baselines map[types.Workload]*baseline
	now       func() time.Time
}

func New() *Detector {
	return &Detector{
		baselines: map[types.Workload]*baseline{},
		now:       time.Now,
	}
}

// Observe ingests one line and returns an anomaly when:
//   - the line produces a brand-new Drain3 cluster for this workload, AND
//   - the workload baseline has been warming up for at least MinHistory.
//
// The returned Anomaly's ImageDigest/Image come from the line that
// triggered it — i.e. the version on which the new error was first seen.
func (d *Detector) Observe(line types.LogLine) *types.Anomaly {
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
			miner:     drain3.New(),
			firstSeen: d.now(),
			known:     map[int]struct{}{},
		}
		d.baselines[wl] = b
	}
	cluster, isNewCluster := b.miner.Add(line.Message)
	if cluster == nil {
		d.mu.Unlock()
		return nil
	}
	_, alreadyKnown := b.known[cluster.ID]
	if isNewCluster {
		b.known[cluster.ID] = struct{}{}
	}
	warmUp := d.now().Sub(b.firstSeen) < MinHistory
	d.mu.Unlock()

	if !isNewCluster || alreadyKnown || warmUp {
		return nil
	}

	return &types.Anomaly{
		ID:           fmt.Sprintf("nt-%d-%d", time.Now().UnixNano(), cluster.ID),
		Kind:         types.AnomalyNewTemplate,
		Severity:     types.SeverityMedium,
		FiredAt:      d.now(),
		Workload:     wl,
		ImageDigest:  line.ImageDigest,
		Image:        line.Image,
		Template:     cluster.Format(),
		Sample:       []string{line.Message},
		AffectedPods: 1,
	}
}
