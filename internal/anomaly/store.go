// Package anomaly is the in-memory store + dedup + grouping layer for
// detected anomalies, plus silence rules and acknowledgement state.
//
// Variant grouping: when a new anomaly fires for the same workload as a
// recent one (within groupWindow) on the same broad error topic, we
// append it to that anomaly's Variants list rather than creating a new
// card. This collapses noisy "user not found / user not valid / user
// missing" floods into a single "User validation errors (3 variants)"
// entry.
package anomaly

import (
	"strings"
	"sync"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

const (
	dedupWindow = 15 * time.Minute
	groupWindow = 10 * time.Minute
)

// State for an anomaly the user has acted on.
type State string

const (
	StateActive   State = "active"
	StateSilenced State = "silenced"
	StateResolved State = "resolved"
	StateIgnored  State = "ignored"
)

// Stored wraps an Anomaly with mutable state the dashboard needs.
type Stored struct {
	types.Anomaly
	State    State     `json:"state"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	mu       sync.RWMutex
	all      []*Stored
	byID     map[string]*Stored
	lastSeen map[string]time.Time
	maxItems int
}

func NewStore(maxItems int) *Store {
	if maxItems <= 0 {
		maxItems = 2000
	}
	return &Store{
		byID:     map[string]*Stored{},
		lastSeen: map[string]time.Time{},
		maxItems: maxItems,
	}
}

// Record stores an anomaly with grouping + dedup. Returns:
//   - the canonical anomaly (could be a new one OR an existing one that
//     this anomaly was grouped into),
//   - shouldAlert: true only when this is the first fire (callers should
//     dispatch alerts only in that case).
func (s *Store) Record(a types.Anomaly) (*Stored, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Dedup: identical (workload, kind, template) within 15 minutes.
	dedupKey := a.Workload.String() + "|" + string(a.Kind) + "|" + a.Template
	if last, ok := s.lastSeen[dedupKey]; ok && time.Since(last) < dedupWindow {
		// Find the existing entry and bump its UpdatedAt.
		for i := len(s.all) - 1; i >= 0; i-- {
			if s.all[i].Workload == a.Workload &&
				s.all[i].Kind == a.Kind &&
				s.all[i].Template == a.Template {
				s.all[i].UpdatedAt = a.FiredAt
				return s.all[i], false
			}
		}
	}
	s.lastSeen[dedupKey] = a.FiredAt

	// 2. Variant grouping: same workload + same broad topic within 10m.
	topic := errorTopic(a.Template, a.Sample)
	for i := len(s.all) - 1; i >= 0; i-- {
		x := s.all[i]
		if time.Since(x.FiredAt) > groupWindow {
			break
		}
		if x.Workload == a.Workload && x.Kind == a.Kind &&
			errorTopic(x.Template, x.Sample) == topic && topic != "" {
			// Append the new template as a variant.
			if a.Template != x.Template && !contains(x.Variants, a.Template) {
				x.Variants = append(x.Variants, a.Template)
			}
			x.UpdatedAt = a.FiredAt
			if a.AffectedPods > x.AffectedPods {
				x.AffectedPods = a.AffectedPods
			}
			return x, false
		}
	}

	// 3. New anomaly.
	st := &Stored{Anomaly: a, State: StateActive, UpdatedAt: a.FiredAt}
	if len(s.all) >= s.maxItems {
		evict := s.all[0]
		delete(s.byID, evict.ID)
		s.all = s.all[1:]
	}
	s.byID[a.ID] = st
	s.all = append(s.all, st)
	return st, true
}

// BumpPods increases AffectedPods for the most recent active anomaly
// matching (workload, template) when a new pod has been observed
// emitting the same template.
func (s *Store) BumpPods(w types.Workload, template string, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.all) - 1; i >= 0; i-- {
		x := s.all[i]
		if x.Workload != w || x.Template != template {
			continue
		}
		if count > x.AffectedPods {
			x.AffectedPods = count
			x.UpdatedAt = time.Now()
		}
		return
	}
}

// SetState transitions an anomaly's State (silence/resolve/ignore).
func (s *Store) SetState(id string, st State) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.byID[id]
	if !ok {
		return false
	}
	x.State = st
	x.UpdatedAt = time.Now()
	return true
}

// List returns the most recent anomalies, newest first, optionally
// filtered.
type ListFilter struct {
	Limit     int
	Severity  types.Severity
	Namespace string
	Workload  string
	State     State
	Since     time.Time
}

func (s *Store) List(f ListFilter) []*Stored {
	s.mu.RLock()
	defer s.mu.RUnlock()
	limit := f.Limit
	if limit <= 0 || limit > len(s.all) {
		limit = len(s.all)
	}
	out := make([]*Stored, 0, limit)
	for i := len(s.all) - 1; i >= 0 && len(out) < limit; i-- {
		x := s.all[i]
		if f.Severity != "" && x.Severity != f.Severity {
			continue
		}
		if f.Namespace != "" && x.Workload.Namespace != f.Namespace {
			continue
		}
		if f.Workload != "" && x.Workload.Name != f.Workload {
			continue
		}
		if f.State != "" && x.State != f.State {
			continue
		}
		if !f.Since.IsZero() && x.FiredAt.Before(f.Since) {
			continue
		}
		out = append(out, x)
	}
	return out
}

// All returns every anomaly currently in the store (newest first), no
// filtering. Used for summary calculations.
func (s *Store) All() []*Stored {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Stored, len(s.all))
	for i, j := 0, len(s.all)-1; j >= 0; i, j = i+1, j-1 {
		out[i] = s.all[j]
	}
	return out
}

// Get returns one anomaly by ID.
func (s *Store) Get(id string) (*Stored, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.byID[id]
	return a, ok
}

// errorTopic groups templates into broad classes for variant collapse.
// Sibling of rca.errorTopic but local here to avoid an import cycle.
func errorTopic(template string, samples []string) string {
	t := strings.ToLower(template + " " + strings.Join(samples, " "))
	switch {
	case strings.Contains(t, "econnrefused"), strings.Contains(t, "connection refused"):
		return "conn_refused"
	case strings.Contains(t, "timeout"), strings.Contains(t, "timed out"):
		return "timeout"
	case strings.Contains(t, "oom"), strings.Contains(t, "out of memory"):
		return "oom"
	case strings.Contains(t, "sigterm"), strings.Contains(t, "panic"), strings.Contains(t, "fatal"):
		return "crash"
	case strings.Contains(t, "user not found"), strings.Contains(t, "user_not_found"),
		strings.Contains(t, "user not valid"), strings.Contains(t, "missing tenant"):
		return "user_validation"
	case strings.Contains(t, "401"), strings.Contains(t, "403"),
		strings.Contains(t, "unauthorized"), strings.Contains(t, "forbidden"):
		return "auth"
	case strings.Contains(t, "imagepullbackoff"), strings.Contains(t, "errimagepull"):
		return "image_pull"
	}
	return ""
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
