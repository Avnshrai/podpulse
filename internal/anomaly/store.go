// Package anomaly is the in-memory store + dedup layer for detected
// anomalies, plus the simple RCA "filler" that converts a raw detector
// hit into a human-readable sentence and rollback hint.
//
// Postgres-backed persistence comes later; for the Phase 1 demo this is
// a ring buffer in process memory.
package anomaly

import (
	"fmt"
	"sync"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

// dedupWindow controls how long after firing an anomaly we suppress
// further anomalies of the same (workload, kind, template).
const dedupWindow = 15 * time.Minute

// Store is the in-memory anomaly store. Goroutine-safe.
type Store struct {
	mu       sync.RWMutex
	all      []types.Anomaly
	byID     map[string]int // ID → index into all
	lastSeen map[string]time.Time
	maxItems int
}

func NewStore(maxItems int) *Store {
	if maxItems <= 0 {
		maxItems = 1000
	}
	return &Store{
		byID:     map[string]int{},
		lastSeen: map[string]time.Time{},
		maxItems: maxItems,
	}
}

// Record stores an anomaly if it isn't a recent duplicate. Returns true if
// the anomaly was actually recorded (and so should fire alerts).
func (s *Store) Record(a types.Anomaly) bool {
	dedupKey := fmt.Sprintf("%s|%s|%s", a.Workload, a.Kind, a.Template)

	s.mu.Lock()
	defer s.mu.Unlock()

	if last, ok := s.lastSeen[dedupKey]; ok && time.Since(last) < dedupWindow {
		return false
	}
	s.lastSeen[dedupKey] = a.FiredAt

	if len(s.all) >= s.maxItems {
		// Evict the oldest. Cheap O(n) — fine for a 1000-item buffer.
		evicted := s.all[0]
		delete(s.byID, evicted.ID)
		s.all = s.all[1:]
		// Reindex.
		for i, x := range s.all {
			s.byID[x.ID] = i
		}
	}
	s.byID[a.ID] = len(s.all)
	s.all = append(s.all, a)
	return true
}

// List returns the most recent N anomalies, newest first.
func (s *Store) List(limit int) []types.Anomaly {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.all) {
		limit = len(s.all)
	}
	out := make([]types.Anomaly, 0, limit)
	for i := len(s.all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.all[i])
	}
	return out
}

// Get returns one anomaly by ID.
func (s *Store) Get(id string) (types.Anomaly, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.byID[id]
	if !ok {
		return types.Anomaly{}, false
	}
	return s.all[idx], true
}
