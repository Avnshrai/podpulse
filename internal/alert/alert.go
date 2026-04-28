// Package alert defines the Sender interface that every channel
// (slack, teams, smtp, pagerduty, webhook) implements, plus the simple
// fan-out Dispatcher used by the detector.
package alert

import (
	"context"
	"log/slog"
	"sync"

	"github.com/podpulse/podpulse/internal/types"
)

// Sender ships a single anomaly to one channel.
type Sender interface {
	Name() string
	Send(ctx context.Context, a types.Anomaly) error
}

// Dispatcher fans an anomaly out to every registered Sender. Errors are
// logged and never returned — one slow channel must not block the others.
type Dispatcher struct {
	mu      sync.RWMutex
	senders []Sender
}

func NewDispatcher() *Dispatcher { return &Dispatcher{} }

func (d *Dispatcher) Add(s Sender) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.senders = append(d.senders, s)
}

func (d *Dispatcher) Dispatch(ctx context.Context, a types.Anomaly) {
	d.mu.RLock()
	senders := append([]Sender(nil), d.senders...)
	d.mu.RUnlock()

	if len(senders) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, s := range senders {
		wg.Add(1)
		go func(s Sender) {
			defer wg.Done()
			if err := s.Send(ctx, a); err != nil {
				slog.Error("alert send failed",
					"channel", s.Name(),
					"anomaly_id", a.ID,
					"err", err,
				)
			}
		}(s)
	}
	wg.Wait()
}
