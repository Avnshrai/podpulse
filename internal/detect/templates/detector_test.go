package templates

import (
	"testing"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

func TestNoFireDuringWarmUp(t *testing.T) {
	d := New()
	d.now = staticClock(time.Unix(1000, 0))
	a := d.Observe(line("ns", "Deployment", "app", "v1", "anything ever seen"))
	if a != nil {
		t.Fatalf("expected nil during warm-up, got %+v", a)
	}
}

func TestFireOnNewTemplateAfterWarmUp(t *testing.T) {
	old := MinHistory
	MinHistory = 5 * time.Second
	defer func() { MinHistory = old }()

	t0 := time.Unix(1000, 0)
	clock := &mutClock{now: t0}
	d := New()
	d.now = clock.read

	// Establish baseline with stable templates under image v1.
	for i := 0; i < 5; i++ {
		_ = d.Observe(line("ns", "Deployment", "app", "v1", "GET /foo 200"))
		_ = d.Observe(line("ns", "Deployment", "app", "v1", "POST /bar accepted"))
	}

	// Advance past warm-up. Same templates → still no fire.
	clock.now = t0.Add(10 * time.Second)
	if a := d.Observe(line("ns", "Deployment", "app", "v1", "GET /foo 200")); a != nil {
		t.Fatalf("known template after warm-up should not fire, got %+v", a)
	}

	// New error template under a fresh image-digest → must fire.
	a := d.Observe(line("ns", "Deployment", "app", "v2", "ERROR connection refused upstream redis-master"))
	if a == nil {
		t.Fatal("expected anomaly for new template after warm-up")
	}
	if a.Kind != types.AnomalyNewTemplate {
		t.Errorf("kind: want new_template, got %s", a.Kind)
	}
	if a.ImageDigest != "v2" {
		t.Errorf("image-digest: want v2 (the rollout that introduced the error), got %q", a.ImageDigest)
	}

	// Same broken template again → already-known, must not fire.
	if a := d.Observe(line("ns", "Deployment", "app", "v2", "ERROR connection refused upstream redis-master")); a != nil {
		t.Errorf("repeat of known template must not refire, got %+v", a)
	}
}

func line(ns, kind, name, digest, msg string) types.LogLine {
	return types.LogLine{
		Namespace:   ns,
		OwnerKind:   kind,
		OwnerName:   name,
		Pod:         name + "-pod",
		ImageDigest: digest,
		Message:     msg,
	}
}

func staticClock(t time.Time) func() time.Time { return func() time.Time { return t } }

type mutClock struct{ now time.Time }

func (m *mutClock) read() time.Time { return m.now }
