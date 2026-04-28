package tail

import (
	"testing"
	"time"
)

func TestParseCRIFull(t *testing.T) {
	r, ok := parseCRI("2026-04-28T11:25:50.896000000Z stdout F GPU Communication Service started")
	if !ok {
		t.Fatal("expected ok")
	}
	if r.Stream != "stdout" {
		t.Errorf("stream: %q", r.Stream)
	}
	if r.Message != "GPU Communication Service started" {
		t.Errorf("msg: %q", r.Message)
	}
	if r.Timestamp.Year() != 2026 {
		t.Errorf("ts: %v", r.Timestamp)
	}
}

func TestParseCRIStderr(t *testing.T) {
	r, ok := parseCRI("2026-04-28T11:25:51.000000000Z stderr F Error: connect ECONNREFUSED 127.0.0.1:6379")
	if !ok {
		t.Fatal("expected ok")
	}
	if r.Stream != "stderr" {
		t.Fatalf("stream: %q", r.Stream)
	}
	if r.Message != "Error: connect ECONNREFUSED 127.0.0.1:6379" {
		t.Errorf("msg: %q", r.Message)
	}
}

func TestParseCRIBad(t *testing.T) {
	cases := []string{
		"",
		"not enough fields",
		"only two fields",
		"2026-04-28T11:25:50.896000000Z stdout",
		"badtimestamp stdout F message",
		"2026-04-28T11:25:50.896000000Z weird F message",
	}
	for _, c := range cases {
		if _, ok := parseCRI(c); ok {
			t.Errorf("expected !ok for %q", c)
		}
	}
}

func TestCRITagFP(t *testing.T) {
	if tag := criTag("2026-04-28T11:25:50.896000000Z stdout F hello"); tag != 'F' {
		t.Errorf("F tag: got %q", tag)
	}
	if tag := criTag("2026-04-28T11:25:50.896000000Z stdout P partial"); tag != 'P' {
		t.Errorf("P tag: got %q", tag)
	}
}

// guard against accidental unused-import noise.
var _ = time.Now
