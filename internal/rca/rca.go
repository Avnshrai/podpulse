// Package rca builds the human-readable root-cause sentence and the
// suggested rollback command attached to every anomaly. This is the
// templated (no-LLM) backend; an opt-in Ollama path lives next to it
// (Phase 3).
//
// The RCA sentence is built from facts the detector already has:
// workload, image, image-digest, template, sample line, and (when wired
// up) the most recent rollout for that workload. For Phase 1 we accept
// the rollout info as a parameter so the package can be used from a
// pure-detector path before K8s informers are wired.
package rca

import (
	"fmt"
	"strings"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

// Rollout describes the most recent rollout of a workload, used to
// correlate anomalies with deploys. Empty fields are tolerated.
type Rollout struct {
	When   time.Time
	Image  string
	Digest string
	Commit string // populated from image label org.opencontainers.image.revision when available
}

// Fill mutates the anomaly in place, populating RCA and RollbackHint.
// Pass a zero Rollout if no rollout context is available — the sentence
// will simply omit the rollout clause.
func Fill(a *types.Anomaly, recent Rollout) {
	a.RCA = sentence(*a, recent)
	a.RollbackHint = rollbackCommand(a.Workload)
}

func sentence(a types.Anomaly, r Rollout) string {
	var parts []string

	if !r.When.IsZero() {
		ago := time.Since(r.When).Round(time.Second)
		clause := fmt.Sprintf("Workload %s rolled out %s ago", a.Workload, ago)
		if r.Image != "" {
			clause += " (image " + r.Image
			if r.Commit != "" {
				clause += ", commit " + shortSHA(r.Commit)
			}
			clause += ")"
		}
		parts = append(parts, clause+".")
	}

	switch a.Kind {
	case types.AnomalyNewTemplate:
		t := truncate(a.Template, 120)
		first := fmt.Sprintf("New error template %q first seen on workload %s", t, a.Workload)
		if a.ImageDigest != "" {
			first += " under image-digest " + shortDigest(a.ImageDigest)
		}
		parts = append(parts, first+".")
	case types.AnomalyTemplateRate:
		parts = append(parts, fmt.Sprintf("Template %q rate spiked on %s.", truncate(a.Template, 80), a.Workload))
	case types.AnomalyStatusCodeShift:
		parts = append(parts, fmt.Sprintf("5xx ratio shifted on %s.", a.Workload))
	case types.AnomalyRestartRate:
		parts = append(parts, fmt.Sprintf("Restart rate spiked on %s.", a.Workload))
	}

	if a.AffectedPods > 0 {
		parts = append(parts, fmt.Sprintf("%d pod(s) affected.", a.AffectedPods))
	}

	if !r.When.IsZero() && time.Since(r.When) < 30*time.Minute {
		parts = append(parts, "Likely cause: recent rollout.")
	}

	return strings.Join(parts, " ")
}

func rollbackCommand(w types.Workload) string {
	kind := strings.ToLower(w.Kind)
	if kind == "" {
		kind = "deployment"
	}
	return fmt.Sprintf("kubectl rollout undo %s/%s -n %s", kind, w.Name, w.Namespace)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func shortSHA(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

func shortDigest(d string) string {
	// "sha256:abcdef..." → "sha256:abcdef0"
	if i := strings.Index(d, ":"); i > 0 && len(d) > i+8 {
		return d[:i+8]
	}
	return d
}
