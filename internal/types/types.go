// Package types holds the small set of cross-cutting structs used by both
// the tailer and the detector. Keeping these here avoids import cycles
// between the ingest, detect, and api packages.
package types

import "time"

// LogLine is a single enriched container log line shipped from a tailer to
// the detector. Enrichment happens on the tailer side from the node-local
// pod cache so the detector doesn't need a per-pod lookup per line.
type LogLine struct {
	Timestamp   time.Time `json:"ts"`
	Namespace   string    `json:"ns"`
	OwnerKind   string    `json:"owner_kind,omitempty"` // Deployment, StatefulSet, DaemonSet, ...
	OwnerName   string    `json:"owner_name,omitempty"`
	Pod         string    `json:"pod"`
	Container   string    `json:"container"`
	Image       string    `json:"image,omitempty"`
	ImageDigest string    `json:"image_digest,omitempty"`
	Node        string    `json:"node,omitempty"`
	Stream      string    `json:"stream,omitempty"` // stdout / stderr
	Message     string    `json:"msg"`
}

// Workload identifies a logical workload that owns a set of pods.
// Anomaly baselines are keyed by Workload + ImageDigest.
type Workload struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

func (w Workload) String() string {
	if w.Kind == "" {
		return w.Namespace + "/" + w.Name
	}
	return w.Namespace + "/" + w.Kind + "/" + w.Name
}

// Severity ranks anomalies by blast radius.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// AnomalyKind enumerates the detector's anomaly categories.
type AnomalyKind string

const (
	AnomalyNewTemplate     AnomalyKind = "new_template"
	AnomalyTemplateRate    AnomalyKind = "template_rate_spike"
	AnomalyStatusCodeShift AnomalyKind = "status_code_shift"
	AnomalyRestartRate     AnomalyKind = "restart_rate"
)

// Anomaly is the unit emitted by the detector and consumed by the alert
// dispatcher, the CLI, and the web view.
type Anomaly struct {
	ID          string      `json:"id"`
	Kind        AnomalyKind `json:"kind"`
	Severity    Severity    `json:"severity"`
	FiredAt     time.Time   `json:"fired_at"`
	Workload    Workload    `json:"workload"`
	ImageDigest string      `json:"image_digest,omitempty"`
	Image       string      `json:"image,omitempty"`

	// Template is populated for log-template-based anomalies.
	Template string `json:"template,omitempty"`

	// Sample is one or two recent raw lines that matched the template,
	// useful for the alert and the UI drill-down.
	Sample []string `json:"sample,omitempty"`

	// AffectedPods counts unique pods seen emitting this template within
	// the correlation window. Drives the blast-radius score.
	AffectedPods int `json:"affected_pods"`

	// RCA is the human-readable root-cause sentence. Populated by the
	// RCA engine. Empty for stub anomalies.
	RCA string `json:"rca,omitempty"`

	// RollbackHint is a copy-pasteable kubectl command, when applicable.
	RollbackHint string `json:"rollback_hint,omitempty"`
}
