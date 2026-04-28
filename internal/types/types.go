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

// Suggestion is one actionable troubleshooting step attached to an
// anomaly. The dashboard shows them as a list of kubectl-style
// "investigation cards" instead of a single rollback command.
type Suggestion struct {
	Title   string `json:"title"`
	Command string `json:"command,omitempty"`
	Why     string `json:"why,omitempty"`
}

// TimelineEvent is one step in the "what happened, in order" view.
type TimelineEvent struct {
	When  time.Time `json:"when"`
	Label string    `json:"label"` // e.g. "Deployment rolled out", "First error seen"
}

// ImpactLevel grades the user-visible blast radius of an anomaly.
// Independent of Severity, which is used for routing/dedup; this is the
// human-friendly framing shown next to the headline.
type ImpactLevel string

const (
	ImpactLow      ImpactLevel = "low"      // 1 pod
	ImpactMedium   ImpactLevel = "medium"   // multiple pods, single workload
	ImpactHigh     ImpactLevel = "high"     // multiple workloads in a namespace
	ImpactCritical ImpactLevel = "critical" // cross-namespace / cluster-wide
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
	// redacted before storage.
	Sample []string `json:"sample,omitempty"`

	// AffectedPods/Containers/Nodes drive the impact score.
	AffectedPods       int `json:"affected_pods"`
	AffectedContainers int `json:"affected_containers,omitempty"`
	AffectedNodes      int `json:"affected_nodes,omitempty"`

	// FirstSeenInVersion is true when the template is genuinely new on
	// the workload's current image-digest.
	FirstSeenInVersion bool `json:"first_seen_in_version,omitempty"`

	// --- human-readable framing ---

	// Headline is the one-liner shown at the top of the card, e.g.
	// "User not found errors started 7 min after rollout".
	Headline string `json:"headline,omitempty"`

	// ShortStory is the human paragraph: what happened, on which workload,
	// affecting how many pods. No tech jargon.
	ShortStory string `json:"short_story,omitempty"`

	// RCA is the kept-for-backwards-compat templated sentence with full
	// technical detail (workload path, image-digest, etc.).
	RCA string `json:"rca,omitempty"`

	// Impact is the human-friendly blast-radius framing.
	Impact      ImpactLevel `json:"impact_level,omitempty"`
	ImpactLine  string      `json:"impact_line,omitempty"` // "Affecting 3 pods in gpu-paas-billing"

	// Timeline lists the 2-4 events that frame the incident in order:
	// most recent rollout, first error seen, rate-spike, etc.
	Timeline []TimelineEvent `json:"timeline,omitempty"`

	// Confidence is 0-100 — our internal certainty that this anomaly is
	// real and not warm-up noise. Deployment-correlated anomalies score
	// the highest.
	Confidence int `json:"confidence,omitempty"`

	// DeploymentCorrelated is true when the anomaly fired within a
	// short window after a rollout — the headline reflects this.
	DeploymentCorrelated bool `json:"deployment_correlated,omitempty"`

	// TimeToDetectionSeconds — for deployment-correlated anomalies, how
	// long after the rollout did we detect the new errors.
	TimeToDetectionSeconds int `json:"time_to_detection_seconds,omitempty"`

	// Variants holds additional templates collapsed into this anomaly
	// when grouping similar errors (e.g. "User not found" + "User not
	// authorized to validate tenant"). The card shows the first as the
	// headline and a "+N variants" badge.
	Variants []string `json:"variants,omitempty"`

	// Suggestions is a list of relevant kubectl / diagnostic commands.
	Suggestions []Suggestion `json:"suggestions,omitempty"`
}
