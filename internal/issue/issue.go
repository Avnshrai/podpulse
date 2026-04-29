// Package issue is the unified incident-shaped event PodPulse emits.
//
// Issues come in three flavors:
//
//   IssueLogAnomaly   — a new error template (log-driven, what we had).
//   IssueConfigIssue  — a ConfigMap or Secret changed in a way that's
//                       likely to break the pods that mount it (empty
//                       value, malformed JSON, removed key).
//   IssueCrashLoop    — a pod is crash-looping with a categorizable
//                       reason (OOMKilled, FailedMount, ImagePullBackOff,
//                       Unhealthy probe).
//   IssueScheduling   — a pod cannot be scheduled (insufficient
//                       resources, taints, etc.).
//
// All three render with the same "Root Cause / Impact / Timeline /
// Suggested Fix" structure on the dashboard.
package issue

import (
	"time"

	"github.com/podpulse/podpulse/internal/k8s"
	"github.com/podpulse/podpulse/internal/types"
)

type Type string

const (
	TypeLogAnomaly  Type = "log_anomaly"
	TypeConfigIssue Type = "config_issue"
	TypeCrashLoop   Type = "crash_loop"
	TypeScheduling  Type = "scheduling"
)

// Issue is the canonical record. Most fields overlap with types.Anomaly
// for backward compat, but new fields are first-class for the new types.
type Issue struct {
	ID            string         `json:"id"`
	Type          Type           `json:"type"`
	Severity      types.Severity `json:"severity"`
	Impact        types.ImpactLevel `json:"impact_level"`
	State         string         `json:"state"`
	FiredAt       time.Time      `json:"fired_at"`
	UpdatedAt     time.Time      `json:"updated_at"`

	// Human-readable framing (same shape as Anomaly).
	HumanHeadline     string `json:"human_headline"`
	TechnicalHeadline string `json:"technical_headline,omitempty"`
	ShortStory        string `json:"short_story,omitempty"`
	WhatHappened      string `json:"what_happened,omitempty"`
	LikelyCause       string `json:"likely_cause,omitempty"`
	Confidence        int    `json:"confidence"`
	ConfidenceFactors []string `json:"confidence_factors,omitempty"`
	Urgency           string `json:"urgency,omitempty"`

	// Workload / pod identity.
	Workload     types.Workload `json:"workload"`
	Pod          string         `json:"pod,omitempty"`
	AffectedPods int            `json:"affected_pods"`

	// Type-specific bodies. Only one of these will be set.
	LogAnomaly  *LogAnomalyBody  `json:"log_anomaly,omitempty"`
	ConfigIssue *ConfigIssueBody `json:"config_issue,omitempty"`
	CrashLoop   *CrashLoopBody   `json:"crash_loop,omitempty"`
	Scheduling  *SchedulingBody  `json:"scheduling,omitempty"`

	// "What changed" timeline — every Issue carries it.
	Timeline []TimelineEvent `json:"timeline,omitempty"`

	// Suggested fix list — answers, not just commands.
	SuggestedFix []FixStep `json:"suggested_fix,omitempty"`
}

// TimelineEvent is one row in the "what changed before this incident"
// pane. Three kinds: deploy, config_change, error_observed.
type TimelineEvent struct {
	When  time.Time `json:"when"`
	Kind  string    `json:"kind"` // deploy | config_change | error_observed | event
	Label string    `json:"label"`
	Detail string   `json:"detail,omitempty"`
}

// FixStep is what to actually do — a name, an answer (inline content
// when we can compute it), and the kubectl fallback.
type FixStep struct {
	Title      string `json:"title"`
	Answer     string `json:"answer,omitempty"`     // inline insight, not a command
	Command    string `json:"command,omitempty"`    // kubectl fallback
	Why        string `json:"why,omitempty"`
}

// LogAnomalyBody — what we had before (Drain3 template + sample).
type LogAnomalyBody struct {
	Template           string   `json:"template"`
	Sample             []string `json:"sample,omitempty"`
	Variants           []string `json:"variants,omitempty"`
	FirstSeenInVersion bool     `json:"first_seen_in_version"`
	Image              string   `json:"image,omitempty"`
	ImageDigest        string   `json:"image_digest,omitempty"`
	BeforeAfter        *types.BeforeAfter `json:"before_after,omitempty"`
}

// ConfigIssueBody — the differentiator.
type ConfigIssueBody struct {
	Kind    k8s.ConfigKind `json:"kind"`
	Name    string         `json:"name"`
	Changes []k8s.KeyChange `json:"changes"`
	// Mounts lists the workloads that consume this resource.
	Mounts []k8s.ConfigMount `json:"mounts,omitempty"`
}

// CrashLoopBody — pod is restarting; we attach the most informative
// recent event to explain why.
type CrashLoopBody struct {
	Reason     string `json:"reason"`     // OOMKilled, BackOff, etc.
	Restarts   int32  `json:"restarts"`
	LastEvent  string `json:"last_event,omitempty"`
	Category   k8s.EventCategory `json:"category"`
}

// SchedulingBody — pod is stuck Pending.
type SchedulingBody struct {
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}
