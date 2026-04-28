// Package rca builds the human-readable root-cause sentence and the
// list of investigation suggestions attached to every anomaly. This is
// the templated (no-LLM) backend.
//
// The RCA sentence is built from facts the detector already has:
// workload, image, image-digest, template, sample line, and (when
// available) the most recent rollout for that workload.
//
// The Suggestions list is chosen based on which error patterns the
// template matches — no more "always print kubectl rollout undo".
package rca

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

// Rollout describes the most recent rollout of a workload.
type Rollout struct {
	When   time.Time
	Image  string
	Digest string
	Commit string
}

// Fill mutates the anomaly in place, populating every human-readable
// field: Headline, ShortStory, RCA, Impact, ImpactLine, Timeline,
// Confidence, DeploymentCorrelated, and Suggestions.
func Fill(a *types.Anomaly, recent Rollout) {
	deploymentRecent := !recent.When.IsZero() && time.Since(recent.When) < 30*time.Minute
	a.DeploymentCorrelated = deploymentRecent

	a.Impact, a.ImpactLine = impactFor(*a)
	a.Headline = headline(*a, recent, deploymentRecent)
	a.ShortStory = shortStory(*a, recent, deploymentRecent)
	a.RCA = sentence(*a, recent)
	a.Timeline = buildTimeline(*a, recent, deploymentRecent)
	a.Confidence = confidence(*a, recent, deploymentRecent)
	a.Suggestions = buildSuggestions(*a, recent)
}

// --- Headline / ShortStory ---

// errorTopic looks at the template/sample and returns a short
// human-friendly noun phrase for the headline, e.g. "User not found"
// from "User <*> not found", or "Redis connection refused" from
// "ECONNREFUSED 127.0.0.1:6379".
func errorTopic(a types.Anomaly) string {
	t := strings.ToLower(a.Template + " " + strings.Join(a.Sample, " "))
	connRefused := strings.Contains(t, "econnrefused") || strings.Contains(t, "connection refused")
	switch {
	case connRefused && rxRedis.MatchString(t):
		return "Redis connection refused"
	case connRefused && rxMongo.MatchString(t):
		return "MongoDB connection refused"
	case connRefused && rxPostgres.MatchString(t):
		return "Postgres connection refused"
	case connRefused:
		return "Connection refused"
	case rxOOM.MatchString(t):
		return "Out-of-memory kill"
	case rxCrashLoop.MatchString(t):
		return "Container crash"
	case strings.Contains(t, "user not found"), strings.Contains(t, "user_not_found"):
		return "User not found"
	case rxAuth.MatchString(t):
		return "Auth/permission failure"
	case rxImagePull.MatchString(t):
		return "Image pull failure"
	case rxTimeout.MatchString(t):
		return "Upstream timeout"
	case rxDNS.MatchString(t):
		return "DNS lookup failure"
	case rx5xx.MatchString(t):
		return "5xx response"
	}
	// Fallback: pull the first non-trivial words from the template.
	first := firstWords(a.Template, 5)
	if first == "" {
		first = firstWords(strings.Join(a.Sample, " "), 5)
	}
	if first == "" {
		first = "New error"
	}
	return first
}

func headline(a types.Anomaly, r Rollout, deployRecent bool) string {
	topic := errorTopic(a)
	if deployRecent {
		ago := time.Since(r.When).Round(time.Minute)
		return fmt.Sprintf("%q errors started %s after rollout", topic, humanDuration(ago))
	}
	if a.FirstSeenInVersion {
		return fmt.Sprintf("New %q errors detected", topic)
	}
	switch a.Kind {
	case types.AnomalyTemplateRate:
		return fmt.Sprintf("%q error rate is spiking", topic)
	case types.AnomalyStatusCodeShift:
		return "5xx error rate is spiking"
	case types.AnomalyRestartRate:
		return "Pods are restarting unusually often"
	}
	return fmt.Sprintf("New %q errors detected", topic)
}

func shortStory(a types.Anomaly, r Rollout, deployRecent bool) string {
	wl := a.Workload
	pods := a.AffectedPods
	if pods <= 0 {
		pods = 1
	}
	subject := fmt.Sprintf("Affecting %d pod", pods)
	if pods != 1 {
		subject += "s"
	}
	subject += " of " + wl.Name
	if wl.Namespace != "" {
		subject += " in " + wl.Namespace
	}
	subject += "."
	if deployRecent {
		ago := time.Since(r.When).Round(time.Minute)
		intro := fmt.Sprintf("This workload rolled out %s ago", humanDuration(ago))
		if r.Image != "" {
			intro += " (image " + truncate(r.Image, 60) + ")"
		}
		return intro + ". " + subject
	}
	return subject
}

// --- Impact ---

func impactFor(a types.Anomaly) (types.ImpactLevel, string) {
	pods := a.AffectedPods
	switch {
	case pods <= 0, pods == 1:
		return types.ImpactLow, "Only 1 pod (low risk)"
	case pods <= 3:
		return types.ImpactMedium, fmt.Sprintf("%d pods affected (medium risk)", pods)
	case pods <= 10:
		return types.ImpactHigh, fmt.Sprintf("%d pods affected (high risk)", pods)
	default:
		return types.ImpactCritical, fmt.Sprintf("All %d pods affected (critical)", pods)
	}
}

// --- Timeline ---

func buildTimeline(a types.Anomaly, r Rollout, deployRecent bool) []types.TimelineEvent {
	out := []types.TimelineEvent{}
	if !r.When.IsZero() {
		label := "Deployment rolled out"
		if r.Commit != "" {
			label += " (" + shortSHA(r.Commit) + ")"
		}
		out = append(out, types.TimelineEvent{When: r.When, Label: label})
	}
	out = append(out, types.TimelineEvent{When: a.FiredAt, Label: "First error seen"})
	if deployRecent {
		out = append(out, types.TimelineEvent{When: time.Now(), Label: "Errors continuing"})
	}
	return out
}

// --- Confidence ---

// confidence returns a 0-100 score for how sure we are this anomaly is
// real and signal, not noise. Deployment-correlated anomalies score
// highest (the rollout is the smoking gun).
func confidence(a types.Anomaly, r Rollout, deployRecent bool) int {
	switch {
	case deployRecent && time.Since(r.When) < 5*time.Minute:
		return 92
	case deployRecent && time.Since(r.When) < 30*time.Minute:
		return 78
	case a.FirstSeenInVersion:
		return 70
	case a.Kind == types.AnomalyTemplateRate:
		return 65
	case a.Kind == types.AnomalyRestartRate:
		return 75
	default:
		return 50
	}
}

// --- RCA sentence ---

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

// --- suggestion engine ---

// pattern is a regex + the suggestions to attach when it matches.
type pattern struct {
	re   *regexp.Regexp
	make func(types.Anomaly) []types.Suggestion
}

var (
	rxConnRefused   = regexp.MustCompile(`(?i)(ECONNREFUSED|connection refused)`)
	rxTimeout       = regexp.MustCompile(`(?i)(ETIMEDOUT|context deadline exceeded|i/o timeout|upstream timeout|read.*timed out)`)
	rxDNS           = regexp.MustCompile(`(?i)(ENOTFOUND|no such host|getaddrinfo|DNS lookup)`)
	rxOOM           = regexp.MustCompile(`(?i)(OOMKilled|OutOfMemory|java\.lang\.OutOfMemoryError|cannot allocate memory|MemoryError)`)
	rxCrashLoop     = regexp.MustCompile(`(?i)(SIGTERM|signal:.+terminated|exit status [1-9]|panic:|fatal: |unhandled exception)`)
	rxImagePull     = regexp.MustCompile(`(?i)(ImagePullBackOff|ErrImagePull|manifest unknown|repository does not exist|pull access denied)`)
	rxAuth          = regexp.MustCompile(`(?i)(401 Unauthorized|403 Forbidden|permission denied|authentication failed|invalid credentials|access denied|RBAC)`)
	rx5xx           = regexp.MustCompile(`\b(50[0-9]|5[0-9]{2})\b`)
	rxJSONParse     = regexp.MustCompile(`(?i)(unexpected token|JSON\.parse|invalid JSON|unmarshal error|cannot unmarshal)`)
	rxRedis         = regexp.MustCompile(`(?i)(redis|ioredis|6379)`)
	rxMongo         = regexp.MustCompile(`(?i)(mongodb|MongoServerError|27017)`)
	rxPostgres      = regexp.MustCompile(`(?i)(postgres|psql|5432|FATAL.*database)`)
	rxStackTrace    = regexp.MustCompile(`(?i)(at .*\(.*:\d+:\d+\)|Traceback \(most recent call last\)|java\.lang\.[A-Z])`)
)

func buildSuggestions(a types.Anomaly, r Rollout) []types.Suggestion {
	wl := a.Workload
	t := a.Template + " " + strings.Join(a.Sample, " ")
	out := []types.Suggestion{}

	// Always-useful: tail recent logs for the affected workload.
	out = append(out, types.Suggestion{
		Title:   "Tail recent logs",
		Command: kubectlLogs(wl, false),
		Why:     "Get the last 100 lines from any pod of this workload to see what's happening right now.",
	})
	out = append(out, types.Suggestion{
		Title:   "Inspect pod state and events",
		Command: fmt.Sprintf("kubectl describe %s -n %s -l app=%s",
			strings.ToLower(workloadKind(wl)), wl.Namespace, wl.Name),
		Why:     "Surfaces recent K8s events: scheduling, pulls, probes, container exits.",
	})

	// Pattern-specific.
	if rxConnRefused.MatchString(t) {
		// What service / port was it?
		host, port := guessHostPort(t)
		out = append(out, types.Suggestion{
			Title:   "Verify the upstream Service exists",
			Command: fmt.Sprintf("kubectl get svc -A | grep -i %s", quoteOrAny(host, "redis")),
			Why:     fmt.Sprintf("ECONNREFUSED to %s:%s usually means the Service object isn't reachable — wrong name, wrong namespace, or the upstream pod is down.", display(host, "<host>"), display(port, "<port>")),
		})
		out = append(out, types.Suggestion{
			Title:   "Check the env / configmap that holds the upstream URL",
			Command: fmt.Sprintf("kubectl set env %s/%s -n %s --list",
				strings.ToLower(workloadKind(wl)), wl.Name, wl.Namespace),
			Why:     "If the URL is empty or points at localhost, the client falls back to defaults (e.g. ioredis → 127.0.0.1:6379).",
		})
		if rxRedis.MatchString(t) {
			out = append(out, types.Suggestion{
				Title:   "Probe the Redis service from inside the pod",
				Command: fmt.Sprintf("kubectl exec -it -n %s deploy/%s -- sh -c 'getent hosts redis-master || nslookup redis-master'",
					wl.Namespace, wl.Name),
				Why:     "Confirms whether the redis hostname even resolves from this pod's network namespace.",
			})
		}
	}

	if rxTimeout.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Check for upstream pod readiness or NetworkPolicy denial",
			Command: fmt.Sprintf("kubectl get netpol -n %s; kubectl get pods -n %s -o wide", wl.Namespace, wl.Namespace),
			Why:     "Timeouts often mean the upstream pod is unready, or a NetworkPolicy is silently dropping traffic.",
		})
	}

	if rxDNS.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Verify CoreDNS health and pod /etc/resolv.conf",
			Command: "kubectl -n kube-system get pods -l k8s-app=kube-dns",
			Why:     "ENOTFOUND / no-such-host errors are usually CoreDNS issues or a wrong cluster.local search domain.",
		})
	}

	if rxOOM.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Show pod memory usage",
			Command: fmt.Sprintf("kubectl top pod -n %s -l app=%s", wl.Namespace, wl.Name),
			Why:     "Confirms whether the pod is hitting its memory limit. Compare to .resources.limits.memory.",
		})
		out = append(out, types.Suggestion{
			Title:   "Inspect previous container's last 200 log lines",
			Command: kubectlLogs(wl, true),
			Why:     "OOMKilled containers leave their last output behind in the previous-instance log buffer.",
		})
	}

	if rxCrashLoop.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Read the previous container's logs",
			Command: kubectlLogs(wl, true),
			Why:     "SIGTERM / non-zero exit means the container died and was restarted; --previous gets the death log.",
		})
	}

	if rxImagePull.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Check image pull events",
			Command: fmt.Sprintf("kubectl get events -n %s --field-selector reason=Failed --sort-by=.lastTimestamp", wl.Namespace),
			Why:     "Surfaces ErrImagePull / ImagePullBackOff with the exact registry response.",
		})
	}

	if rxAuth.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Check the ServiceAccount + RoleBindings the pod uses",
			Command: fmt.Sprintf("kubectl get rolebinding,clusterrolebinding -A -o wide | grep %s", wl.Name),
			Why:     "401/403 from the K8s API usually means the SA is missing the verb on this resource.",
		})
	}

	if rx5xx.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Look at the upstream service's logs",
			Command: fmt.Sprintf("kubectl get pods,svc -n %s", wl.Namespace),
			Why:     "5xx in this workload often originates downstream — find the service it depends on and tail its logs.",
		})
	}

	if rxJSONParse.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Inspect the configmap / secret the app reads",
			Command: fmt.Sprintf("kubectl describe configmap -n %s | head -200", wl.Namespace),
			Why:     "JSON parse errors at startup almost always mean a malformed value (unescaped quote, missing comma, embedded newline).",
		})
	}

	if rxStackTrace.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Get a full backtrace",
			Command: kubectlLogs(wl, false) + " | grep -A 50 -E 'Traceback|Exception|panic'",
			Why:     "Stack traces span many lines — pull a generous --tail and grep for the throw site.",
		})
	}

	if rxMongo.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Confirm MongoDB replica-set is reachable",
			Command: "kubectl get pods -A -l 'app=mongodb' -o wide",
			Why:     "Mongo connection errors point to the replica set status — check that the primary is electable.",
		})
	}

	if rxPostgres.MatchString(t) {
		out = append(out, types.Suggestion{
			Title:   "Check Postgres connection limits / authentication",
			Command: fmt.Sprintf("kubectl get pods -n %s -l app=postgres", wl.Namespace),
			Why:     "FATAL from Postgres is typically too-many-connections, password mismatch, or pg_hba.conf rejection.",
		})
	}

	// Rollout-related: only suggest undo if there was a recent rollout.
	if !r.When.IsZero() && time.Since(r.When) < 60*time.Minute {
		out = append(out, types.Suggestion{
			Title:   "Compare to the previous rollout",
			Command: fmt.Sprintf("kubectl rollout history %s/%s -n %s",
				strings.ToLower(workloadKind(wl)), wl.Name, wl.Namespace),
			Why:     fmt.Sprintf("This workload rolled out %s ago — see what changed.", time.Since(r.When).Round(time.Second)),
		})
		out = append(out, types.Suggestion{
			Title:   "Roll back if the new release is bad",
			Command: fmt.Sprintf("kubectl rollout undo %s/%s -n %s",
				strings.ToLower(workloadKind(wl)), wl.Name, wl.Namespace),
			Why:     "Use only after confirming the regression came from the recent release.",
		})
	}

	return out
}

func kubectlLogs(w types.Workload, previous bool) string {
	suffix := ""
	if previous {
		suffix = " --previous"
	}
	kind := strings.ToLower(workloadKind(w))
	return fmt.Sprintf("kubectl logs -n %s %s/%s --tail=100%s", w.Namespace, kind, w.Name, suffix)
}

func workloadKind(w types.Workload) string {
	if w.Kind == "" {
		return "deployment"
	}
	return w.Kind
}

func quoteOrAny(host, fallback string) string {
	if host == "" {
		return fallback
	}
	return host
}

func display(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// guessHostPort tries to extract host + port from a connection-refused
// log line (e.g., "connect ECONNREFUSED 127.0.0.1:6379" or
// "connection refused upstream=redis-master:6379").
func guessHostPort(line string) (string, string) {
	re := regexp.MustCompile(`([A-Za-z0-9._-]+):(\d{1,5})`)
	if m := re.FindStringSubmatch(line); len(m) == 3 {
		return m[1], m[2]
	}
	return "", ""
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
	if i := strings.Index(d, ":"); i > 0 && len(d) > i+8 {
		return d[:i+8]
	}
	return d
}

// humanDuration renders a Duration like "7 min" or "2 hr".
func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return "less than a minute"
	}
	if d < time.Hour {
		mins := int(d / time.Minute)
		if mins == 1 {
			return "1 min"
		}
		return fmt.Sprintf("%d min", mins)
	}
	hrs := int(d / time.Hour)
	if hrs == 1 {
		return "1 hr"
	}
	return fmt.Sprintf("%d hr", hrs)
}

// firstWords returns the first n whitespace-separated words of s,
// dropping leading punctuation.
func firstWords(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	parts := strings.Fields(s)
	if len(parts) > n {
		parts = parts[:n]
	}
	out := strings.Join(parts, " ")
	out = strings.Trim(out, `"'.,:;`)
	return out
}
