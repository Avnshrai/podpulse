// Package api wires up the detector's HTTP surface:
//
//	POST /v1/ingest                  tailer ships log-line batches here
//	GET  /v1/anomalies               list anomalies (filterable)
//	GET  /v1/anomalies/{id}          single anomaly drill-down
//	POST /v1/anomalies/{id}/silence  mark silenced
//	POST /v1/anomalies/{id}/resolve  mark resolved
//	POST /v1/anomalies/{id}/ignore   mark ignored
//	GET  /v1/workloads               list workloads (with anomaly counts)
//	GET  /v1/services                list K8s Services
//	GET  /v1/deployments             recent rollouts (caused-anomalies tag)
//	GET  /v1/events                  K8s Events feed (proxied)
//	GET  /v1/incidents               anomalies grouped by namespace + window
//	GET  /v1/summary                 dashboard top-level stats
//	GET  /v1/channels                configured alert channels
//	GET  /healthz                    readiness/liveness
//	GET  /                           embedded SPA
package api

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/podpulse/podpulse/internal/alert"
	"github.com/podpulse/podpulse/internal/anomaly"
	"github.com/podpulse/podpulse/internal/detect/templates"
	"github.com/podpulse/podpulse/internal/issue"
	ppk8s "github.com/podpulse/podpulse/internal/k8s"
	"github.com/podpulse/podpulse/internal/rca"
	"github.com/podpulse/podpulse/internal/redact"
	"github.com/podpulse/podpulse/internal/types"
	"github.com/podpulse/podpulse/internal/users"
)

// K8sAPIProxy is set by the detector main when in-cluster proxy is
// available; the api package mounts it under /k8s/* so kubectl can
// reach the apiserver through PodPulse.
var K8sAPIProxy http.Handler

type Server struct {
	store         *anomaly.Store
	detector      *templates.Detector
	dispatcher    *alert.Dispatcher
	webFS         fs.FS
	k8sCache      *ppk8s.Cache
	configWatcher *ppk8s.ConfigWatcher
	eventWatcher  *ppk8s.EventWatcher
	auditWatcher  *ppk8s.AuditWatcher
	userManager   *users.Manager
	issueEngine   *issue.Engine
	channels      []string
	startedAt     time.Time
}

type Options struct {
	Store         *anomaly.Store
	Detector      *templates.Detector
	Dispatcher    *alert.Dispatcher
	WebFS         fs.FS
	K8sCache      *ppk8s.Cache
	ConfigWatcher *ppk8s.ConfigWatcher
	EventWatcher  *ppk8s.EventWatcher
	AuditWatcher  *ppk8s.AuditWatcher
	UserManager   *users.Manager
	IssueEngine   *issue.Engine
	Channels      []string
}

func NewServer(opts Options) *Server {
	return &Server{
		store:         opts.Store,
		detector:      opts.Detector,
		dispatcher:    opts.Dispatcher,
		webFS:         opts.WebFS,
		k8sCache:      opts.K8sCache,
		configWatcher: opts.ConfigWatcher,
		eventWatcher:  opts.EventWatcher,
		auditWatcher:  opts.AuditWatcher,
		userManager:   opts.UserManager,
		issueEngine:   opts.IssueEngine,
		channels:      opts.Channels,
		startedAt:     time.Now(),
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/ingest", s.handleIngest)

	mux.HandleFunc("GET /v1/anomalies", s.handleListAnomalies)
	mux.HandleFunc("GET /v1/anomalies/{id}", s.handleGetAnomaly)
	mux.HandleFunc("POST /v1/anomalies/{id}/silence", s.handleAnomalyState(anomaly.StateSilenced))
	mux.HandleFunc("POST /v1/anomalies/{id}/resolve", s.handleAnomalyState(anomaly.StateResolved))
	mux.HandleFunc("POST /v1/anomalies/{id}/ignore", s.handleAnomalyState(anomaly.StateIgnored))

	mux.HandleFunc("GET /v1/workloads", s.handleListWorkloads)
	mux.HandleFunc("GET /v1/services", s.handleListServices)
	mux.HandleFunc("GET /v1/deployments", s.handleListDeployments)
	mux.HandleFunc("GET /v1/events", s.handleListEvents)
	mux.HandleFunc("GET /v1/incidents", s.handleListIncidents)
	mux.HandleFunc("GET /v1/summary", s.handleSummary)
	mux.HandleFunc("GET /v1/channels", s.handleListChannels)

	// New: unified Issues + per-namespace timeline + config diff feed.
	mux.HandleFunc("GET /v1/issues", s.handleListIssues)
	mux.HandleFunc("GET /v1/issues/{id}", s.handleGetIssue)
	mux.HandleFunc("POST /v1/issues/{id}/silence", s.handleIssueState("silenced"))
	mux.HandleFunc("POST /v1/issues/{id}/resolve", s.handleIssueState("resolved"))
	mux.HandleFunc("POST /v1/issues/{id}/ignore", s.handleIssueState("ignored"))
	mux.HandleFunc("GET /v1/timeline", s.handleTimeline)
	mux.HandleFunc("GET /v1/config-changes", s.handleConfigChanges)

	// Audit + onboarded users.
	mux.HandleFunc("GET /v1/audit", s.handleAudit)
	mux.HandleFunc("GET /v1/audit/actors", s.handleAuditActors)
	mux.HandleFunc("GET /v1/users", s.handleListUsers)
	mux.HandleFunc("POST /v1/users", s.handleCreateUser)
	mux.HandleFunc("DELETE /v1/users/{name}", s.handleDeleteUser)
	mux.HandleFunc("GET /v1/users/{name}/kubeconfig", s.handleUserKubeconfig)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	// kubectl-compatible reverse proxy to the in-cluster apiserver.
	// Register per-method to keep Go 1.22 ServeMux's strict-pattern
	// rules happy (it rejects mixing method-specific and method-
	// agnostic patterns at the same path level).
	if K8sAPIProxy != nil {
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"} {
			mux.Handle(m+" /k8s/", K8sAPIProxy)
		}
	}

	if s.webFS != nil {
		// no-cache the SPA so browsers don't pin old HTML/JS after a
		// detector image upgrade.
		fs := http.FileServer(http.FS(s.webFS))
		mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			fs.ServeHTTP(w, r)
		}))
	}
	return mux
}

// --- Ingest ---

type ingestBatch struct {
	Lines []types.LogLine `json:"lines"`
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	var batch ingestBatch
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&batch); err != nil {
		http.Error(w, "bad batch: "+err.Error(), http.StatusBadRequest)
		return
	}

	for _, line := range batch.Lines {
		// 1. Redact secrets BEFORE templating.
		line.Message = redact.Line(line.Message)
		// 2. Enrich with K8s metadata.
		s.enrich(&line)
		// 3. Observe.
		a, obs := s.detector.Observe(line)

		// Bump pod counts on existing anomaly even when no new fire.
		if obs.MatchedKnown && obs.Template != "" {
			count := s.detector.PodCount(obs.Workload, obs.Template)
			if count > 1 {
				s.store.BumpPods(obs.Workload, obs.Template, count)
			}
		}

		if a == nil {
			continue
		}

		// 4. Severity from blast radius (cross-workload check).
		a.Severity = s.scoreSeverity(*a)

		// 5. Fill RCA v2 (headline, story, timeline, confidence, suggestions).
		var rcaRollout rca.Rollout
		if s.k8sCache != nil {
			r := s.k8sCache.RecentRollout(a.Workload)
			rcaRollout = rca.Rollout{
				When: r.When, Image: r.Image, Digest: r.Digest, Commit: r.Commit,
			}
		}
		rca.Fill(a, rcaRollout)

		// 5a. Compute Before/After deployment counts for the hero panel.
		if !rcaRollout.When.IsZero() {
			window := time.Since(rcaRollout.When)
			if window < 5*time.Minute {
				window = 5 * time.Minute
			}
			if window > 30*time.Minute {
				window = 30 * time.Minute
			}
			before, after := s.detector.HitsAround(a.Workload, a.Template, rcaRollout.When, window)
			ba := &types.BeforeAfter{
				WindowSeconds: int(window.Seconds()),
				Before:        before,
				After:         after,
			}
			switch {
			case before == 0 && after > 0:
				ba.ChangePct = -1 // sentinel for ∞
			case before > 0:
				ba.ChangePct = (after - before) * 100 / before
			}
			a.BeforeAfter = ba
		}

		stored, fresh := s.store.Record(*a)
		if !fresh {
			continue
		}

		// 6. Dispatch alerts.
		go func(a types.Anomaly) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s.dispatcher.Dispatch(ctx, a)
		}(stored.Anomaly)

		slog.Info("anomaly fired",
			"id", stored.ID,
			"kind", stored.Kind,
			"severity", stored.Severity,
			"workload", stored.Workload.String(),
			"template", truncate(stored.Template, 60),
			"deployment_correlated", stored.DeploymentCorrelated,
			"confidence", stored.Confidence,
		)
	}

	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) enrich(line *types.LogLine) {
	if s.k8sCache == nil {
		return
	}
	meta, ok := s.k8sCache.LookupPod(line.Namespace, line.Pod)
	if !ok {
		return
	}
	if line.OwnerKind == "" {
		line.OwnerKind = meta.OwnerKind
	}
	if line.OwnerName == "" {
		line.OwnerName = meta.OwnerName
	}
	if line.Image == "" {
		line.Image = meta.Image
	}
	if line.ImageDigest == "" {
		line.ImageDigest = meta.ImageDigest
	}
	if line.Node == "" {
		line.Node = meta.Node
	}
}

// scoreSeverity blends pod count + cross-workload spread. Other
// concurrent anomalies in the same namespace upgrade severity (a single
// pod alone is Low; cluster-wide upgrades to Critical).
func (s *Server) scoreSeverity(a types.Anomaly) types.Severity {
	pods := a.AffectedPods
	if pods <= 0 {
		pods = 1
	}

	// Concurrent activity in same namespace within last 60s.
	others := 0
	otherWorkloads := map[string]struct{}{}
	cutoff := time.Now().Add(-60 * time.Second)
	for _, st := range s.store.All() {
		if st.Workload.Namespace != a.Workload.Namespace {
			continue
		}
		if st.Workload == a.Workload {
			continue
		}
		if st.FiredAt.Before(cutoff) {
			break
		}
		others++
		otherWorkloads[st.Workload.Name] = struct{}{}
	}

	switch {
	case len(otherWorkloads) >= 3:
		return types.SeverityCritical
	case len(otherWorkloads) >= 1 || pods >= 5:
		return types.SeverityHigh
	case pods >= 2:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

// --- Anomaly endpoints ---

func (s *Server) handleListAnomalies(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	f := anomaly.ListFilter{
		Limit:     limit,
		Severity:  types.Severity(q.Get("severity")),
		Namespace: q.Get("namespace"),
		Workload:  q.Get("workload"),
		State:     anomaly.State(q.Get("state")),
	}
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			f.Since = time.Now().Add(-d)
		}
	}
	out := s.store.List(f)
	writeJSON(w, map[string]any{"anomalies": out, "count": len(out)})
}

func (s *Server) handleGetAnomaly(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.store.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, a)
}

func (s *Server) handleAnomalyState(state anomaly.State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !s.store.SetState(id, state) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"id": id, "state": state})
	}
}

// --- Workloads ---

type workloadView struct {
	Workload      types.Workload `json:"workload"`
	Pods          int            `json:"pods"`
	Image         string         `json:"image,omitempty"`
	Digest        string         `json:"image_digest,omitempty"`
	LastRoll      time.Time      `json:"last_rollout,omitempty"`
	AnomalyCount  int            `json:"anomaly_count"`
	WorstSeverity types.Severity `json:"worst_severity,omitempty"`
}

func (s *Server) handleListWorkloads(w http.ResponseWriter, r *http.Request) {
	if s.k8sCache == nil {
		writeJSON(w, map[string]any{"workloads": []workloadView{}, "k8s_connected": false})
		return
	}

	agg := map[types.Workload]*workloadView{}
	for _, m := range s.k8sCache.PodsSnapshot() {
		wl := types.Workload{Namespace: m.Namespace, Kind: m.OwnerKind, Name: m.OwnerName}
		if wl.Name == "" {
			wl = types.Workload{Namespace: m.Namespace, Kind: "Pod", Name: m.PodName}
		}
		v, ok := agg[wl]
		if !ok {
			v = &workloadView{Workload: wl, Image: m.Image, Digest: m.ImageDigest}
			agg[wl] = v
		}
		v.Pods++
	}

	// Anomaly counts per workload.
	for _, st := range s.store.All() {
		if v, ok := agg[st.Workload]; ok {
			v.AnomalyCount++
			if severityRank(st.Severity) > severityRank(v.WorstSeverity) {
				v.WorstSeverity = st.Severity
			}
		}
	}

	for wl, v := range agg {
		r := s.k8sCache.RecentRollout(wl)
		v.LastRoll = r.When
	}

	out := make([]workloadView, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AnomalyCount != out[j].AnomalyCount {
			return out[i].AnomalyCount > out[j].AnomalyCount
		}
		return out[i].Workload.Namespace+out[i].Workload.Name <
			out[j].Workload.Namespace+out[j].Workload.Name
	})
	writeJSON(w, map[string]any{"workloads": out, "count": len(out), "k8s_connected": true})
}

// --- Services ---

func (s *Server) handleListServices(w http.ResponseWriter, _ *http.Request) {
	if s.k8sCache == nil {
		writeJSON(w, map[string]any{"services": []ppk8s.ServiceMeta{}, "k8s_connected": false})
		return
	}
	out := s.k8sCache.ServicesSnapshot()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	writeJSON(w, map[string]any{"services": out, "count": len(out), "k8s_connected": true})
}

// --- Deployments (rollouts with impact assessment) ---

type deploymentView struct {
	Workload          types.Workload `json:"workload"`
	When              time.Time      `json:"when"`
	Image             string         `json:"image,omitempty"`
	Digest            string         `json:"image_digest,omitempty"`
	Commit            string         `json:"commit,omitempty"`
	CausedAnomalies   int            `json:"caused_anomalies"`
	WorstSeverity     types.Severity `json:"worst_severity,omitempty"`
	IssueDetected     bool           `json:"issue_detected"`
}

func (s *Server) handleListDeployments(w http.ResponseWriter, r *http.Request) {
	if s.k8sCache == nil {
		writeJSON(w, map[string]any{"deployments": []deploymentView{}, "k8s_connected": false})
		return
	}
	rollouts := s.k8sCache.RolloutsSnapshot()
	all := s.store.All()

	out := make([]deploymentView, 0, len(rollouts))
	for wl, ro := range rollouts {
		// Filter rollouts older than 7 days.
		if time.Since(ro.When) > 7*24*time.Hour {
			continue
		}
		dv := deploymentView{
			Workload: wl, When: ro.When,
			Image: ro.Image, Digest: ro.Digest, Commit: ro.Commit,
		}
		// Count anomalies for this workload that fired AFTER the rollout.
		for _, a := range all {
			if a.Workload != wl {
				continue
			}
			if a.FiredAt.Before(ro.When) {
				continue
			}
			if a.FiredAt.Sub(ro.When) > 60*time.Minute {
				continue
			}
			dv.CausedAnomalies++
			if severityRank(a.Severity) > severityRank(dv.WorstSeverity) {
				dv.WorstSeverity = a.Severity
			}
			dv.IssueDetected = true
		}
		out = append(out, dv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.After(out[j].When) })
	writeJSON(w, map[string]any{"deployments": out, "count": len(out), "k8s_connected": true})
}

// --- Events (placeholder; will proxy K8s events in a future iteration) ---

func (s *Server) handleListEvents(w http.ResponseWriter, _ *http.Request) {
	// For now, surface anomalies as "events" so the page isn't empty.
	all := s.store.All()
	type ev struct {
		Time    time.Time `json:"time"`
		Type    string    `json:"type"`
		Subject string    `json:"subject"`
		Message string    `json:"message"`
	}
	out := make([]ev, 0, len(all))
	for _, a := range all {
		out = append(out, ev{
			Time:    a.FiredAt,
			Type:    string(a.Kind),
			Subject: a.Workload.String(),
			Message: a.Headline,
		})
	}
	writeJSON(w, map[string]any{"events": out, "count": len(out)})
}

// --- Incidents (anomalies grouped by namespace + 60s window) ---

type incidentView struct {
	ID            string         `json:"id"`
	Namespace     string         `json:"namespace"`
	StartedAt     time.Time      `json:"started_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	Workloads     []string       `json:"workloads"`
	WorstSeverity types.Severity `json:"worst_severity"`
	AnomalyCount  int            `json:"anomaly_count"`
	Headlines     []string       `json:"headlines"`
}

func (s *Server) handleListIncidents(w http.ResponseWriter, _ *http.Request) {
	all := s.store.All()
	// Group by namespace + 5-min bucket.
	type key struct {
		ns     string
		bucket int64
	}
	buckets := map[key]*incidentView{}
	for _, a := range all {
		k := key{a.Workload.Namespace, a.FiredAt.Unix() / 300}
		v, ok := buckets[k]
		if !ok {
			v = &incidentView{
				ID:        a.Workload.Namespace + "-" + strconv.FormatInt(k.bucket, 10),
				Namespace: a.Workload.Namespace,
				StartedAt: a.FiredAt,
				UpdatedAt: a.FiredAt,
			}
			buckets[k] = v
		}
		if a.FiredAt.Before(v.StartedAt) {
			v.StartedAt = a.FiredAt
		}
		if a.FiredAt.After(v.UpdatedAt) {
			v.UpdatedAt = a.FiredAt
		}
		v.AnomalyCount++
		if severityRank(a.Severity) > severityRank(v.WorstSeverity) {
			v.WorstSeverity = a.Severity
		}
		if !contains(v.Workloads, a.Workload.Name) {
			v.Workloads = append(v.Workloads, a.Workload.Name)
		}
		if a.Headline != "" && len(v.Headlines) < 3 && !contains(v.Headlines, a.Headline) {
			v.Headlines = append(v.Headlines, a.Headline)
		}
	}
	out := make([]incidentView, 0, len(buckets))
	for _, v := range buckets {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	writeJSON(w, map[string]any{"incidents": out, "count": len(out)})
}

// --- Summary (top of dashboard) ---

type summary struct {
	Total           int              `json:"total"`
	ActiveCount     int              `json:"active_count"`     // not silenced/resolved/ignored
	HighRiskCount   int              `json:"high_risk_count"`  // critical+high severity, active
	LowCount        int              `json:"low_count"`        // low severity, active (collapse target)
	BySeverity      map[string]int   `json:"by_severity"`
	TopWorkloads    []topWL          `json:"top_workloads"`
	RecentDeploys   []deploymentView `json:"recent_deployments"`
	Sparkline       []sparkPoint     `json:"sparkline"`
	K8sConnected    bool             `json:"k8s_connected"`
	Channels        []string         `json:"channels"`
	StoragePolicy   string           `json:"storage_policy"`
	StartedAt       time.Time        `json:"started_at"`
	PrimaryIncident *anomaly.Stored  `json:"primary_incident,omitempty"`
	Recommendations []recommendation `json:"recommendations"`
}

// recommendation is one decision-shaped suggestion shown on the Overview.
type recommendation struct {
	Title       string `json:"title"`        // e.g. "Rollback orbiter-auth"
	Reason      string `json:"reason"`       // why we're suggesting this
	Confidence  int    `json:"confidence"`   // 0-100
	AnomalyID   string `json:"anomaly_id,omitempty"`
	WorkloadName string `json:"workload_name,omitempty"`
	Command     string `json:"command,omitempty"` // shell command to execute / copy
}

type topWL struct {
	Workload     types.Workload `json:"workload"`
	AffectedPods int            `json:"affected_pods"`
	AnomalyCount int            `json:"anomaly_count"`
}

type sparkPoint struct {
	Time  time.Time `json:"time"`
	Count int       `json:"count"`
}

func (s *Server) handleSummary(w http.ResponseWriter, _ *http.Request) {
	all := s.store.All()
	since := time.Now().Add(-6 * time.Hour)

	sum := summary{
		BySeverity:    map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
		StoragePolicy: "templates_only",
		StartedAt:     s.startedAt,
		Channels:      append([]string(nil), s.channels...),
		K8sConnected:  s.k8sCache != nil,
	}
	wlAgg := map[types.Workload]*topWL{}
	var primary *anomaly.Stored
	primaryRank := -1
	for _, a := range all {
		if a.FiredAt.Before(since) {
			continue
		}
		sum.Total++
		sum.BySeverity[string(a.Severity)]++
		if a.State == anomaly.StateActive {
			sum.ActiveCount++
			switch a.Severity {
			case types.SeverityCritical, types.SeverityHigh:
				sum.HighRiskCount++
			case types.SeverityLow:
				sum.LowCount++
			}
			// Pick the primary incident: highest rank by severity +
			// deployment-correlation + recency.
			r := severityRank(a.Severity) * 100
			if a.DeploymentCorrelated {
				r += 50
			}
			if a.Confidence > 80 {
				r += 20
			}
			ageMins := time.Since(a.FiredAt).Minutes()
			if ageMins < 10 {
				r += 10 - int(ageMins)
			}
			if r > primaryRank {
				primaryRank = r
				primary = a
			}
		}

		v, ok := wlAgg[a.Workload]
		if !ok {
			v = &topWL{Workload: a.Workload}
			wlAgg[a.Workload] = v
		}
		v.AnomalyCount++
		if a.AffectedPods > v.AffectedPods {
			v.AffectedPods = a.AffectedPods
		}
	}
	sum.PrimaryIncident = primary
	for _, v := range wlAgg {
		sum.TopWorkloads = append(sum.TopWorkloads, *v)
	}
	sort.Slice(sum.TopWorkloads, func(i, j int) bool {
		if sum.TopWorkloads[i].AnomalyCount != sum.TopWorkloads[j].AnomalyCount {
			return sum.TopWorkloads[i].AnomalyCount > sum.TopWorkloads[j].AnomalyCount
		}
		return sum.TopWorkloads[i].AffectedPods > sum.TopWorkloads[j].AffectedPods
	})
	if len(sum.TopWorkloads) > 5 {
		sum.TopWorkloads = sum.TopWorkloads[:5]
	}

	// Sparkline: last 6h in 10-minute bins (36 buckets).
	const buckets = 36
	binDur := 6 * time.Hour / time.Duration(buckets)
	sum.Sparkline = make([]sparkPoint, buckets)
	now := time.Now()
	for i := 0; i < buckets; i++ {
		sum.Sparkline[i] = sparkPoint{Time: now.Add(-time.Duration(buckets-1-i) * binDur)}
	}
	for _, a := range all {
		idx := int(a.FiredAt.Sub(now.Add(-6*time.Hour)) / binDur)
		if idx >= 0 && idx < buckets {
			sum.Sparkline[idx].Count++
		}
	}

	// Recent deploys w/ impact.
	if s.k8sCache != nil {
		rollouts := s.k8sCache.RolloutsSnapshot()
		recent := []deploymentView{}
		for wl, ro := range rollouts {
			if time.Since(ro.When) > 24*time.Hour {
				continue
			}
			dv := deploymentView{Workload: wl, When: ro.When, Image: ro.Image, Commit: ro.Commit}
			for _, a := range all {
				if a.Workload != wl {
					continue
				}
				if a.FiredAt.Before(ro.When) {
					continue
				}
				if a.FiredAt.Sub(ro.When) > 60*time.Minute {
					continue
				}
				dv.CausedAnomalies++
				if severityRank(a.Severity) > severityRank(dv.WorstSeverity) {
					dv.WorstSeverity = a.Severity
				}
				dv.IssueDetected = true
			}
			recent = append(recent, dv)
		}
		sort.Slice(recent, func(i, j int) bool { return recent[i].When.After(recent[j].When) })
		if len(recent) > 5 {
			recent = recent[:5]
		}
		sum.RecentDeploys = recent
	}

	// Smart, decision-shaped recommendations: deployment-caused issues
	// outrank everything, then high-risk workloads, then noise.
	for _, d := range sum.RecentDeploys {
		if d.IssueDetected && d.WorstSeverity != types.SeverityLow {
			ttd := ""
			// Find the matching primary anomaly to get TTD.
			for _, a := range all {
				if a.Workload == d.Workload && a.DeploymentCorrelated && a.TimeToDetectionSeconds > 0 {
					ttd = humanizeSeconds(a.TimeToDetectionSeconds)
					break
				}
			}
			reason := "New errors started immediately after deployment"
			if ttd != "" {
				reason = "Errors detected " + ttd + " after rollout"
			}
			sum.Recommendations = append(sum.Recommendations, recommendation{
				Title:        "Rollback " + d.Workload.Name,
				Reason:       reason,
				Confidence:   confidenceForDeploy(d, all),
				WorkloadName: d.Workload.Name,
				Command:      "kubectl rollout undo " + strings.ToLower(string(d.Workload.Kind)) + "/" + d.Workload.Name + " -n " + d.Workload.Namespace,
			})
		}
	}
	if primary != nil && len(sum.Recommendations) == 0 {
		sum.Recommendations = append(sum.Recommendations, recommendation{
			Title:        "Investigate " + primary.Workload.Name,
			Reason:       primary.Headline,
			Confidence:   primary.Confidence,
			AnomalyID:    primary.ID,
			WorkloadName: primary.Workload.Name,
			Command:      "kubectl logs -n " + primary.Workload.Namespace + " " + strings.ToLower(string(primary.Workload.Kind)) + "/" + primary.Workload.Name + " --tail=100",
		})
	}

	writeJSON(w, sum)
}

// --- Issues (unified incident view) ---

func (s *Server) handleListIssues(w http.ResponseWriter, r *http.Request) {
	if s.issueEngine == nil {
		writeJSON(w, map[string]any{"issues": []*issue.Issue{}, "count": 0})
		return
	}
	q := r.URL.Query()
	all := s.issueEngine.All()
	out := make([]*issue.Issue, 0, len(all))
	wantType := q.Get("type")
	wantState := q.Get("state")
	wantNS := q.Get("namespace")
	for _, iss := range all {
		if wantType != "" && string(iss.Type) != wantType {
			continue
		}
		if wantState != "" && iss.State != wantState {
			continue
		}
		if wantNS != "" && iss.Workload.Namespace != wantNS {
			continue
		}
		out = append(out, iss)
	}
	writeJSON(w, map[string]any{"issues": out, "count": len(out)})
}

func (s *Server) handleGetIssue(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.issueEngine == nil {
		http.Error(w, "engine not initialized", http.StatusServiceUnavailable)
		return
	}
	iss, ok := s.issueEngine.Get(id)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, iss)
}

func (s *Server) handleIssueState(state string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if s.issueEngine == nil || !s.issueEngine.SetState(id, state) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"id": id, "state": state})
	}
}

// --- Timeline (what changed in a namespace recently) ---

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ns := q.Get("namespace")
	since := time.Now().Add(-1 * time.Hour)
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}

	type tlItem struct {
		When  time.Time `json:"when"`
		Kind  string    `json:"kind"`
		Label string    `json:"label"`
		Detail string   `json:"detail,omitempty"`
	}
	out := []tlItem{}

	// Deployments in namespace.
	if s.k8sCache != nil {
		for wl, ro := range s.k8sCache.RolloutsSnapshot() {
			if ns != "" && wl.Namespace != ns {
				continue
			}
			if ro.When.Before(since) {
				continue
			}
			detail := ro.Image
			if ro.Commit != "" {
				detail += " · " + ro.Commit[:min(7, len(ro.Commit))]
			}
			out = append(out, tlItem{When: ro.When, Kind: "deploy", Label: wl.Name + " rolled out", Detail: detail})
		}
	}
	// Config changes in namespace.
	if s.configWatcher != nil {
		nsList := []string{ns}
		if ns == "" {
			nsList = []string{}
			seen := map[string]struct{}{}
			for _, c := range s.configWatcher.RecentChanges(500) {
				if c.When.Before(since) {
					continue
				}
				if _, ok := seen[c.Namespace]; ok {
					continue
				}
				seen[c.Namespace] = struct{}{}
				nsList = append(nsList, c.Namespace)
			}
		}
		for _, n := range nsList {
			for _, c := range s.configWatcher.ChangesForNamespace(n, since) {
				detail := describeChangesShort(c.Changes)
				out = append(out, tlItem{When: c.When, Kind: "config_change",
					Label: string(c.Kind) + " " + c.Name + " changed", Detail: detail})
			}
		}
	}
	// Active issues / events.
	if s.issueEngine != nil {
		for _, iss := range s.issueEngine.All() {
			if ns != "" && iss.Workload.Namespace != ns {
				continue
			}
			if iss.FiredAt.Before(since) {
				continue
			}
			out = append(out, tlItem{When: iss.FiredAt, Kind: "issue", Label: iss.HumanHeadline})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.Before(out[j].When) })
	writeJSON(w, map[string]any{"items": out, "count": len(out)})
}

func describeChangesShort(changes []ppk8s.KeyChange) string {
	if len(changes) == 0 {
		return ""
	}
	if len(changes) == 1 {
		c := changes[0]
		return string(c.Type) + ": " + c.Key
	}
	return strconv.Itoa(len(changes)) + " keys changed"
}

// --- Config changes feed ---

func (s *Server) handleConfigChanges(w http.ResponseWriter, r *http.Request) {
	if s.configWatcher == nil {
		writeJSON(w, map[string]any{"changes": []any{}, "count": 0})
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	changes := s.configWatcher.RecentChanges(limit)
	writeJSON(w, map[string]any{"changes": changes, "count": len(changes)})
}

func min(a, b int) int { if a < b { return a }; return b }

// --- Channels ---

func (s *Server) handleListChannels(w http.ResponseWriter, _ *http.Request) {
	out := make([]map[string]any, 0, len(s.channels))
	for _, c := range s.channels {
		out = append(out, map[string]any{"name": c, "configured": true})
	}
	writeJSON(w, map[string]any{"channels": out, "count": len(out)})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func severityRank(s types.Severity) int {
	switch s {
	case types.SeverityCritical:
		return 4
	case types.SeverityHigh:
		return 3
	case types.SeverityMedium:
		return 2
	case types.SeverityLow:
		return 1
	}
	return 0
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// strings used in this file (suppress unused-import warning if pruning later).
var _ = strings.HasPrefix

func humanizeSeconds(s int) string {
	if s < 60 {
		return strconv.Itoa(s) + "s"
	}
	if s < 3600 {
		return strconv.Itoa(s/60) + "m"
	}
	return strconv.Itoa(s/3600) + "h"
}

func confidenceForDeploy(d deploymentView, all []*anomaly.Stored) int {
	for _, a := range all {
		if a.Workload == d.Workload && a.DeploymentCorrelated && a.Confidence > 0 {
			return a.Confidence
		}
	}
	return 70
}

// --- Audit ---

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.auditWatcher == nil {
		writeJSON(w, map[string]any{"events": []ppk8s.AuditEvent{}, "count": 0, "available": false})
		return
	}
	q := r.URL.Query()
	f := ppk8s.AuditFilter{
		Limit:      300,
		Actor:      q.Get("actor"),
		Namespace:  q.Get("namespace"),
		Kind:       q.Get("kind"),
		Action:     ppk8s.AuditAction(q.Get("action")),
		OnlyHumans: q.Get("only_humans") == "true",
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			f.Limit = n
		}
	}
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			f.Since = time.Now().Add(-d)
		}
	}
	events := s.auditWatcher.Query(f)
	writeJSON(w, map[string]any{"events": events, "count": len(events), "available": true})
}

func (s *Server) handleAuditActors(w http.ResponseWriter, _ *http.Request) {
	if s.auditWatcher == nil {
		writeJSON(w, map[string]any{"actors": []ppk8s.ActorStat{}, "count": 0})
		return
	}
	a := s.auditWatcher.Actors()
	writeJSON(w, map[string]any{"actors": a, "count": len(a)})
}

// --- Onboarded users ---

func (s *Server) handleListUsers(w http.ResponseWriter, _ *http.Request) {
	if s.userManager == nil {
		writeJSON(w, map[string]any{"users": []users.User{}, "count": 0, "available": false})
		return
	}
	list := s.userManager.List()
	writeJSON(w, map[string]any{"users": list, "count": len(list), "available": true})
}

type createUserReq struct {
	Name        string      `json:"name"`
	Namespace   string      `json:"namespace"`
	Scope       users.Scope `json:"scope"`
	Description string      `json:"description"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if s.userManager == nil {
		http.Error(w, "user manager unavailable (k8s integration disabled)", http.StatusServiceUnavailable)
		return
	}
	var body createUserReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
		http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
		return
	}
	u := users.User{
		Name:        body.Name,
		Namespace:   body.Namespace,
		Scope:       body.Scope,
		Description: body.Description,
	}
	created, err := s.userManager.Onboard(r.Context(), u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, created)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	if s.userManager == nil {
		http.Error(w, "user manager unavailable", http.StatusServiceUnavailable)
		return
	}
	name := r.PathValue("name")
	if err := s.userManager.Remove(r.Context(), name); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUserKubeconfig(w http.ResponseWriter, r *http.Request) {
	if s.userManager == nil {
		http.Error(w, "user manager unavailable", http.StatusServiceUnavailable)
		return
	}
	name := r.PathValue("name")
	ttl := int64(3600)
	if v := r.URL.Query().Get("ttl"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n <= 24*3600 {
			ttl = n
		}
	}
	cfg, err := s.userManager.Kubeconfig(r.Context(), name, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.kubeconfig"`)
	_, _ = io.WriteString(w, cfg)
}
