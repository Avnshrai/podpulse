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
	ppk8s "github.com/podpulse/podpulse/internal/k8s"
	"github.com/podpulse/podpulse/internal/rca"
	"github.com/podpulse/podpulse/internal/redact"
	"github.com/podpulse/podpulse/internal/types"
)

type Server struct {
	store      *anomaly.Store
	detector   *templates.Detector
	dispatcher *alert.Dispatcher
	webFS      fs.FS
	k8sCache   *ppk8s.Cache
	channels   []string // names of configured channels
	startedAt  time.Time
}

type Options struct {
	Store      *anomaly.Store
	Detector   *templates.Detector
	Dispatcher *alert.Dispatcher
	WebFS      fs.FS
	K8sCache   *ppk8s.Cache
	Channels   []string
}

func NewServer(opts Options) *Server {
	return &Server{
		store:      opts.Store,
		detector:   opts.Detector,
		dispatcher: opts.Dispatcher,
		webFS:      opts.WebFS,
		k8sCache:   opts.K8sCache,
		channels:   opts.Channels,
		startedAt:  time.Now(),
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

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	if s.webFS != nil {
		mux.Handle("GET /", http.FileServer(http.FS(s.webFS)))
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
