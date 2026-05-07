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
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/podpulse/podpulse/internal/alert"
	"github.com/podpulse/podpulse/internal/anomaly"
	"github.com/podpulse/podpulse/internal/detect/templates"
	"github.com/google/uuid"
	"github.com/podpulse/podpulse/internal/auth"
	"github.com/podpulse/podpulse/internal/connect"
	"github.com/podpulse/podpulse/internal/clusters"
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
	clusterStore  *clusters.Store
	authMgr       *auth.Manager
	connectHub    *connect.Hub
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
	ClusterStore  *clusters.Store
	Auth          *auth.Manager
	ConnectHub    *connect.Hub
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
		clusterStore:  opts.ClusterStore,
		authMgr:       opts.Auth,
		connectHub:    opts.ConnectHub,
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

	// Bring-your-own-kubeconfig clusters (multi-cluster scaffold).
	mux.HandleFunc("GET /v1/clusters", s.handleListClusters)
	mux.HandleFunc("POST /v1/clusters", s.handleRegisterCluster)
	mux.HandleFunc("DELETE /v1/clusters/{id}", s.handleDeleteCluster)

	// Agent-tunnel onboarding (pp-connect dials home).
	if s.connectHub != nil {
		mux.HandleFunc("POST /v1/clusters/connect/token", s.handleCreatePairingToken)
		mux.HandleFunc("GET /v1/clusters/connect/status/{token}", s.handleConnectStatus)
		mux.Handle("/v1/connect", s.connectHub) // WS upgrade — agent dials this
	}

	// Auth endpoints (only mounted when Postgres + auth manager exist).
	if s.authMgr != nil && s.authMgr.Available() {
		mux.HandleFunc("POST /v1/auth/signup", s.handleSignup)
		mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
		mux.HandleFunc("POST /v1/auth/logout", s.handleLogout)
		mux.HandleFunc("GET /v1/auth/me", s.handleAuthMe)
		mux.HandleFunc("GET /v1/proxy-audit", s.handleProxyAuditList)
	}

	// Cluster-scoped onboarding flow.
	mux.HandleFunc("GET /v1/clusters/{id}/users", s.handleListClusterUsers)
	mux.HandleFunc("POST /v1/clusters/{id}/users", s.handleCreateClusterUser)
	mux.HandleFunc("DELETE /v1/clusters/{id}/users/{name}", s.handleDeleteClusterUser)
	mux.HandleFunc("GET /v1/clusters/{id}/users/{name}/kubeconfig", s.handleClusterUserKubeconfig)

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

	// Wrap the whole mux in the auth middleware: it resolves the
	// session token (cookie or Bearer) into an Identity stored in the
	// request context. Handlers can pull it via auth.IdentityFromContext.
	// Single-tenant fallback: when authMgr is unavailable, requests
	// flow through with a nil Identity — handlers treat that as
	// "no org scoping".
	return s.authMiddleware(mux)
}

// authMiddleware resolves the session and gates protected endpoints.
//
// Always allowed (even unauthenticated):
//   /healthz, /v1/auth/*, /k8s/* (kubectl uses its own SA bearer),
//   GET / and any static asset under the SPA root.
//
// Gated when auth is available:
//   every other /v1/* call requires a valid session.
//
// Admin-only writes:
//   POST/DELETE on /v1/clusters, /v1/users, /v1/clusters/*/users.
//   Members get 403.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Always-public paths.
		if isPublicPath(path) {
			next.ServeHTTP(w, r)
			return
		}

		// /k8s/* uses its own bearer-token auth at the apiserver layer.
		if strings.HasPrefix(path, "/k8s/") {
			next.ServeHTTP(w, r)
			return
		}

		if s.authMgr == nil || !s.authMgr.Available() {
			// Single-tenant fallback — no auth wired up, let everything through.
			next.ServeHTTP(w, r)
			return
		}

		token := auth.TokenFromRequest(r)
		ident, err := s.authMgr.Resolve(r.Context(), token)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Admin-only writes.
		if isAdminOnly(r) && !ident.IsAdmin() {
			http.Error(w, "forbidden: admin role required", http.StatusForbidden)
			return
		}

		r = r.WithContext(auth.WithIdentity(r.Context(), ident))
		next.ServeHTTP(w, r)
	})
}

func isPublicPath(p string) bool {
	switch p {
	case "/healthz":
		return true
	case "/v1/connect":
		// WS endpoint — pp-connect agent authenticates with its own
		// pairing token (X-PodPulse-Token header), not a session cookie.
		return true
	}
	if strings.HasPrefix(p, "/v1/auth/") {
		return true
	}
	// Static SPA: anything not under /v1.
	if !strings.HasPrefix(p, "/v1/") {
		return true
	}
	return false
}

func isAdminOnly(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return false
	}
	p := r.URL.Path
	switch {
	case p == "/v1/clusters":
		return true
	case p == "/v1/clusters/connect/token":
		return true
	case strings.HasPrefix(p, "/v1/clusters/") && strings.Contains(p, "/users"):
		return true
	case p == "/v1/users":
		return true
	case strings.HasPrefix(p, "/v1/clusters/"): // DELETE /v1/clusters/{id}
		return true
	case strings.HasPrefix(p, "/v1/users/"):
		return true
	}
	return false
}

// orgFromCtx returns the calling org's UUID, or uuid.Nil for
// single-tenant fallback.
func orgFromCtx(r *http.Request) uuid.UUID {
	id := auth.IdentityFromContext(r.Context())
	if id == nil {
		return uuid.Nil
	}
	return id.OrgID
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

// --- Auth (multi-tenant) ---

type signupReq struct {
	OrgName     string `json:"org_name"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var body signupReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	token, ident, err := s.authMgr.Signup(r.Context(), body.OrgName, body.Email, body.Password, body.DisplayName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	auth.SetSessionCookie(w, r, token)
	writeJSON(w, map[string]any{
		"identity": identityWire(ident),
		"token":    token,
	})
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body loginReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	token, ident, err := s.authMgr.Login(r.Context(), body.Email, body.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	auth.SetSessionCookie(w, r, token)
	writeJSON(w, map[string]any{
		"identity": identityWire(ident),
		"token":    token,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	tok := auth.TokenFromRequest(r)
	_ = s.authMgr.Logout(r.Context(), tok)
	auth.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	tok := auth.TokenFromRequest(r)
	ident, err := s.authMgr.Resolve(r.Context(), tok)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, identityWire(ident))
}

func identityWire(i *auth.Identity) map[string]any {
	return map[string]any{
		"user_id":      i.UserID,
		"org_id":       i.OrgID,
		"org_name":     i.OrgName,
		"org_slug":     i.OrgSlug,
		"email":        i.Email,
		"role":         i.Role,
		"display_name": i.Display,
	}
}

// --- Proxy audit log ---

func (s *Server) handleProxyAuditList(w http.ResponseWriter, r *http.Request) {
	if s.authMgr == nil || !s.authMgr.Available() {
		writeJSON(w, map[string]any{"events": []any{}, "count": 0, "available": false})
		return
	}
	q := r.URL.Query()
	limit := 200
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	since := time.Now().Add(-24 * time.Hour)
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	orgID := orgFromCtx(r)

	type row struct {
		Time      time.Time `json:"time"`
		ClusterID string    `json:"cluster_id,omitempty"`
		User      string    `json:"user,omitempty"`
		Method    string    `json:"method"`
		Path      string    `json:"path"`
		Status    int       `json:"status"`
		Duration  int       `json:"duration_ms"`
		ClientIP  string    `json:"client_ip,omitempty"`
	}

	// We use the auth manager's pool indirectly via a direct query.
	// Reuses the same connection pool; tenant isolation enforced via
	// `WHERE org_id = $1` (or NULL match in single-tenant mode).
	pool := s.authMgr.Pool()
	if pool == nil {
		writeJSON(w, map[string]any{"events": []any{}, "count": 0, "available": false})
		return
	}

	var rows pgxRows
	var err error
	if orgID == uuid.Nil {
		rows, err = pool.Query(r.Context(), `
			SELECT ts, cluster_id::text, COALESCE(user_name,''), method, path, status, duration_ms, COALESCE(client_ip,'')
			FROM proxy_audit WHERE ts >= $1 ORDER BY ts DESC LIMIT $2`,
			since, limit)
	} else {
		rows, err = pool.Query(r.Context(), `
			SELECT ts, cluster_id::text, COALESCE(user_name,''), method, path, status, duration_ms, COALESCE(client_ip,'')
			FROM proxy_audit
			WHERE org_id = $1 AND ts >= $2 ORDER BY ts DESC LIMIT $3`,
			orgID, since, limit)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []row{}
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.Time, &x.ClusterID, &x.User, &x.Method, &x.Path, &x.Status, &x.Duration, &x.ClientIP); err != nil {
			continue
		}
		out = append(out, x)
	}
	writeJSON(w, map[string]any{"events": out, "count": len(out), "available": true})
}

// pgxRows is the small slice of pgx.Rows we use, declared as an
// interface so this file doesn't have to import pgx directly.
type pgxRows interface {
	Next() bool
	Scan(dest ...any) error
	Close()
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
	clusterID := r.URL.Query().Get("cluster_id")
	if err := s.userManager.Remove(r.Context(), clusterID, name); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Cluster-scoped users ---

func (s *Server) handleListClusterUsers(w http.ResponseWriter, r *http.Request) {
	if s.userManager == nil {
		writeJSON(w, map[string]any{"users": []any{}, "count": 0})
		return
	}
	id := r.PathValue("id")
	out := s.userManager.ListForCluster(id)
	writeJSON(w, map[string]any{"users": out, "count": len(out)})
}

func (s *Server) handleCreateClusterUser(w http.ResponseWriter, r *http.Request) {
	if s.userManager == nil {
		http.Error(w, "user manager unavailable", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	var body createUserReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
		http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
		return
	}
	u := users.User{
		Name: body.Name, Namespace: body.Namespace, Scope: body.Scope,
		Description: body.Description, ClusterID: id,
	}
	out, err := s.userManager.OnboardInCluster(r.Context(), u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, out)
}

func (s *Server) handleDeleteClusterUser(w http.ResponseWriter, r *http.Request) {
	if s.userManager == nil {
		http.Error(w, "user manager unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := s.userManager.Remove(r.Context(), r.PathValue("id"), r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleClusterUserKubeconfig(w http.ResponseWriter, r *http.Request) {
	if s.userManager == nil {
		http.Error(w, "user manager unavailable", http.StatusServiceUnavailable)
		return
	}
	id := r.PathValue("id")
	name := r.PathValue("name")
	ttl := int64(3600)
	if v := r.URL.Query().Get("ttl"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 && n <= 24*3600 {
			ttl = n
		}
	}
	cfg, err := s.userManager.Kubeconfig(r.Context(), id, name, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.kubeconfig"`)
	_, _ = io.WriteString(w, cfg)
}

// --- Clusters (BYO kubeconfig) ---

func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request) {
	if s.clusterStore == nil {
		writeJSON(w, map[string]any{"clusters": []any{}, "count": 0, "available": false})
		return
	}
	list, err := s.clusterStore.List(r.Context(), orgFromCtx(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"clusters": list, "count": len(list), "available": true})
}

type registerClusterReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Kubeconfig  string `json:"kubeconfig"`
}

func (s *Server) handleRegisterCluster(w http.ResponseWriter, r *http.Request) {
	if s.clusterStore == nil {
		http.Error(w, "cluster registry not initialized", http.StatusServiceUnavailable)
		return
	}
	var body registerClusterReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
		return
	}
	createdBy := "ui"
	if id := auth.IdentityFromContext(r.Context()); id != nil {
		createdBy = id.Email
	}
	c, err := s.clusterStore.Register(r.Context(), orgFromCtx(r), body.Name, body.Kubeconfig, body.Description, createdBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, c)
}

func (s *Server) handleDeleteCluster(w http.ResponseWriter, r *http.Request) {
	if s.clusterStore == nil {
		http.Error(w, "cluster registry not initialized", http.StatusServiceUnavailable)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := s.clusterStore.Delete(r.Context(), orgFromCtx(r), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Agent-tunnel onboarding (pp-connect) ---

type createPairingTokenReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleCreatePairingToken(w http.ResponseWriter, r *http.Request) {
	if s.connectHub == nil {
		http.Error(w, "agent-tunnel not enabled (Postgres required)", http.StatusServiceUnavailable)
		return
	}
	var body createPairingTokenReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	createdBy := "ui"
	if id := auth.IdentityFromContext(r.Context()); id != nil {
		createdBy = id.Email
	}
	token, err := s.connectHub.CreatePairingToken(r.Context(), orgFromCtx(r), body.Name, body.Description, createdBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	saasURL := strings.TrimRight(externalURLFromRequest(r), "/")
	helmCmd := strings.TrimSpace(`
helm upgrade --install podpulse-connect oci://ghcr.io/avnshrai/charts/podpulse-connect \
  --namespace podpulse-system --create-namespace \
  --set saas.url=` + saasURL + ` \
  --set saas.token=` + token)

	kubectlYAML := buildAgentManifest(saasURL, token)

	writeJSON(w, map[string]any{
		"token":           token,
		"expires_in_secs": 3600,
		"helm_command":    helmCmd,
		"kubectl_yaml":    kubectlYAML,
	})
}

// handleConnectStatus polls a pairing token; returns whether the agent
// has dialed home yet, and (when paired) the cluster_id to navigate to.
func (s *Server) handleConnectStatus(w http.ResponseWriter, r *http.Request) {
	if s.connectHub == nil || s.authMgr == nil || !s.authMgr.Available() {
		http.Error(w, "agent-tunnel not enabled", http.StatusServiceUnavailable)
		return
	}
	token := r.PathValue("token")
	if !strings.HasPrefix(token, "ppc_") {
		http.Error(w, "bad token", http.StatusBadRequest)
		return
	}
	pool := s.authMgr.Pool()
	if pool == nil {
		http.Error(w, "no DB pool", http.StatusServiceUnavailable)
		return
	}
	var (
		usedAt    *time.Time
		clusterID *uuid.UUID
		expiresAt time.Time
		orgID     *uuid.UUID
	)
	err := pool.QueryRow(r.Context(), `
		SELECT used_at, cluster_id, expires_at, org_id
		FROM pairing_tokens WHERE token = $1`, token).
		Scan(&usedAt, &clusterID, &expiresAt, &orgID)
	if err != nil {
		http.Error(w, "token not found", http.StatusNotFound)
		return
	}
	// Org isolation: poller must be on the same org as the token.
	caller := orgFromCtx(r)
	if caller != uuid.Nil && orgID != nil && *orgID != caller {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	online := false
	if clusterID != nil {
		online = s.connectHub.IsOnline(*clusterID)
	}
	out := map[string]any{
		"paired":     clusterID != nil,
		"online":     online,
		"expires_at": expiresAt,
	}
	if clusterID != nil {
		out["cluster_id"] = clusterID.String()
	}
	if usedAt != nil {
		out["used_at"] = usedAt
	}
	writeJSON(w, out)
}

// externalURLFromRequest returns the public-facing URL the SPA was
// loaded from. Used to pre-fill the helm command shown in the UI.
func externalURLFromRequest(r *http.Request) string {
	if v := os.Getenv("PODPULSE_EXTERNAL_URL"); v != "" {
		return v
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		host = v
	}
	return scheme + "://" + host
}

// buildAgentManifest produces a self-contained YAML the user can pipe
// to `kubectl apply -f -`. Saves them from needing helm.
func buildAgentManifest(saasURL, token string) string {
	const tmpl = `# pp-connect — PodPulse cluster-tunnel agent.
# Apply with:  kubectl apply -f <(curl -s ...)   or  kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata: {name: podpulse-system}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: pp-connect, namespace: podpulse-system}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: pp-connect-admin}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: pp-connect
  namespace: podpulse-system
---
apiVersion: v1
kind: Secret
metadata: {name: pp-connect-token, namespace: podpulse-system}
type: Opaque
stringData:
  token: TOKEN_PLACEHOLDER
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: pp-connect, namespace: podpulse-system}
spec:
  replicas: 1
  selector: {matchLabels: {app: pp-connect}}
  template:
    metadata: {labels: {app: pp-connect}}
    spec:
      serviceAccountName: pp-connect
      containers:
      - name: agent
        image: ghcr.io/avnshrai/podpulse/pp-connect:latest
        env:
        - {name: PP_SAAS_URL, value: "SAAS_URL_PLACEHOLDER"}
        - name: PP_TOKEN
          valueFrom:
            secretKeyRef:
              name: pp-connect-token
              key: token
        resources:
          requests: {cpu: 50m, memory: 64Mi}
          limits:   {cpu: 250m, memory: 256Mi}
`
	out := strings.ReplaceAll(tmpl, "TOKEN_PLACEHOLDER", token)
	out = strings.ReplaceAll(out, "SAAS_URL_PLACEHOLDER", saasURL)
	return out
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
	clusterID := r.URL.Query().Get("cluster_id")
	cfg, err := s.userManager.Kubeconfig(r.Context(), clusterID, name, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.kubeconfig"`)
	_, _ = io.WriteString(w, cfg)
}
