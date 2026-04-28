// Package api wires up the detector's HTTP surface:
//
//	POST /v1/ingest           tailer ships log-line batches here
//	GET  /v1/anomalies        list anomalies (newest first)
//	GET  /v1/anomalies/{id}   single anomaly drill-down
//	GET  /v1/workloads        list workloads the K8s informer has seen
//	GET  /healthz             readiness/liveness
//	GET  /                    embedded animated single-page view
package api

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/podpulse/podpulse/internal/alert"
	"github.com/podpulse/podpulse/internal/anomaly"
	"github.com/podpulse/podpulse/internal/detect/templates"
	ppk8s "github.com/podpulse/podpulse/internal/k8s"
	"github.com/podpulse/podpulse/internal/rca"
	"github.com/podpulse/podpulse/internal/types"
)

type Server struct {
	store      *anomaly.Store
	detector   *templates.Detector
	dispatcher *alert.Dispatcher
	webFS      fs.FS

	// k8sCache is optional. When nil, ingest enrichment + RCA rollout
	// context are skipped — the detector still works in standalone /
	// demo mode.
	k8sCache *ppk8s.Cache
}

type Options struct {
	Store      *anomaly.Store
	Detector   *templates.Detector
	Dispatcher *alert.Dispatcher
	WebFS      fs.FS
	K8sCache   *ppk8s.Cache // nil-safe
}

func NewServer(opts Options) *Server {
	return &Server{
		store:      opts.Store,
		detector:   opts.Detector,
		dispatcher: opts.Dispatcher,
		webFS:      opts.WebFS,
		k8sCache:   opts.K8sCache,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ingest", s.handleIngest)
	mux.HandleFunc("GET /v1/anomalies", s.handleListAnomalies)
	mux.HandleFunc("GET /v1/anomalies/{id}", s.handleGetAnomaly)
	mux.HandleFunc("GET /v1/workloads", s.handleListWorkloads)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})
	if s.webFS != nil {
		mux.Handle("GET /", http.FileServer(http.FS(s.webFS)))
	}
	return mux
}

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
		s.enrich(&line)
		a := s.detector.Observe(line)
		if a == nil {
			continue
		}

		var rollout rca.Rollout
		if s.k8sCache != nil {
			r := s.k8sCache.RecentRollout(a.Workload)
			rollout = rca.Rollout{
				When:   r.When,
				Image:  r.Image,
				Digest: r.Digest,
				Commit: r.Commit,
			}
		}
		rca.Fill(a, rollout)

		if !s.store.Record(*a) {
			continue
		}

		go func(a types.Anomaly) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s.dispatcher.Dispatch(ctx, a)
		}(*a)

		slog.Info("anomaly fired",
			"id", a.ID,
			"kind", a.Kind,
			"workload", a.Workload.String(),
			"template", truncate(a.Template, 80),
		)
	}

	w.WriteHeader(http.StatusAccepted)
}

// enrich fills owner/image/digest from the K8s informer cache if the
// tailer didn't supply them. Tailers running on real nodes can't cheaply
// know the owner-controller of a pod from the file path alone, so the
// detector resolves it here.
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

func (s *Server) handleListAnomalies(w http.ResponseWriter, _ *http.Request) {
	out := s.store.List(100)
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

type workloadView struct {
	Workload types.Workload `json:"workload"`
	Pods     int            `json:"pods"`
	Image    string         `json:"image,omitempty"`
	Digest   string         `json:"image_digest,omitempty"`
	LastRoll time.Time      `json:"last_rollout,omitempty"`
}

func (s *Server) handleListWorkloads(w http.ResponseWriter, _ *http.Request) {
	if s.k8sCache == nil {
		writeJSON(w, map[string]any{"workloads": []workloadView{}, "k8s_connected": false})
		return
	}

	agg := map[types.Workload]*workloadView{}
	for _, m := range s.k8sCache.PodsSnapshot() {
		wl := types.Workload{Namespace: m.Namespace, Kind: m.OwnerKind, Name: m.OwnerName}
		if wl.Name == "" {
			wl.Kind = "Pod"
			wl.Name = m.PodName
		}
		v, ok := agg[wl]
		if !ok {
			v = &workloadView{Workload: wl, Image: m.Image, Digest: m.ImageDigest}
			agg[wl] = v
		}
		v.Pods++
		if v.Image == "" {
			v.Image = m.Image
		}
		if v.Digest == "" {
			v.Digest = m.ImageDigest
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
		if out[i].Workload.Namespace != out[j].Workload.Namespace {
			return out[i].Workload.Namespace < out[j].Workload.Namespace
		}
		return out[i].Workload.Name < out[j].Workload.Name
	})
	writeJSON(w, map[string]any{"workloads": out, "count": len(out), "k8s_connected": true})
}

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
