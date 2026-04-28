// Package api wires up the detector's HTTP surface:
//
//	POST /v1/ingest           tailer ships log-line batches here
//	GET  /v1/anomalies        CLI + web view list anomalies (newest first)
//	GET  /v1/anomalies/{id}   single anomaly drill-down
//	GET  /healthz             readiness/liveness
//	GET  /                    embedded animated single-page view
//
// One package, one file — keep the surface small until we have a
// reason to split.
package api

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/podpulse/podpulse/internal/alert"
	"github.com/podpulse/podpulse/internal/anomaly"
	"github.com/podpulse/podpulse/internal/detect/templates"
	"github.com/podpulse/podpulse/internal/rca"
	"github.com/podpulse/podpulse/internal/types"
)

type Server struct {
	store      *anomaly.Store
	detector   *templates.Detector
	dispatcher *alert.Dispatcher
	webFS      fs.FS
}

func NewServer(store *anomaly.Store, det *templates.Detector, disp *alert.Dispatcher, webFS fs.FS) *Server {
	return &Server{store: store, detector: det, dispatcher: disp, webFS: webFS}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/ingest", s.handleIngest)
	mux.HandleFunc("GET /v1/anomalies", s.handleListAnomalies)
	mux.HandleFunc("GET /v1/anomalies/{id}", s.handleGetAnomaly)
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
		a := s.detector.Observe(line)
		if a == nil {
			continue
		}
		// Phase 1: no rollout context yet — pass an empty Rollout.
		// Phase 3 wires K8s informer data here.
		rca.Fill(a, rca.Rollout{})

		if !s.store.Record(*a) {
			continue // suppressed by dedup
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

func (s *Server) handleListAnomalies(w http.ResponseWriter, r *http.Request) {
	limit := 100
	out := s.store.List(limit)
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
