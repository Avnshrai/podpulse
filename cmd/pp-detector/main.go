// pp-detector is the PodPulse control-plane binary.
//
// It accepts log-line batches from pp-tailer DaemonSets over HTTP, runs
// the detection pipeline (Drain3 templates → new-template-per-image-
// digest), fills root-cause sentences, dispatches alerts, and serves
// the CLI/web API.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/podpulse/podpulse/internal/alert"
	"github.com/podpulse/podpulse/internal/alert/slack"
	"github.com/podpulse/podpulse/internal/anomaly"
	"github.com/podpulse/podpulse/internal/api"
	"github.com/podpulse/podpulse/internal/api/web"
	"github.com/podpulse/podpulse/internal/detect/templates"
)

func main() {
	var (
		httpAddr     = flag.String("http-addr", ":8080", "HTTP listen address (ingest + UI + API)")
		slackWebhook = flag.String("slack-webhook", os.Getenv("SLACK_WEBHOOK"), "Slack incoming webhook URL")
		minHistory   = flag.Duration("min-history", 30*time.Second,
			"Per-(workload, image-digest) warm-up window before new-template alerts can fire")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	templates.MinHistory = *minHistory

	store := anomaly.NewStore(1000)
	detector := templates.New()

	dispatcher := alert.NewDispatcher()
	if *slackWebhook != "" {
		dispatcher.Add(slack.New(*slackWebhook))
		slog.Info("slack channel configured")
	} else {
		slog.Info("no alert channels configured (set --slack-webhook or SLACK_WEBHOOK)")
	}

	server := api.NewServer(store, detector, dispatcher, web.FS())

	httpSrv := &http.Server{
		Addr:              *httpAddr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		slog.Info("pp-detector listening", "http", *httpAddr, "min_history", minHistory.String())
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server stopped", "err", err)
			cancel()
		}
	}()

	<-ctx.Done()
	slog.Info("pp-detector shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}
