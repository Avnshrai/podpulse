// pp-detector is the PodPulse control-plane binary.
//
// It accepts log-line batches from pp-tailer DaemonSets over HTTP, runs
// the detection pipeline (Drain3 templates → new-template-per-image-
// digest), enriches incoming log lines from a K8s informer cache, fills
// root-cause sentences (with rollout context), dispatches alerts, and
// serves the CLI/web API.
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
	ppk8s "github.com/podpulse/podpulse/internal/k8s"
)

func main() {
	var (
		httpAddr     = flag.String("http-addr", ":8080", "HTTP listen address (ingest + UI + API)")
		slackWebhook = flag.String("slack-webhook", os.Getenv("SLACK_WEBHOOK"), "Slack incoming webhook URL")
		minHistory = flag.Duration("min-history", 5*time.Minute,
			"Per-workload warm-up window before new-template alerts can fire")
		minLines = flag.Int("min-lines", 200,
			"Minimum lines observed for a workload before any alert fires (cold-start gate)")
		kubeconfig = flag.String("kubeconfig", os.Getenv("KUBECONFIG"),
			"Path to kubeconfig (auto-detected when running in-cluster or from ~/.kube/config)")
		k8sEnabled = flag.Bool("k8s", true,
			"Enable Kubernetes informer integration (set to false to run standalone)")
		resync = flag.Duration("k8s-resync", 5*time.Minute, "Informer resync period")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	templates.MinHistory = *minHistory
	templates.MinLines = *minLines

	store := anomaly.NewStore(1000)
	detector := templates.New()

	dispatcher := alert.NewDispatcher()
	var channels []string
	if *slackWebhook != "" {
		dispatcher.Add(slack.New(*slackWebhook))
		channels = append(channels, "slack")
		slog.Info("slack channel configured")
	} else {
		slog.Info("no alert channels configured (set --slack-webhook or SLACK_WEBHOOK)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var k8sCache *ppk8s.Cache
	if *k8sEnabled {
		client, err := ppk8s.NewClient(*kubeconfig)
		if err != nil {
			slog.Warn("kubernetes integration disabled — could not load config",
				"err", err)
		} else {
			k8sCache = ppk8s.NewCache(logger)
			go func() {
				if err := k8sCache.Run(ctx, client, *resync); err != nil && ctx.Err() == nil {
					slog.Error("informer loop exited", "err", err)
				}
			}()
			slog.Info("kubernetes integration enabled")
		}
	}

	server := api.NewServer(api.Options{
		Store:      store,
		Detector:   detector,
		Dispatcher: dispatcher,
		WebFS:      web.FS(),
		K8sCache:   k8sCache,
		Channels:   channels,
	})

	httpSrv := &http.Server{
		Addr:              *httpAddr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("pp-detector listening",
			"http", *httpAddr,
			"min_history", minHistory.String(),
			"k8s", k8sCache != nil,
		)
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
