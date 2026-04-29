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
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/podpulse/podpulse/internal/alert"
	"github.com/podpulse/podpulse/internal/alert/slack"
	"github.com/podpulse/podpulse/internal/anomaly"
	"github.com/podpulse/podpulse/internal/api"
	"github.com/podpulse/podpulse/internal/api/web"
	"github.com/podpulse/podpulse/internal/detect/templates"
	"github.com/podpulse/podpulse/internal/issue"
	ppk8s "github.com/podpulse/podpulse/internal/k8s"
	"github.com/podpulse/podpulse/internal/proxy"
	"github.com/podpulse/podpulse/internal/users"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

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
		externalURL = flag.String("external-url", env("PODPULSE_EXTERNAL_URL", "https://localhost:8080"),
			"Public URL where users reach PodPulse (used in generated kubeconfigs as the apiserver URL)")
		kubeconfigInsecure = flag.Bool("kubeconfig-insecure", true,
			"Generate kubeconfigs with insecure-skip-tls-verify (for tunnel/localhost use). Set false in prod with a real TLS cert.")
		tlsEnabled = flag.Bool("tls", true,
			"Serve TLS with an in-memory self-signed cert. Required: kubectl strips bearer tokens on plain HTTP.")
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
	var configWatcher *ppk8s.ConfigWatcher
	var eventWatcher *ppk8s.EventWatcher
	var auditWatcher *ppk8s.AuditWatcher
	var userMgr *users.Manager
	if *k8sEnabled {
		client, err := ppk8s.NewClient(*kubeconfig)
		if err != nil {
			slog.Warn("kubernetes integration disabled — could not load config",
				"err", err)
		} else {
			k8sCache = ppk8s.NewCache(logger)
			configWatcher = ppk8s.NewConfigWatcher(k8sCache, logger)
			eventWatcher = ppk8s.NewEventWatcher(logger)
			auditWatcher = ppk8s.NewAuditWatcher(logger)

			// In-cluster apiserver URL. Used both as the proxy upstream
			// and as the literal "kubernetes.default.svc" fallback for
			// kubeconfigs when no --external-url is set.
			apiUpstream := "https://kubernetes.default.svc"

			// Mount the kubectl-compatible reverse proxy so
			// kubeconfigs that point at PodPulse work transparently.
			ph, perr := proxy.New(proxy.Config{
				Upstream:      apiUpstream,
				StripPrefix:   "/k8s",
				CABundle:      proxy.LoadInClusterCA(),
				AllowInsecure: proxy.LoadInClusterCA() == nil, // dev-only fallback
			})
			if perr != nil {
				slog.Warn("k8s proxy disabled", "err", perr)
			} else {
				api.K8sAPIProxy = ph
				slog.Info("k8s api proxy mounted at /k8s", "upstream", apiUpstream)
			}

			// User-facing apiserver URL used in generated kubeconfigs.
			// Defaults to the PodPulse external URL + /k8s so kubectl
			// reaches the apiserver through PodPulse.
			kubeconfigServer := strings.TrimRight(*externalURL, "/") + "/k8s"
			userMgr = users.NewManager(client, kubeconfigServer)
			userMgr.InsecureTLS = *kubeconfigInsecure
			slog.Info("kubeconfig generator configured",
				"server", kubeconfigServer, "insecure_skip_tls", *kubeconfigInsecure)
			go func() {
				if err := k8sCache.Run(ctx, client, *resync); err != nil && ctx.Err() == nil {
					slog.Error("pod/rs/svc informer loop exited", "err", err)
				}
			}()
			go func() {
				if err := configWatcher.Run(ctx, client, *resync); err != nil && ctx.Err() == nil {
					slog.Error("config watcher exited", "err", err)
				}
			}()
			go func() {
				if err := eventWatcher.Run(ctx, client, *resync); err != nil && ctx.Err() == nil {
					slog.Error("event watcher exited", "err", err)
				}
			}()
			go func() {
				if err := auditWatcher.Run(ctx, client, *resync); err != nil && ctx.Err() == nil {
					slog.Error("audit watcher exited", "err", err)
				}
			}()
			slog.Info("kubernetes integration enabled (pods, rs, svc, configmaps, secrets, events, audit, users)")
		}
	}

	issueEngine := issue.NewEngine(configWatcher, eventWatcher, k8sCache, store)
	go runIssueRefresher(ctx, issueEngine)

	server := api.NewServer(api.Options{
		Store:         store,
		Detector:      detector,
		Dispatcher:    dispatcher,
		WebFS:         web.FS(),
		K8sCache:      k8sCache,
		ConfigWatcher: configWatcher,
		EventWatcher:  eventWatcher,
		AuditWatcher:  auditWatcher,
		UserManager:   userMgr,
		IssueEngine:   issueEngine,
		Channels:      channels,
	})

	httpSrv := &http.Server{
		Addr:              *httpAddr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if *tlsEnabled {
			cert, err := proxy.SelfSignedCert("podpulse")
			if err != nil {
				slog.Error("could not generate self-signed cert", "err", err)
				cancel()
				return
			}
			httpSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
			slog.Info("pp-detector listening (TLS, self-signed)",
				"https", *httpAddr,
				"min_history", minHistory.String(),
				"k8s", k8sCache != nil,
			)
			if err := httpSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				slog.Error("https server stopped", "err", err)
				cancel()
			}
			return
		}
		slog.Info("pp-detector listening (PLAIN HTTP — kubectl will not work)",
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

func runIssueRefresher(ctx context.Context, e *issue.Engine) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	e.Refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.Refresh()
		}
	}
}
