// podpulse-demo runs both the detector and a synthetic tailer in a
// single process. Built for the public hosted demo on Fly.io / Render
// — no Kubernetes cluster required, no SSH tunnels, just a URL.
//
// The demo tailer simulates three fake workloads emitting realistic
// log patterns and periodically rolls out a "bad version" so the
// dashboard always has fresh anomalies to show.
//
// In production the detector + DaemonSet tailer run separately inside
// a real cluster — that path is unchanged. This binary exists only to
// let visitors play with the UI without installing anything.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	// Spawn the detector as a child process. We could embed its main
	// directly, but a fork keeps the demo binary tiny and means a
	// detector crash doesn't take down the wrapper.
	//
	// --tls=false because fly.io / Render terminate TLS at their edge
	// and expect plain HTTP on the internal port. (For real cluster
	// deploys we keep self-signed TLS so kubectl works.)
	det := exec.CommandContext(ctx, "/usr/local/bin/pp-detector",
		"--http-addr="+addr,
		"--k8s=false",
		"--min-history=10s",
		"--min-lines=15",
		"--tls=false",
	)
	det.Stdout = os.Stdout
	det.Stderr = os.Stderr
	if err := det.Start(); err != nil {
		slog.Error("could not start detector", "err", err)
		os.Exit(1)
	}
	slog.Info("detector started", "pid", det.Process.Pid, "addr", addr)

	// Wait for detector to come up.
	detectorURL := "http://localhost" + addr
	if err := waitHealthy(ctx, detectorURL, 30*time.Second); err != nil {
		slog.Error("detector never became healthy", "err", err)
		_ = det.Process.Kill()
		os.Exit(1)
	}
	slog.Info("detector healthy — starting demo workload generator")

	// Run the synthetic generator in-process.
	go runDemoGenerator(ctx, detectorURL)

	// Wait for the detector to exit (signal will cascade).
	if err := det.Wait(); err != nil && ctx.Err() == nil {
		slog.Error("detector exited", "err", err)
	}
}

func waitHealthy(ctx context.Context, base string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		resp, err := c.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s/healthz", base)
}

// runDemoGenerator emits realistic-looking log lines for three fake
// workloads. Every ~2 minutes one of them "rolls out" a buggy
// version that introduces a new error pattern, so the dashboard
// always has an active incident in view.
func runDemoGenerator(ctx context.Context, detectorURL string) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	workloads := []*demoWorkload{
		{
			Namespace: "payments", Workload: "payments-api",
			GoodPatterns: []string{
				"GET /api/charges 200 12ms",
				"GET /api/customers 200 7ms",
				"POST /api/charges accepted ref=ch_abc",
				"webhook.received stripe event=charge.succeeded",
				"healthcheck ok db=up redis=up",
			},
			BadPatterns: []string{
				"ERROR connection refused upstream=redis-master:6379",
				"ERROR upstream timeout after 5000ms calling redis-master",
			},
			DigestStable: "sha256:b14d1ea5e21c0ff1ce7b6c2a0d8e3a44e7f1c30b8d2e5c0a1234567890abcdef",
			DigestNew:    "sha256:fa1ledc0ffee0badd1e5e7654321deadbeefcafe9876543210fedcba98765432",
		},
		{
			Namespace: "auth", Workload: "user-service",
			GoodPatterns: []string{
				`{"level":"info","msg":"auth.success","user":"alice"}`,
				`{"level":"info","msg":"token.minted","ttl":3600}`,
				`{"level":"info","msg":"healthcheck.ok"}`,
				`{"level":"info","msg":"jwt.verified","aud":"api"}`,
			},
			BadPatterns: []string{
				`{"level":"error","msg":"User not found","tenant":"acme"}`,
				`{"level":"error","msg":"User not authorized to validate tenant","reason":"missing scope"}`,
			},
			DigestStable: "sha256:1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890",
			DigestNew:    "sha256:9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
		},
		{
			Namespace: "platform", Workload: "ingest-worker",
			GoodPatterns: []string{
				"level=info ts=now msg=\"job dequeued\" id=job-42 type=ingest",
				"level=info ts=now msg=\"batch processed\" rows=1024 ms=87",
				"level=info ts=now msg=\"checkpoint saved\" offset=8847261",
			},
			BadPatterns: []string{
				"level=error msg=\"OOMKilled detected — container terminated\"",
				"panic: runtime error: invalid memory address or nil pointer dereference",
			},
			DigestStable: "sha256:7654321098abcdef7654321098abcdef7654321098abcdef7654321098abcdef",
			DigestNew:    "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		},
	}

	const podCount = 3
	tickGood := time.NewTicker(180 * time.Millisecond)
	defer tickGood.Stop()
	flush := time.NewTicker(500 * time.Millisecond)
	defer flush.Stop()
	rollout := time.NewTicker(2 * time.Minute)
	defer rollout.Stop()
	rolloutIdx := 0

	batch := make([]types.LogLine, 0, 64)
	emit := func(w *demoWorkload, msg string, broken bool) {
		digest := w.DigestStable
		if broken {
			digest = w.DigestNew
		}
		batch = append(batch, types.LogLine{
			Timestamp:   time.Now(),
			Namespace:   w.Namespace,
			OwnerKind:   "Deployment",
			OwnerName:   w.Workload,
			Pod:         fmt.Sprintf("%s-%d", w.Workload, rng.Intn(podCount)),
			Container:   "app",
			Image:       fmt.Sprintf("registry.example/%s:v2.4.1", w.Workload),
			ImageDigest: digest,
			Node:        "demo-node",
			Stream:      "stdout",
			Message:     msg,
		})
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-rollout.C:
			// Roll out a "buggy version" on one workload at a time.
			workloads[rolloutIdx%len(workloads)].Broken = true
			slog.Warn("demo: bad rollout simulated",
				"workload", workloads[rolloutIdx%len(workloads)].Workload)
			// Reset previous one so the dashboard isn't permanently red.
			prev := (rolloutIdx - 1 + len(workloads)) % len(workloads)
			workloads[prev].Broken = false
			rolloutIdx++

		case <-tickGood.C:
			for _, w := range workloads {
				emit(w, w.GoodPatterns[rng.Intn(len(w.GoodPatterns))], false)
				if w.Broken {
					emit(w, w.BadPatterns[rng.Intn(len(w.BadPatterns))], true)
				}
			}

		case <-flush.C:
			if len(batch) == 0 {
				continue
			}
			if err := postBatch(ctx, detectorURL, batch); err != nil {
				slog.Error("ingest post failed", "err", err, "lines", len(batch))
			}
			batch = batch[:0]
		}
	}
}

type demoWorkload struct {
	Namespace    string
	Workload     string
	GoodPatterns []string
	BadPatterns  []string
	DigestStable string
	DigestNew    string
	Broken       bool
}

var demoClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func postBatch(ctx context.Context, base string, lines []types.LogLine) error {
	body, err := json.Marshal(map[string]any{"lines": lines})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := demoClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("detector returned %d", resp.StatusCode)
	}
	return nil
}
