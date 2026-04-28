// pp-tailer is the PodPulse log-tailing DaemonSet binary.
//
// In production it reads CRI container logs from /var/log/pods, enriches
// each line with workload metadata from a node-local pod cache, and
// ships batches to pp-detector. For Phase 1 the production path is
// stubbed; --demo runs a self-contained generator that emits a stable
// baseline of log patterns and (after a configurable delay) starts
// emitting a "new" pattern, which is what the detector should fire on.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

func main() {
	var (
		detectorURL = flag.String("detector", env("DETECTOR_URL", "http://localhost:8080"),
			"pp-detector base URL")
		nodeName = flag.String("node", env("NODE_NAME", "local"),
			"Kubernetes node name")
		demo = flag.Bool("demo", false,
			"Run a self-contained synthetic log generator (Phase 1 demo)")
		demoBreakAfter = flag.Duration("demo-break-after", 45*time.Second,
			"In demo mode, start emitting a new error template this long after start")
		demoNamespace = flag.String("demo-namespace", "podpulse-dev", "Demo workload namespace")
		demoWorkload  = flag.String("demo-workload", "payments-api", "Demo workload name")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("pp-tailer starting",
		"detector", *detectorURL,
		"node", *nodeName,
		"demo", *demo,
	)

	if !*demo {
		logger.Warn("non-demo CRI log tailing not implemented yet — pass --demo for Phase 1")
		<-ctx.Done()
		return
	}

	runDemo(ctx, *detectorURL, *nodeName, *demoNamespace, *demoWorkload, *demoBreakAfter)
	logger.Info("pp-tailer shutting down")
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// baselinePatterns are the log lines the demo workload emits "normally".
// They're deliberately varied (different token counts, structures) so the
// Drain3 miner produces several stable templates before the "break."
var baselinePatterns = []string{
	"GET /api/users 200 12ms",
	"GET /api/orders 200 7ms",
	"POST /api/payments accepted ref=abc",
	"cache hit key=session ttl=300",
	"healthcheck ok db=up redis=up",
}

// brokenPatterns simulate a bad rollout: a brand-new error template the
// detector has never seen for this (workload, image-digest).
var brokenPatterns = []string{
	"ERROR connection refused upstream=redis-master:6379",
	"ERROR upstream timeout after 5000ms calling redis-master",
}

func runDemo(ctx context.Context, detectorURL, node, ns, workload string, breakAfter time.Duration) {
	tickGood := time.NewTicker(200 * time.Millisecond)
	defer tickGood.Stop()
	breakAt := time.After(breakAfter)
	broken := false

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	batch := make([]types.LogLine, 0, 32)
	flush := time.NewTicker(500 * time.Millisecond)
	defer flush.Stop()

	const podCount = 3
	digestStable := "sha256:b14d1ea5e21c0ff1ce7b6c2a0d8e3a44e7f1c30b8d2e5c0a1234567890abcdef"
	digestNew := "sha256:fa1ledc0ffee0badd1e5e7654321deadbeefcafe9876543210fedcba98765432"

	emit := func(msg string, useNewDigest bool) {
		digest := digestStable
		if useNewDigest {
			digest = digestNew
		}
		batch = append(batch, types.LogLine{
			Timestamp:   time.Now(),
			Namespace:   ns,
			OwnerKind:   "Deployment",
			OwnerName:   workload,
			Pod:         fmt.Sprintf("%s-%d", workload, rng.Intn(podCount)),
			Container:   "app",
			Image:       "registry.example/" + workload + ":v2.4.1",
			ImageDigest: digest,
			Node:        node,
			Stream:      "stdout",
			Message:     msg,
		})
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-breakAt:
			if !broken {
				slog.Warn("demo: simulating bad rollout — switching to new image-digest with new error template")
				broken = true
			}
		case <-tickGood.C:
			emit(baselinePatterns[rng.Intn(len(baselinePatterns))], false)
			if broken {
				emit(brokenPatterns[rng.Intn(len(brokenPatterns))], true)
			}
		case <-flush.C:
			if len(batch) == 0 {
				continue
			}
			if err := postBatch(ctx, detectorURL, batch); err != nil {
				slog.Error("ingest post failed", "err", err)
			}
			batch = batch[:0]
		}
	}
}

func postBatch(ctx context.Context, base string, lines []types.LogLine) error {
	body, err := json.Marshal(map[string]any{"lines": lines})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/ingest",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("detector returned %d", resp.StatusCode)
	}
	return nil
}
