// pp-tailer is the PodPulse log-tailing DaemonSet binary.
//
// Production: reads CRI container logs from /var/log/pods (one file per
// container), parses CRI format, and ships batches of enriched log
// lines to pp-detector over HTTP. The tailer extracts {namespace, pod,
// container} from the file path; the detector enriches with workload
// owner / image / image-digest from its K8s informer cache.
//
// Demo (--demo): self-contained synthetic generator used while
// validating the pipeline without touching real workloads.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/podpulse/podpulse/internal/tail"
	"github.com/podpulse/podpulse/internal/types"
)

func main() {
	var (
		detectorURL = flag.String("detector", env("DETECTOR_URL", "http://localhost:8080"),
			"pp-detector base URL")
		nodeName = flag.String("node", env("NODE_NAME", "local"),
			"Kubernetes node name")
		logsDir = flag.String("logs-dir", env("LOGS_DIR", "/var/log/pods"),
			"Root directory of CRI pod logs")
		scanEvery = flag.Duration("scan-every", 5*time.Second,
			"How often to scan logs-dir for new pod log files")
		batchSize = flag.Int("batch", 64, "Max log lines per ingest batch")
		flushEvery = flag.Duration("flush-every", 500*time.Millisecond,
			"Max time before a partial batch is flushed")
		demo = flag.Bool("demo", false,
			"Run a self-contained synthetic log generator (skips real CRI tailing)")
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
		"logs_dir", *logsDir,
	)

	if *demo {
		runDemo(ctx, *detectorURL, *nodeName, *demoNamespace, *demoWorkload, *demoBreakAfter)
		logger.Info("pp-tailer shutting down")
		return
	}

	runReal(ctx, *detectorURL, *nodeName, *logsDir, *scanEvery, *batchSize, *flushEvery)
	logger.Info("pp-tailer shutting down")
}

// runReal wires the directory watcher → file tailers → batched POST
// ingest pipeline.
func runReal(ctx context.Context, detectorURL, nodeName, logsDir string,
	scanEvery time.Duration, batchSize int, flushEvery time.Duration) {

	type bufferedLine struct {
		pp tail.PodPath
		r  tail.Record
	}
	in := make(chan bufferedLine, 4096)

	w := &tail.Watcher{
		Root:      logsDir,
		ScanEvery: scanEvery,
		OnNewPath: func(pp tail.PodPath) {
			slog.Info("tailing pod", "namespace", pp.Namespace, "pod", pp.Pod, "container", pp.Container)
		},
		OnRecord: func(pp tail.PodPath, r tail.Record) {
			select {
			case in <- bufferedLine{pp, r}:
			default:
				// Drop lines under sustained backpressure rather than
				// blocking the file tailer goroutine.
			}
		},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := w.Run(ctx); err != nil {
			slog.Error("watcher exited", "err", err)
		}
	}()

	batch := make([]types.LogLine, 0, batchSize)
	flush := time.NewTicker(flushEvery)
	defer flush.Stop()

	doFlush := func() {
		if len(batch) == 0 {
			return
		}
		if err := postBatch(ctx, detectorURL, batch); err != nil {
			slog.Error("ingest post failed", "err", err, "lines", len(batch))
		}
		batch = batch[:0]
	}

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case b := <-in:
			batch = append(batch, types.LogLine{
				Timestamp: b.r.Timestamp,
				Namespace: b.pp.Namespace,
				Pod:       b.pp.Pod,
				Container: b.pp.Container,
				Node:      nodeName,
				Stream:    b.r.Stream,
				Message:   b.r.Message,
			})
			if len(batch) >= batchSize {
				doFlush()
			}
		case <-flush.C:
			doFlush()
		}
	}
	doFlush()
	wg.Wait()
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// --- demo mode (kept for synthetic validation) ---

var baselinePatterns = []string{
	"GET /api/users 200 12ms",
	"GET /api/orders 200 7ms",
	"POST /api/payments accepted ref=abc",
	"cache hit key=session ttl=300",
	"healthcheck ok db=up redis=up",
}

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

// httpClient skips TLS verification on the in-cluster detector
// connection. The detector serves a self-signed cert that the tailer
// pod can't easily fetch (it's regenerated on every detector restart),
// so we accept the cert without validation. The connection is still
// pod-to-pod via the cluster service network — same trust boundary as
// any other in-cluster service call.
var httpClient = &http.Client{
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/ingest",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("detector returned %d", resp.StatusCode)
	}
	return nil
}
