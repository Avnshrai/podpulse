// pp-tailer is the PodPulse log-tailing DaemonSet binary.
//
// It runs on every node, reads container logs from /var/log/pods/* in CRI
// format, enriches each line with workload/pod/container/image metadata
// from a node-local pod cache, and ships batched lines to pp-detector
// over gRPC.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var (
		detectorAddr = flag.String("detector", "pp-detector:9090", "pp-detector gRPC address")
		logsDir      = flag.String("logs-dir", "/var/log/pods", "CRI pod logs directory")
		nodeName     = flag.String("node", os.Getenv("NODE_NAME"), "Kubernetes node name (defaults to $NODE_NAME)")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	logger.Info("pp-tailer starting",
		"detector", *detectorAddr,
		"logs_dir", *logsDir,
		"node", *nodeName,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()
	logger.Info("pp-tailer shutting down")
}
