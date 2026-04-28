// pp-detector is the PodPulse control-plane binary.
//
// It runs as a Deployment in-cluster, watches Kubernetes resources via
// client-go informers, receives log lines from pp-tailer DaemonSets over
// gRPC, runs the detection pipeline (Drain3 templates, EWMA, Holt-Winters,
// CUSUM), produces root-cause summaries, and dispatches alerts.
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
		grpcAddr = flag.String("grpc-addr", ":9090", "gRPC ingest listen address")
		httpAddr = flag.String("http-addr", ":8080", "HTTP/UI listen address")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	logger.Info("pp-detector starting",
		"grpc", *grpcAddr,
		"http", *httpAddr,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	<-ctx.Done()
	logger.Info("pp-detector shutting down")
}
