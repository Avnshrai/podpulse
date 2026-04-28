// podpulse is the PodPulse CLI.
//
// It talks to a pp-detector instance (gRPC/HTTP) and is the primary day-1
// interface for SREs:
//
//	podpulse anomalies                  list current/recent anomalies
//	podpulse explain <id>               print RCA + suggested rollback
//	podpulse silence <workload> --for=  create a silence rule
//	podpulse tail <workload>            live template-level tail
//	podpulse channels test <name>       send a synthetic alert
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
)

const usage = `podpulse — Kubernetes incident detector CLI

Usage:
  podpulse <command> [flags]

Commands:
  anomalies          List current and recent anomalies
  explain <id>       Show root-cause summary for an anomaly
  silence <workload> Create a silence rule
  tail <workload>    Live-tail templates against the baseline
  channels test <n>  Send a synthetic alert through a configured channel
  version            Print version

Global flags:
  --server   pp-detector address (default: http://localhost:8080, or $PODPULSE_SERVER)
  --json     emit machine-readable JSON
`

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "anomalies":
		runAnomalies(args)
	case "explain":
		runExplain(args)
	case "silence":
		runSilence(args)
	case "tail":
		runTail(args)
	case "channels":
		runChannels(args)
	case "version":
		fmt.Println("podpulse dev")
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

func runAnomalies(args []string) {
	fs := flag.NewFlagSet("anomalies", flag.ExitOnError)
	ns := fs.String("namespace", "", "filter by namespace")
	wl := fs.String("workload", "", "filter by workload")
	sev := fs.String("severity", "", "filter by severity (low|medium|high|critical)")
	_ = fs.Parse(args)

	slog.Info("anomalies (stub)", "namespace", *ns, "workload", *wl, "severity", *sev)
	fmt.Println("(no anomalies — detector API not implemented yet)")
}

func runExplain(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: podpulse explain <anomaly-id>")
		os.Exit(2)
	}
	slog.Info("explain (stub)", "id", args[0])
}

func runSilence(args []string) {
	fs := flag.NewFlagSet("silence", flag.ExitOnError)
	dur := fs.String("for", "1h", "silence duration")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: podpulse silence <workload> [--for=DURATION]")
		os.Exit(2)
	}
	slog.Info("silence (stub)", "workload", fs.Arg(0), "for", *dur)
}

func runTail(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: podpulse tail <workload>")
		os.Exit(2)
	}
	slog.Info("tail (stub)", "workload", args[0])
}

func runChannels(args []string) {
	if len(args) < 2 || args[0] != "test" {
		fmt.Fprintln(os.Stderr, "usage: podpulse channels test <channel-name>")
		os.Exit(2)
	}
	slog.Info("channels test (stub)", "channel", args[1])
}
