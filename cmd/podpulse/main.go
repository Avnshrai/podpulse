// podpulse is the PodPulse CLI.
//
// It talks to a pp-detector instance over HTTP and is the primary day-1
// interface for SREs:
//
//	podpulse anomalies                  list current/recent anomalies
//	podpulse explain <id>               print RCA + suggested rollback
//	podpulse silence <workload>         create a silence rule (Phase 2)
//	podpulse tail <workload>            live template-level tail (Phase 2)
//	podpulse channels test <name>       send a synthetic alert (Phase 2)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/podpulse/podpulse/internal/types"
)

const usage = `podpulse — Kubernetes incident detector CLI

Usage:
  podpulse [global flags] <command> [args]

Commands:
  anomalies               List current and recent anomalies
  explain <id>            Show root-cause summary for an anomaly
  silence <workload>      Create a silence rule (Phase 2)
  tail <workload>         Live-tail templates against the baseline (Phase 2)
  channels test <name>    Send a synthetic alert through a configured channel (Phase 2)
  version                 Print version

Global flags:
  --server URL   pp-detector base URL (default $PODPULSE_SERVER or http://localhost:8080)
  --json         emit machine-readable JSON
`

type globalFlags struct {
	server string
	jsonOu bool
}

func parseGlobals(args []string) (globalFlags, []string) {
	g := globalFlags{server: env("PODPULSE_SERVER", "http://localhost:8080")}
	rest := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 >= len(args) {
				die("--server requires a URL")
			}
			g.server = args[i+1]
			i++
		case "--json":
			g.jsonOu = true
		default:
			rest = append(rest, args[i])
		}
	}
	return g, rest
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	g, args := parseGlobals(os.Args[1:])
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "anomalies":
		runAnomalies(g, rest)
	case "explain":
		runExplain(g, rest)
	case "silence", "tail":
		fmt.Fprintf(os.Stderr, "%s is implemented in Phase 2\n", cmd)
		os.Exit(2)
	case "channels":
		fmt.Fprintln(os.Stderr, "channels is implemented in Phase 2")
		os.Exit(2)
	case "version":
		fmt.Println("podpulse dev")
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

func runAnomalies(g globalFlags, args []string) {
	fs := flag.NewFlagSet("anomalies", flag.ExitOnError)
	nsFilter := fs.String("namespace", "", "filter by namespace")
	wlFilter := fs.String("workload", "", "filter by workload name")
	sevFilter := fs.String("severity", "", "filter by severity (low|medium|high|critical)")
	limit := fs.Int("limit", 50, "max items to print")
	_ = fs.Parse(args)

	var resp struct {
		Anomalies []types.Anomaly `json:"anomalies"`
		Count     int             `json:"count"`
	}
	if err := getJSON(g.server+"/v1/anomalies", &resp); err != nil {
		die("fetch anomalies: %v", err)
	}

	out := resp.Anomalies
	if *nsFilter != "" {
		out = filter(out, func(a types.Anomaly) bool { return a.Workload.Namespace == *nsFilter })
	}
	if *wlFilter != "" {
		out = filter(out, func(a types.Anomaly) bool { return a.Workload.Name == *wlFilter })
	}
	if *sevFilter != "" {
		out = filter(out, func(a types.Anomaly) bool { return string(a.Severity) == *sevFilter })
	}
	if *limit > 0 && len(out) > *limit {
		out = out[:*limit]
	}

	if g.jsonOu {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}

	if len(out) == 0 {
		fmt.Println("(no anomalies)")
		return
	}
	fmt.Printf("%-22s  %-8s  %-22s  %-12s  %s\n", "FIRED", "SEV", "WORKLOAD", "KIND", "TEMPLATE")
	for _, a := range out {
		fmt.Printf("%-22s  %-8s  %-22s  %-12s  %s\n",
			a.FiredAt.Format(time.RFC3339),
			a.Severity,
			truncate(a.Workload.String(), 22),
			a.Kind,
			truncate(a.Template, 60),
		)
	}
}

func runExplain(g globalFlags, args []string) {
	if len(args) < 1 {
		die("usage: podpulse explain <anomaly-id>")
	}
	id := args[0]
	var a types.Anomaly
	if err := getJSON(g.server+"/v1/anomalies/"+url.PathEscape(id), &a); err != nil {
		die("fetch anomaly: %v", err)
	}

	if g.jsonOu {
		_ = json.NewEncoder(os.Stdout).Encode(a)
		return
	}

	fmt.Printf("Anomaly %s\n", a.ID)
	fmt.Printf("  fired:     %s\n", a.FiredAt.Format(time.RFC3339))
	fmt.Printf("  kind:      %s\n", a.Kind)
	fmt.Printf("  severity:  %s\n", a.Severity)
	fmt.Printf("  workload:  %s\n", a.Workload)
	if a.Image != "" {
		fmt.Printf("  image:     %s\n", a.Image)
	}
	if a.ImageDigest != "" {
		fmt.Printf("  digest:    %s\n", a.ImageDigest)
	}
	if a.Template != "" {
		fmt.Printf("  template:  %s\n", a.Template)
	}
	if a.RCA != "" {
		fmt.Printf("\n  RCA: %s\n", a.RCA)
	}
	if a.RollbackHint != "" {
		fmt.Printf("\n  Suggested:\n    %s\n", a.RollbackHint)
	}
	if len(a.Sample) > 0 {
		fmt.Printf("\n  Sample line:\n    %s\n", a.Sample[0])
	}
}

// --- helpers ---

func getJSON(url string, out any) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func filter[T any](in []T, ok func(T) bool) []T {
	out := in[:0]
	for _, v := range in {
		if ok(v) {
			out = append(out, v)
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func die(format string, args ...any) {
	fmt.Fprintln(os.Stderr, "podpulse: "+fmt.Sprintf(format, args...))
	os.Exit(1)
}
