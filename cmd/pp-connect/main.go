// pp-connect is the PodPulse cluster-tunnel agent.
//
// Run inside any Kubernetes cluster (one Deployment is enough). The
// agent:
//
//  1. Reads the pod's ServiceAccount token + cluster CA from
//     /var/run/secrets/kubernetes.io/serviceaccount/.
//  2. Starts a tiny loopback HTTP server (127.0.0.1:18080) that
//     proxies every request to https://kubernetes.default.svc:443,
//     injecting the SA bearer and using the cluster CA for TLS.
//  3. Opens a WebSocket to PodPulse SaaS at $PP_SAAS_URL/v1/connect
//     using $PP_TOKEN as a pairing/agent token.
//  4. Whenever the SaaS asks for a connection to "apiserver:0",
//     hands back a TCP stream to the loopback HTTP server.
//
// That's it. The agent never speaks to Postgres, never decides
// authorization, never persists anything. Pairing is a single
// outbound TLS connection.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rancher/remotedialer"

	"github.com/podpulse/podpulse/internal/connect"
)

const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// Where the loopback HTTP proxy listens. The agent's custom
	// dialer routes connect.AgentDialAddress to this address.
	loopbackAddr = "127.0.0.1:18080"

	agentVersion = "0.1.0"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		saasURL     = flag.String("saas-url", env("PP_SAAS_URL", ""), "PodPulse SaaS base URL (e.g. https://podpulse-demo.onrender.com)")
		token       = flag.String("token", env("PP_TOKEN", ""), "Pairing/agent token (ppc_…)")
		apiserver   = flag.String("apiserver", env("PP_APISERVER", "https://kubernetes.default.svc:443"), "In-cluster apiserver URL")
		insecureTLS = flag.Bool("insecure-skip-verify", env("PP_INSECURE", "") == "1", "Skip apiserver TLS verification (dev only)")
		caPath      = flag.String("ca", env("PP_CA_PATH", saCAPath), "Path to in-cluster CA bundle")
		tokenPath   = flag.String("sa-token", env("PP_SA_TOKEN_PATH", saTokenPath), "Path to ServiceAccount token")
	)
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	if *saasURL == "" || *token == "" {
		slog.Error("--saas-url and --token (or PP_SAAS_URL / PP_TOKEN) are required")
		os.Exit(2)
	}

	wsURL, err := buildWSURL(*saasURL)
	if err != nil {
		slog.Error("invalid --saas-url", "err", err)
		os.Exit(2)
	}

	apiURL, err := url.Parse(*apiserver)
	if err != nil {
		slog.Error("invalid --apiserver", "err", err)
		os.Exit(2)
	}

	tlsConfig, err := buildTLSConfig(*caPath, *insecureTLS, apiURL.Hostname())
	if err != nil {
		slog.Error("could not build TLS config", "err", err)
		os.Exit(2)
	}

	saToken, err := os.ReadFile(*tokenPath)
	if err != nil && !*insecureTLS {
		slog.Warn("could not read SA token — proxying without bearer auth", "err", err)
	}
	saTokenStr := strings.TrimSpace(string(saToken))

	k8sVersion := readK8sVersion(apiURL, tlsConfig, saTokenStr)
	slog.Info("agent starting",
		"saas", wsURL,
		"apiserver", apiURL.String(),
		"agent_version", agentVersion,
		"k8s_version", k8sVersion,
		"go", runtime.Version(),
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// 1. Start the loopback apiserver proxy.
	proxy := newAPIServerProxy(apiURL, tlsConfig, saTokenStr)
	loopback := &http.Server{
		Addr:              loopbackAddr,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		slog.Info("loopback proxy listening", "addr", loopbackAddr)
		if err := loopback.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("loopback proxy stopped", "err", err)
			cancel()
		}
	}()
	defer loopback.Shutdown(context.Background())

	// 2. Connect home and stay connected.
	go runTunnel(ctx, wsURL, *token, k8sVersion)

	<-ctx.Done()
	slog.Info("pp-connect shutting down")
}

func buildWSURL(saasURL string) (string, error) {
	u, err := url.Parse(saasURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/connect"
	u.RawQuery = ""
	return u.String(), nil
}

func buildTLSConfig(caPath string, insecure bool, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if insecure {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("CA bundle at %s contains no PEM certs", caPath)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// newAPIServerProxy returns a reverse proxy that forwards every
// request to the in-cluster apiserver, replacing the Authorization
// header with the agent's SA token.
func newAPIServerProxy(target *url.URL, tlsCfg *tls.Config, bearer string) http.Handler {
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.FlushInterval = -1
	rp.Transport = &http.Transport{
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		// Don't forward Host header from upstream — apiserver expects its own.
		req.Header.Del("X-Forwarded-Host")
		req.Header.Del("X-Forwarded-For")
	}
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		slog.Warn("apiserver proxy error", "err", err)
		http.Error(w, "apiserver unreachable: "+err.Error(), http.StatusBadGateway)
	}
	return rp
}

// runTunnel keeps the WS open. ClientConnect blocks; on disconnect we
// reconnect with a 5s backoff (handled inside ClientConnect already).
func runTunnel(ctx context.Context, wsURL, token, k8sVer string) {
	headers := http.Header{}
	headers.Set(connect.HeaderToken, token)
	headers.Set(connect.HeaderAgentVersion, agentVersion)
	headers.Set(connect.HeaderK8sVersion, k8sVer)

	// Authorize: only allow dials to our magic address.
	auth := func(proto, address string) bool {
		if proto != "tcp" {
			return false
		}
		return address == connect.AgentDialAddress
	}

	// Local dialer: anything addressed to AgentDialAddress goes to
	// our loopback proxy. Everything else is denied (defense-in-depth
	// against a compromised SaaS asking us to dial random hosts).
	localDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != connect.AgentDialAddress {
			return nil, fmt.Errorf("dial denied for address %q", address)
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", loopbackAddr)
	}

	wsDialer := &websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		Proxy:            http.ProxyFromEnvironment,
	}

	for {
		if ctx.Err() != nil {
			return
		}
		err := remotedialer.ConnectToProxyWithDialer(ctx, wsURL, headers, auth, wsDialer, localDialer, nil)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("tunnel disconnected — retrying in 5s", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// readK8sVersion makes a one-shot /version call to advertise the
// cluster's k8s version on first connect. Best-effort.
func readK8sVersion(apiURL *url.URL, tlsCfg *tls.Config, bearer string) string {
	c := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	req, _ := http.NewRequest("GET", apiURL.String()+"/version", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// The /version body looks like `"gitVersion": "v1.31.2"`. Pull it out
	// without dragging in encoding/json for one field.
	const key = `"gitVersion":`
	i := strings.Index(string(body), key)
	if i < 0 {
		return ""
	}
	rest := string(body)[i+len(key):]
	q1 := strings.Index(rest, `"`)
	if q1 < 0 {
		return ""
	}
	rest = rest[q1+1:]
	q2 := strings.Index(rest, `"`)
	if q2 < 0 {
		return ""
	}
	return rest[:q2]
}
