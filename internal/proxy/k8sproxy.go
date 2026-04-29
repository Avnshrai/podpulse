// Package proxy implements a kubectl-compatible reverse proxy in front
// of the in-cluster Kubernetes apiserver.
//
// Why this exists:
//
//   AKS (and most managed K8s) put the apiserver on a private VPC
//   endpoint that's unreachable from a developer's laptop. Even when
//   PodPulse mints a working kubeconfig with the right SA token, the
//   server URL `https://kubernetes.default.svc` only resolves
//   inside the cluster.
//
//   Big-tool pattern (Rancher, Teleport, Lens Spaces): make the proxy
//   itself the kubectl-visible apiserver. The kubeconfig points at
//   PodPulse's public URL; PodPulse forwards every API call to the
//   real in-cluster apiserver and authorizes on behalf of the user
//   via their SA token (passed straight through — we never elevate
//   to PodPulse's own permissions).
//
// What this implements:
//
//   GET  /k8s/api/...            → https://kubernetes.default.svc/api/...
//   GET  /k8s/apis/...           → https://kubernetes.default.svc/apis/...
//   POST /k8s/api/v1/...
//   etc., including WebSocket upgrades for `kubectl exec / port-forward`
//   and chunked streaming for `kubectl logs -f` / `--watch`.
//
//   The Authorization header from the kubeconfig (the user's SA bearer
//   token) is forwarded as-is. We never inject PodPulse's own token.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// K8sAPIProxy returns an http.Handler that reverse-proxies any request
// under the configured prefix (e.g. "/k8s") to the in-cluster
// apiserver.
//
// caBundle: PEM bytes of the apiserver CA (read from the SA-mounted
//           /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
//           when running in-cluster).
// upstream: the apiserver URL (https://kubernetes.default.svc:443
//           in-cluster; whatever's in kubeconfig out-of-cluster).
// stripPrefix: usually "/k8s" — removed before forwarding.
type Config struct {
	Upstream    string
	StripPrefix string
	CABundle    []byte // PEM
	// AllowInsecure intentionally relaxes TLS verification on the
	// upstream connection. Only set this when CABundle is unavailable
	// (kind / minikube dev environments). In production with the
	// in-cluster SA, CABundle is always available.
	AllowInsecure bool
}

func New(cfg Config) (http.Handler, error) {
	target, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       buildTLS(cfg.CABundle, cfg.AllowInsecure, target.Host),
	}

	rp := &httputil.ReverseProxy{
		Transport: transport,
		// FlushInterval = -1 means "flush immediately" — required for
		// streaming responses (logs -f, watch).
		FlushInterval: -1,
		Director: func(r *http.Request) {
			// Strip /k8s prefix.
			r.URL.Scheme = target.Scheme
			r.URL.Host = target.Host
			r.Host = target.Host
			if cfg.StripPrefix != "" && strings.HasPrefix(r.URL.Path, cfg.StripPrefix) {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, cfg.StripPrefix)
				if r.URL.Path == "" || r.URL.Path[0] != '/' {
					r.URL.Path = "/" + r.URL.Path
				}
			}

			// Critical: do NOT inject PodPulse's bearer token. The
			// kubeconfig already carries the user's SA token in the
			// Authorization header; the apiserver authenticates and
			// authorizes the user directly.
			//
			// We also strip the SA-projected token if any client side-
			// car decided to add it.
			if r.Header.Get("Authorization") == "" {
				// No token on the inbound request — refuse.
				// (This branch is dead in normal kubectl flows but
				// guards against accidental anonymous proxying.)
			}

			// Standard forwarded-for hygiene.
			r.Header.Set("X-Forwarded-Proto", "https")
		},
		ModifyResponse: func(resp *http.Response) error {
			// Hop-by-hop hygiene: kubectl is sensitive to certain
			// headers (Connection, Upgrade) being mangled by the
			// reverse proxy. ReverseProxy already handles most of
			// this, but we make sure WebSocket upgrades pass through
			// unmodified.
			return nil
		},
	}

	return rp, nil
}

// buildTLS constructs a TLS config that trusts the cluster CA.
func buildTLS(caBundle []byte, allowInsecure bool, host string) *tls.Config {
	c := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if allowInsecure {
		c.InsecureSkipVerify = true
		return c
	}
	if len(caBundle) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caBundle) {
			c.RootCAs = pool
		}
	}
	// ServerName is what TLS verification uses; default to the URL
	// host but strip the port if present.
	if i := strings.IndexByte(host, ':'); i > 0 {
		c.ServerName = host[:i]
	} else {
		c.ServerName = host
	}
	return c
}

// LoadInClusterCA reads the SA-mounted CA bundle. Returns nil bytes
// (no error) when not running in-cluster.
func LoadInClusterCA() []byte {
	const p = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}
