// Multi-cluster reverse proxy.
//
// Path layout:
//
//   /k8s/<cluster_id>/api/...     → routes to that cluster's apiserver
//   /k8s/api/...                   → routes to the in-cluster apiserver
//                                     (legacy / single-cluster mode)
//
// For the multi-cluster path we read the cluster's stored kubeconfig
// from the cluster store, build a per-cluster TLS config (trusts the
// cluster's CA), and forward the request preserving the user's bearer
// token. After the response is sent we insert one row into proxy_audit
// — one row per kubectl call.
//
// The user identity is best-effort decoded from the bearer token's
// `sub` claim (which for K8s ServiceAccount tokens is the canonical
// `system:serviceaccount:<ns>:<name>`).
package proxy

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/podpulse/podpulse/internal/clusters"
)

// MultiClusterProxy routes /k8s/<cluster_id>/... requests to the
// matching cluster's apiserver. Falls back to a default handler for
// /k8s/... (no cluster_id) which usually points at the in-cluster
// apiserver.
//
// Two upstream modes:
//
//   "kubeconfig" — cluster has a stored kubeconfig YAML; we build a
//                  per-cluster TLS config from its CA and forward
//                  directly to the apiserver URL.
//   "tunnel"     — cluster is reachable only via a pp-connect agent
//                  that has dialed home. We get an http.RoundTripper
//                  from the connect.Hub that funnels each request
//                  back through the WebSocket tunnel.
type MultiClusterProxy struct {
	store    *clusters.Store
	fallback http.Handler // default /k8s proxy (single-cluster legacy)
	pool     *pgxpool.Pool
	tunnel   TunnelProvider // nil-safe: if nil, only kubeconfig mode works

	// per-cluster proxy cache so we build httputil.ReverseProxy once.
	cache map[uuid.UUID]*cachedProxy
}

// TunnelProvider is what connect.Hub satisfies. Decoupled to avoid
// an import cycle (connect imports clusters → can't reverse).
type TunnelProvider interface {
	IsOnline(uuid.UUID) bool
	RoundTripper(uuid.UUID) http.RoundTripper
}

type cachedProxy struct {
	rp       *httputil.ReverseProxy
	upstream *url.URL
	tunnel   bool // true when this proxy routes through a pp-connect tunnel
}

// NewMultiCluster returns a handler for /k8s/* paths.
//
// fallback is the legacy single-cluster proxy (built by proxy.New for
// the in-cluster apiserver). pool is optional — when non-nil, every
// request is logged to proxy_audit.
func NewMultiCluster(store *clusters.Store, fallback http.Handler, pool *pgxpool.Pool) *MultiClusterProxy {
	return &MultiClusterProxy{
		store:    store,
		fallback: fallback,
		pool:     pool,
		cache:    map[uuid.UUID]*cachedProxy{},
	}
}

// SetTunnelProvider wires in a TunnelProvider (typically *connect.Hub)
// after construction. Done in main after both are built so we don't
// need to thread the dep through every call site.
func (m *MultiClusterProxy) SetTunnelProvider(t TunnelProvider) {
	m.tunnel = t
}

func (m *MultiClusterProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Path looks like /k8s/<segment>/...
	path := strings.TrimPrefix(r.URL.Path, "/k8s/")
	first, rest := splitFirst(path)
	clusterID, isCluster := tryUUID(first)

	// Wrap the writer to capture status for audit.
	rec := &statusRecorder{ResponseWriter: w, status: 200}

	if isCluster && m.store != nil {
		ok := m.serveCluster(rec, r, clusterID, rest)
		if !ok && m.fallback != nil {
			// Fall back to legacy proxy if the cluster_id was unknown.
			r.URL.Path = "/k8s/" + rest
			m.fallback.ServeHTTP(rec, r)
		}
	} else if m.fallback != nil {
		m.fallback.ServeHTTP(rec, r)
	} else {
		http.Error(rec, "no proxy backend configured", http.StatusServiceUnavailable)
	}

	// Best-effort audit. Don't block the response on DB writes — fire a
	// goroutine that logs in the background.
	if m.pool != nil {
		actor := actorFromBearer(r.Header.Get("Authorization"))
		// Tenant scoping: stamp the row with the cluster's org. Without
		// this every row lands with org_id=NULL and the audit page
		// (which filters `WHERE org_id = $1`) hides every entry.
		var orgID uuid.UUID
		if isCluster && m.store != nil {
			orgID = m.store.OrgID(clusterID)
		}
		event := proxyAuditRow{
			ClusterID:  clusterID,
			OrgID:      orgID,
			UserName:   actor,
			Method:     r.Method,
			Path:       truncate(r.URL.Path, 1024),
			Status:     rec.status,
			DurationMs: int(time.Since(start).Milliseconds()),
			ClientIP:   clientIP(r),
		}
		go event.insert(m.pool)
	}
}

// serveCluster builds (or reuses) a reverse proxy for the named
// cluster and forwards the request. Returns false if the cluster_id
// is not registered.
func (m *MultiClusterProxy) serveCluster(w http.ResponseWriter, r *http.Request, id uuid.UUID, rest string) bool {
	cp, ok := m.cache[id]
	if !ok {
		built, err := m.build(id)
		if err != nil {
			http.Error(w, "cluster proxy unavailable: "+err.Error(), http.StatusBadGateway)
			return true // we handled it (with an error), no fallback
		}
		cp = built
		m.cache[id] = built
	}

	// Tunnel-mode: gate on agent liveness. The cached transport stays
	// valid across reconnects, so we keep it cached but refuse the
	// request when the WS is down.
	if cp.tunnel && m.tunnel != nil && !m.tunnel.IsOnline(id) {
		http.Error(w, "cluster agent offline — install pp-connect or wait for it to reconnect", http.StatusBadGateway)
		return true
	}

	// Rewrite path so the upstream sees the original Kubernetes API path
	// (without /k8s/<id>).
	r.URL.Path = "/" + rest
	r.URL.Host = cp.upstream.Host
	r.URL.Scheme = cp.upstream.Scheme
	r.Host = cp.upstream.Host
	cp.rp.ServeHTTP(w, r)
	return true
}

// build dispatches to the right per-cluster proxy constructor based
// on the cluster's connect_mode.
func (m *MultiClusterProxy) build(id uuid.UUID) (*cachedProxy, error) {
	mode := m.store.Mode(id)
	if mode == "tunnel" {
		if m.tunnel == nil {
			return nil, errClusterNotFound
		}
		return buildTunnelProxy(id, m.tunnel)
	}
	return buildClusterProxy(m.store, id)
}

// buildTunnelProxy constructs a ReverseProxy whose RoundTripper writes
// every request through the agent's WebSocket. The "upstream URL" we
// store is a synthetic http://apiserver scheme — the path/host info
// is what's relayed to the agent, which forwards to its loopback
// apiserver proxy. Plain HTTP because the agent does TLS locally.
func buildTunnelProxy(id uuid.UUID, t TunnelProvider) (*cachedProxy, error) {
	upstream, _ := url.Parse("http://apiserver")
	rp := &httputil.ReverseProxy{
		Transport:     t.RoundTripper(id),
		FlushInterval: -1,
		Director: func(req *http.Request) {
			// Director already called from ServeHTTP; nothing else to do.
		},
	}
	return &cachedProxy{rp: rp, upstream: upstream, tunnel: true}, nil
}

func buildClusterProxy(store *clusters.Store, id uuid.UUID) (*cachedProxy, error) {
	yamlBlob, ok := store.KubeconfigYAML(id)
	if !ok {
		return nil, errClusterNotFound
	}
	caBundle, server, err := caFromKubeconfig([]byte(yamlBlob))
	if err != nil {
		return nil, err
	}

	target, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       buildTLS(caBundle, len(caBundle) == 0, target.Host),
	}

	rp := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Director: func(req *http.Request) {
			// Director already called from ServeHTTP — no-op here so
			// the path/host we set above sticks.
		},
	}
	return &cachedProxy{rp: rp, upstream: target}, nil
}

// caFromKubeconfig pulls the apiserver URL + CA bundle out of a raw
// kubeconfig YAML. Handles both certificate-authority-data (b64-PEM)
// and certificate-authority (file path — we ignore the file case;
// kubeconfigs from the BYO flow always have inline CA in practice).
func caFromKubeconfig(yamlBlob []byte) ([]byte, string, error) {
	cfg, err := clientcmd.Load(yamlBlob)
	if err != nil {
		return nil, "", err
	}
	currentCtx := cfg.Contexts[cfg.CurrentContext]
	if currentCtx == nil {
		// Fall back to the first context.
		for _, c := range cfg.Contexts {
			currentCtx = c
			break
		}
	}
	if currentCtx == nil {
		return nil, "", errNoContext
	}
	cluster := cfg.Clusters[currentCtx.Cluster]
	if cluster == nil {
		return nil, "", errNoCluster
	}
	if len(cluster.CertificateAuthorityData) > 0 {
		return cluster.CertificateAuthorityData, cluster.Server, nil
	}
	// Try to read the CA from a referenced file (typical of dev kubeconfigs).
	if cluster.CertificateAuthority != "" {
		// We don't have FS access in many contexts — return empty CA
		// and let the proxy fall back to InsecureSkipVerify (only
		// safe in dev — the operator should provide inline CA for
		// production).
		return nil, cluster.Server, nil
	}
	// Insecure cluster: server present, no CA.
	if cluster.InsecureSkipTLSVerify {
		return nil, cluster.Server, nil
	}
	return nil, cluster.Server, nil
}

// --- audit row ---

type proxyAuditRow struct {
	ClusterID  uuid.UUID
	OrgID      uuid.UUID
	UserName   string
	Method     string
	Path       string
	Status     int
	DurationMs int
	ClientIP   string
}

func (e proxyAuditRow) insert(pool *pgxpool.Pool) {
	if pool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var clusterArg any = e.ClusterID
	if e.ClusterID == uuid.Nil {
		clusterArg = nil
	}
	var orgArg any = e.OrgID
	if e.OrgID == uuid.Nil {
		orgArg = nil
	}
	_, _ = pool.Exec(ctx, `
		INSERT INTO proxy_audit (cluster_id, org_id, user_name, method, path, status, duration_ms, client_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		clusterArg, orgArg, nullStr(e.UserName), e.Method, e.Path, e.Status, e.DurationMs, nullStr(e.ClientIP),
	)
}

// statusRecorder wraps http.ResponseWriter so we can capture the
// status code after the handler completes.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}
func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}
// http.Flusher passthrough so streaming (kubectl logs -f / --watch) works.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// --- helpers ---

var (
	errClusterNotFound = httpErr("cluster not registered")
	errNoContext       = httpErr("kubeconfig has no current-context")
	errNoCluster       = httpErr("kubeconfig context references unknown cluster")
)

type httpErr string

func (e httpErr) Error() string { return string(e) }

func splitFirst(p string) (first, rest string) {
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

func tryUUID(s string) (uuid.UUID, bool) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, false
	}
	return id, true
}

// actorFromBearer pulls the SA principal out of a JWT-shaped bearer
// token. Best-effort — returns empty string on any parse failure.
// We don't validate the signature; the apiserver does that. We just
// want a label for the audit row.
func actorFromBearer(authz string) string {
	const p = "Bearer "
	if !strings.HasPrefix(authz, p) {
		return ""
	}
	tok := strings.TrimSpace(authz[len(p):])
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return ""
	}
	return claims.Sub
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Real-Ip"); v != "" {
		return v
	}
	return r.RemoteAddr
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// suppress unused import detector if we ever drop the field.
var _ = clientcmdapi.NewConfig
var _ = x509.NewCertPool
