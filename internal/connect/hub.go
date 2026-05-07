// Package connect implements the agent-tunnel for PodPulse SaaS.
//
// The pp-connect agent runs inside a customer cluster and dials home
// over a WebSocket. PodPulse SaaS uses that connection to forward
// kubectl traffic *back* to the cluster's apiserver — no inbound
// firewall rules, no VPN required.
//
// Wire layout (rancher/remotedialer is the transport):
//
//   pp-connect ──── outbound TLS ────→  /v1/connect  (Hub)
//                                       │
//                                       │ authenticates bearer token
//                                       │ from `Authorization: Bearer ppc_…`
//                                       │ → resolves to cluster_id
//                                       ▼
//                                       remotedialer.Server registers
//                                       the conn under clientKey=cluster_id
//
// Once the tunnel is up, MultiClusterProxy can ask the Hub for an
// http.RoundTripper that dials through to the agent and out to the
// in-cluster apiserver.
//
// Token format: `ppc_<32-hex>`. Tokens live in pairing_tokens; after
// first use we record (used_at, cluster_id) but the token stays valid
// for subsequent reconnects (the agent stores it in a Secret).
package connect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rancher/remotedialer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// AgentDialAddress is the magic destination string that the server
// asks the agent's custom dialer to "open". The agent recognizes it
// and short-circuits to its local apiserver-proxy. Using a fixed
// string keeps the per-cluster server-side bookkeeping trivial.
const AgentDialAddress = "apiserver:0"

// HelloHeader keys exchanged during the WS handshake.
const (
	HeaderToken        = "X-PodPulse-Token"
	HeaderAgentVersion = "X-PodPulse-Agent-Version"
	HeaderK8sVersion   = "X-PodPulse-K8s-Version"
)

// Hub is the server-side entry point. It owns the remotedialer.Server,
// resolves pairing tokens to cluster IDs, and maintains the online /
// last-seen state of every connected cluster.
type Hub struct {
	pool *pgxpool.Pool
	log  *slog.Logger

	rd *remotedialer.Server

	mu      sync.RWMutex
	online  map[uuid.UUID]*tunnelInfo // cluster_id → live tunnel info
	pending map[string]chan uuid.UUID // pairing_token → "first connect" notify
}

type tunnelInfo struct {
	ClusterID    uuid.UUID
	ConnectedAt  time.Time
	AgentVersion string
	K8sVersion   string
}

// NewHub constructs a Hub. pool may be nil (single-tenant fallback —
// tunnels still work, but pairing tokens have to be set out-of-band
// via env, which is only useful for dev).
func NewHub(pool *pgxpool.Pool, log *slog.Logger) *Hub {
	if log == nil {
		log = slog.Default()
	}
	h := &Hub{
		pool:    pool,
		log:     log,
		online:  map[uuid.UUID]*tunnelInfo{},
		pending: map[string]chan uuid.UUID{},
	}
	h.rd = remotedialer.New(h.authorize, remotedialer.DefaultErrorWriter)
	return h
}

// ServeHTTP exposes the Hub as an http.Handler — mount it at /v1/connect.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.rd.ServeHTTP(w, r)
}

// authorize is invoked by remotedialer when an agent's WS upgrade
// request arrives. We translate the bearer token into a cluster_id
// (the clientKey remotedialer will use to address this tunnel).
func (h *Hub) authorize(req *http.Request) (string, bool, error) {
	token := readToken(req)
	if token == "" {
		return "", false, errors.New("missing pairing token")
	}

	clusterID, err := h.resolveToken(req.Context(), token, req.Header.Get(HeaderAgentVersion), req.Header.Get(HeaderK8sVersion))
	if err != nil {
		h.log.Warn("agent rejected", "err", err)
		return "", false, err
	}

	info := &tunnelInfo{
		ClusterID:    clusterID,
		ConnectedAt:  time.Now(),
		AgentVersion: req.Header.Get(HeaderAgentVersion),
		K8sVersion:   req.Header.Get(HeaderK8sVersion),
	}
	h.mu.Lock()
	h.online[clusterID] = info
	notify := h.pending[token]
	delete(h.pending, token)
	h.mu.Unlock()

	if notify != nil {
		select {
		case notify <- clusterID:
		default:
		}
	}

	h.markOnline(req.Context(), clusterID, info, true)

	go h.watchClose(clusterID, token)

	h.log.Info("agent connected",
		"cluster_id", clusterID,
		"agent_version", info.AgentVersion,
		"k8s_version", info.K8sVersion,
	)
	return clusterID.String(), true, nil
}

// watchClose polls remotedialer.Server.HasSession(clientKey) and marks
// the cluster offline when the WS goes away. remotedialer doesn't fire
// a callback on disconnect, so we poll at a low rate (every 5s).
func (h *Hub) watchClose(clusterID uuid.UUID, token string) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		if !h.rd.HasSession(clusterID.String()) {
			h.mu.Lock()
			delete(h.online, clusterID)
			h.mu.Unlock()
			h.markOffline(context.Background(), clusterID)
			h.log.Info("agent disconnected", "cluster_id", clusterID)
			return
		}
	}
}

// resolveToken validates a pairing token. On first use it consumes the
// token (sets used_at) and creates the cluster row when needed. On
// subsequent uses it returns the existing cluster_id.
func (h *Hub) resolveToken(ctx context.Context, token, agentVer, k8sVer string) (uuid.UUID, error) {
	if h.pool == nil {
		// Single-tenant dev fallback: token is the literal cluster_id.
		id, err := uuid.Parse(token)
		if err != nil {
			return uuid.Nil, errors.New("invalid token (no DB; expected uuid)")
		}
		return id, nil
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var (
		orgID      *uuid.UUID
		name, desc string
		expiresAt  time.Time
		clusterID  *uuid.UUID
	)
	err = tx.QueryRow(ctx, `
		SELECT org_id, name, description, expires_at, cluster_id
		FROM pairing_tokens WHERE token = $1`, token).
		Scan(&orgID, &name, &desc, &expiresAt, &clusterID)
	if err == pgx.ErrNoRows {
		return uuid.Nil, errors.New("unknown pairing token")
	}
	if err != nil {
		return uuid.Nil, err
	}
	if time.Now().After(expiresAt) && clusterID == nil {
		return uuid.Nil, errors.New("pairing token expired (and was never used)")
	}

	if clusterID != nil {
		// Reconnect — token already paired with a cluster.
		if _, err := tx.Exec(ctx, `
			UPDATE clusters SET online=true, last_seen=now(),
				agent_version = COALESCE(NULLIF($2,''), agent_version),
				k8s_version   = COALESCE(NULLIF($3,''), k8s_version)
			WHERE id = $1`, *clusterID, agentVer, k8sVer); err != nil {
			return uuid.Nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return uuid.Nil, err
		}
		return *clusterID, nil
	}

	// First connect — create the cluster row and bind the token to it.
	newID := uuid.New()
	var orgArg any = nil
	if orgID != nil {
		orgArg = *orgID
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO clusters (id, org_id, name, apiserver_url, kubeconfig, description,
			created_by, connect_mode, online, last_seen, agent_version, k8s_version)
		VALUES ($1, $2, $3, NULL, NULL, $4, $5, 'tunnel', true, now(), $6, $7)`,
		newID, orgArg, name, desc, "agent:"+token[:8], agentVer, k8sVer); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE pairing_tokens SET used_at = now(), cluster_id = $1 WHERE token = $2`,
		newID, token); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return newID, nil
}

func (h *Hub) markOnline(ctx context.Context, id uuid.UUID, info *tunnelInfo, _ bool) {
	if h.pool == nil {
		return
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _ = h.pool.Exec(c, `
		UPDATE clusters SET online=true, last_seen=now(),
			agent_version = COALESCE(NULLIF($2,''), agent_version),
			k8s_version   = COALESCE(NULLIF($3,''), k8s_version)
		WHERE id = $1`, id, info.AgentVersion, info.K8sVersion)
}

func (h *Hub) markOffline(ctx context.Context, id uuid.UUID) {
	if h.pool == nil {
		return
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, _ = h.pool.Exec(c, `UPDATE clusters SET online=false WHERE id=$1`, id)
}

// IsOnline reports whether a cluster currently has a live WS tunnel.
func (h *Hub) IsOnline(clusterID uuid.UUID) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.online[clusterID]
	return ok && h.rd.HasSession(clusterID.String())
}

// Dialer returns a net.Dialer-style function that opens a TCP-like
// connection through the agent's tunnel. The address passed in is
// what the agent's custom dialer will receive — for our use case
// always pass AgentDialAddress.
func (h *Hub) Dialer(clusterID uuid.UUID) func(ctx context.Context, network, address string) (net.Conn, error) {
	d := h.rd.Dialer(clusterID.String())
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return d(ctx, network, address)
	}
}

// RoundTripper builds an http.RoundTripper that funnels every request
// through the agent for the given cluster. The agent's apiserver
// proxy listens on AgentDialAddress and handles TLS + bearer-token
// injection internally, so on the server side we speak plain HTTP.
func (h *Hub) RoundTripper(clusterID uuid.UUID) http.RoundTripper {
	dialer := h.Dialer(clusterID)
	return &http.Transport{
		// Force every dial through the tunnel.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer(ctx, network, AgentDialAddress)
		},
		ForceAttemptHTTP2:     false, // agent loopback is HTTP/1.1
		MaxIdleConns:          20,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// ClientForCluster returns a typed Kubernetes client whose Transport
// rides the agent tunnel — every API call lands at the customer's
// in-cluster apiserver via the agent's loopback proxy.
//
// Used for cluster-scoped user onboarding: when the SaaS has no
// in-cluster k8s integration of its own (--k8s=false), we still need
// a clientset to create ServiceAccounts / Roles / RoleBindings in
// tunnel-connected clusters.
func (h *Hub) ClientForCluster(clusterID uuid.UUID) (kubernetes.Interface, error) {
	if !h.IsOnline(clusterID) {
		return nil, fmt.Errorf("cluster %s has no live agent", clusterID)
	}
	cfg := &rest.Config{
		// Host is unused once Transport is set, but client-go validates
		// it as a syntactically-valid URL. The tunnel ignores the host.
		Host: "http://apiserver",
		// Plain HTTP — the agent does TLS termination locally.
		Transport: h.RoundTripper(clusterID),
		// Generous timeouts; kubectl traffic is interactive.
		Timeout: 60 * time.Second,
	}
	return kubernetes.NewForConfig(cfg)
}

// --- Pairing token API ---

// CreatePairingToken mints a one-shot token an admin can hand to an
// agent install command. Token is hex-encoded (`ppc_` + 32 hex chars).
// Lives 1h before first use; lifetime is unbounded once paired.
func (h *Hub) CreatePairingToken(ctx context.Context, orgID uuid.UUID, name, description, createdBy string) (string, error) {
	if h.pool == nil {
		return "", errors.New("pairing tokens require Postgres")
	}
	token := newToken()
	var orgArg any = orgID
	if orgID == uuid.Nil {
		orgArg = nil
	}
	expires := time.Now().Add(time.Hour)
	if _, err := h.pool.Exec(ctx, `
		INSERT INTO pairing_tokens (token, org_id, name, description, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		token, orgArg, name, description, createdBy, expires); err != nil {
		return "", err
	}
	return token, nil
}

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "ppc_" + hex.EncodeToString(b)
}

func readToken(req *http.Request) string {
	if v := req.Header.Get(HeaderToken); v != "" {
		return v
	}
	auth := req.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[len("Bearer "):])
	}
	return ""
}

// dummy to silence unused-import in pure-stdlib builds
var _ = fmt.Sprintf
