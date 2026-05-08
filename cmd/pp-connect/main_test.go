package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestAPIServerProxy_AuthPrecedence is the regression test for the
// RBAC escape we shipped briefly: the agent was unconditionally
// replacing the caller's Authorization with its own cluster-admin SA
// token, so every scoped end-user kubectl call ended up authenticated
// as pp-connect (cluster-admin). The contract:
//
//   1. Caller has Authorization → forward unmodified.
//   2. Caller has no Authorization → inject the agent's SA token.
//
// Both cases must work; failing #1 is a privilege escalation, failing
// #2 breaks SaaS-initiated admin onboarding (no bearer present).
func TestAPIServerProxy_AuthPrecedence(t *testing.T) {
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte("AGENT_SA_TOKEN"), 0600); err != nil {
		t.Fatal(err)
	}

	// Stand in for the in-cluster apiserver. Echoes the Authorization
	// header it received so the test can assert who reached it.
	var lastSeen atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastSeen.Store(r.Header.Get("Authorization"))
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	tokens := &tokenSource{path: tokFile}
	if _, err := tokens.read(); err != nil {
		t.Fatal(err)
	}
	proxy := newAPIServerProxy(target, tlsCfg, tokens)

	// Case 1: caller already authenticated. Their bearer must reach
	// the apiserver verbatim.
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://apiserver/api/v1/pods", nil)
		req.Header.Set("Authorization", "Bearer USER_SCOPED_TOKEN")
		proxy.ServeHTTP(rec, req)
		if got := lastSeen.Load(); got != "Bearer USER_SCOPED_TOKEN" {
			t.Fatalf("scoped bearer was not preserved — apiserver saw %q (want %q). "+
				"This is the RBAC escape: end-users would authenticate as pp-connect.",
				got, "Bearer USER_SCOPED_TOKEN")
		}
	}

	// Case 2: SaaS-initiated admin call (no bearer). Agent must
	// inject its own SA token so onboarding still works.
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "http://apiserver/api/v1/namespaces/foo/serviceaccounts", strings.NewReader("{}"))
		req.Header.Del("Authorization")
		proxy.ServeHTTP(rec, req)
		if got := lastSeen.Load(); got != "Bearer AGENT_SA_TOKEN" {
			t.Fatalf("admin path: apiserver saw %q (want %q). "+
				"Without the agent's SA token, SaaS-initiated onboarding fails.",
				got, "Bearer AGENT_SA_TOKEN")
		}
	}

	// Case 3: empty bearer header (set, but with empty value) — treat
	// like missing. Defensive against a buggy client that sends
	// `Authorization:` with no value.
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "http://apiserver/api/v1/pods", nil)
		req.Header.Set("Authorization", "")
		proxy.ServeHTTP(rec, req)
		if got := lastSeen.Load(); got != "Bearer AGENT_SA_TOKEN" {
			t.Fatalf("empty Authorization: apiserver saw %q (want %q)",
				got, "Bearer AGENT_SA_TOKEN")
		}
	}
}

// TestTokenSource_Rotates verifies the on-disk token cache picks up
// kubelet's mid-run token rotation. The previous bug was that the
// agent read /var/run/.../token once at startup, never again, so
// every call after the first rotation 401'd.
func TestTokenSource_Rotates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("v1"), 0600); err != nil {
		t.Fatal(err)
	}
	ts := &tokenSource{path: p}
	if got := ts.Get(); got != "v1" {
		t.Fatalf("first read: got %q, want v1", got)
	}
	// Rewrite the file (kubelet does this before the projected token
	// expires) and walk the cache past its TTL.
	if err := os.WriteFile(p, []byte("v2"), 0600); err != nil {
		t.Fatal(err)
	}
	ts.cachedAt = time.Now().Add(-time.Minute) // force-expire cache
	if got := ts.Get(); got != "v2" {
		t.Fatalf("after rotation: got %q, want v2 — agent will use a stale token and 401", got)
	}
}
