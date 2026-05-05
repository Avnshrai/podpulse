// Package auth implements PodPulse's multi-tenant org/user/session
// flow. Each PodPulse tenant is an Organization. Every user belongs
// to exactly one org and has a role of either "admin" or "member".
//
//   admin   — can register clusters, onboard cluster users, view
//             everything in the org.
//   member  — read-only: sees Issues / Workloads / What changed /
//             Audit log. Cannot register clusters or onboard users.
//
// Sessions are simple opaque tokens (32 random bytes hex-encoded)
// stored in the sessions table. Sent as `pp_session` cookie OR as
// `Authorization: Bearer <token>`. 7-day TTL, sliding (refreshed on
// every authenticated request).
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

const (
	SessionTTL    = 7 * 24 * time.Hour
	CookieName    = "pp_session"
	RoleAdmin     = "admin"
	RoleMember    = "member"
)

// Identity is the resolved caller from a session token.
type Identity struct {
	UserID  uuid.UUID
	OrgID   uuid.UUID
	OrgSlug string
	OrgName string
	Email   string
	Role    string
	Display string
}

func (i *Identity) IsAdmin() bool { return i != nil && i.Role == RoleAdmin }

// Manager is the auth surface used by the api package.
type Manager struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Manager { return &Manager{pool: pool} }

// Pool returns the underlying Postgres pool. Used by other packages
// that need to query auth-tagged tenant tables (proxy_audit, etc.)
// while sharing the same connection pool.
func (m *Manager) Pool() *pgxpool.Pool {
	if m == nil {
		return nil
	}
	return m.pool
}

// Available reports whether auth is wired up (i.e. Postgres is
// available). When false, the api package falls back to single-user
// mode (no orgs, no auth gating — the legacy single-tenant flow).
func (m *Manager) Available() bool { return m != nil && m.pool != nil }

// --- Signup / Login ---

// Signup creates a brand-new organization and its first admin user
// in one transaction. Returns the new session token.
func (m *Manager) Signup(ctx context.Context, orgName, email, password, displayName string) (string, *Identity, error) {
	if !m.Available() {
		return "", nil, errors.New("auth not available (Postgres not configured)")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	orgName = strings.TrimSpace(orgName)
	if orgName == "" || email == "" || len(password) < 8 {
		return "", nil, errors.New("org name, email, and 8+ char password are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", nil, err
	}
	slug := slugify(orgName)

	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback(ctx)

	var orgID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING id`,
		orgName, slug).Scan(&orgID); err != nil {
		return "", nil, &SignupError{Field: "org", Err: err}
	}

	var userID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO org_users (org_id, email, password_hash, role, display_name)
		VALUES ($1, $2, $3, 'admin', $4) RETURNING id`,
		orgID, email, string(hash), nullStr(displayName)).Scan(&userID); err != nil {
		return "", nil, &SignupError{Field: "user", Err: err}
	}

	token, expiresAt, err := mintSession(ctx, tx, userID, orgID, RoleAdmin)
	if err != nil {
		return "", nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", nil, err
	}
	_ = expiresAt
	return token, &Identity{
		UserID: userID, OrgID: orgID, OrgSlug: slug, OrgName: orgName,
		Email: email, Role: RoleAdmin, Display: displayName,
	}, nil
}

// SignupError lets the API surface friendly conflict errors.
type SignupError struct {
	Field string
	Err   error
}

func (e *SignupError) Error() string { return e.Field + ": " + e.Err.Error() }
func (e *SignupError) Unwrap() error { return e.Err }

// Login validates the email/password and mints a fresh session.
func (m *Manager) Login(ctx context.Context, email, password string) (string, *Identity, error) {
	if !m.Available() {
		return "", nil, errors.New("auth not available")
	}
	email = strings.ToLower(strings.TrimSpace(email))

	var userID, orgID uuid.UUID
	var hash, role, display, orgSlug, orgName string
	err := m.pool.QueryRow(ctx, `
		SELECT u.id, u.org_id, u.password_hash, u.role, COALESCE(u.display_name,''),
		       o.slug, o.name
		FROM org_users u JOIN organizations o ON o.id = u.org_id
		WHERE u.email = $1`, email).Scan(
		&userID, &orgID, &hash, &role, &display, &orgSlug, &orgName)
	if err == pgx.ErrNoRows {
		return "", nil, errors.New("invalid email or password")
	}
	if err != nil {
		return "", nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", nil, errors.New("invalid email or password")
	}

	token, _, err := mintSessionWithPool(ctx, m.pool, userID, orgID, role)
	if err != nil {
		return "", nil, err
	}
	return token, &Identity{
		UserID: userID, OrgID: orgID, OrgSlug: orgSlug, OrgName: orgName,
		Email: email, Role: role, Display: display,
	}, nil
}

// Logout deletes the session row.
func (m *Manager) Logout(ctx context.Context, token string) error {
	if !m.Available() || token == "" {
		return nil
	}
	_, err := m.pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, token)
	return err
}

// Resolve verifies a session token and returns the caller's identity.
// Returns nil + non-nil error for any auth failure.
func (m *Manager) Resolve(ctx context.Context, token string) (*Identity, error) {
	if !m.Available() {
		return nil, errors.New("auth not available")
	}
	if token == "" {
		return nil, errors.New("missing token")
	}
	var userID, orgID uuid.UUID
	var role, email, display, orgSlug, orgName string
	var expiresAt time.Time
	err := m.pool.QueryRow(ctx, `
		SELECT s.user_id, s.org_id, s.role, s.expires_at,
		       u.email, COALESCE(u.display_name,''),
		       o.slug, o.name
		FROM sessions s
		JOIN org_users u ON u.id = s.user_id
		JOIN organizations o ON o.id = s.org_id
		WHERE s.token = $1`, token).Scan(
		&userID, &orgID, &role, &expiresAt, &email, &display, &orgSlug, &orgName)
	if err == pgx.ErrNoRows {
		return nil, errors.New("session not found")
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(expiresAt) {
		_, _ = m.pool.Exec(ctx, `DELETE FROM sessions WHERE token = $1`, token)
		return nil, errors.New("session expired")
	}
	// Sliding expiry: bump the session forward when used.
	_, _ = m.pool.Exec(ctx,
		`UPDATE sessions SET expires_at = $1 WHERE token = $2`,
		time.Now().Add(SessionTTL), token)
	return &Identity{
		UserID: userID, OrgID: orgID, OrgSlug: orgSlug, OrgName: orgName,
		Email: email, Role: role, Display: display,
	}, nil
}

// --- HTTP middleware + helpers ---

type ctxKey int

const identityKey ctxKey = 1

// IdentityFromContext retrieves the resolved caller identity, or nil.
func IdentityFromContext(ctx context.Context) *Identity {
	v, _ := ctx.Value(identityKey).(*Identity)
	return v
}

// WithIdentity stores an identity in the context.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// TokenFromRequest reads the session token from the cookie or
// Authorization: Bearer header.
func TokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	return ""
}

// SetSessionCookie writes the session cookie. SameSite=Lax + httponly.
// Secure flag is on when r.URL.Scheme is https; we accept r=nil for
// non-request contexts.
func SetSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	c := &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(SessionTTL.Seconds()),
	}
	if r != nil && r.TLS != nil {
		c.Secure = true
	}
	http.SetCookie(w, c)
}

// ClearSessionCookie expires the cookie immediately.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
}

// --- internals ---

func mintSession(ctx context.Context, tx pgx.Tx, userID, orgID uuid.UUID, role string) (string, time.Time, error) {
	token := newToken()
	exp := time.Now().Add(SessionTTL)
	_, err := tx.Exec(ctx, `
		INSERT INTO sessions (token, user_id, org_id, role, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		token, userID, orgID, role, exp)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func mintSessionWithPool(ctx context.Context, pool *pgxpool.Pool, userID, orgID uuid.UUID, role string) (string, time.Time, error) {
	token := newToken()
	exp := time.Now().Add(SessionTTL)
	_, err := pool.Exec(ctx, `
		INSERT INTO sessions (token, user_id, org_id, role, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		token, userID, orgID, role, exp)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	out := make([]byte, 0, len(s))
	prevDash := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
			prevDash = false
		case c == ' ' || c == '-' || c == '_':
			if !prevDash && len(out) > 0 {
				out = append(out, '-')
				prevDash = true
			}
		}
	}
	res := strings.TrimRight(string(out), "-")
	if res == "" {
		res = "org"
	}
	return res
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
