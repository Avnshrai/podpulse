-- 0002_auth: organizations, users (email/password), sessions, and
-- org_id tagging on existing tenant-data tables so every read/write
-- can be scoped to the caller's org.
--
-- Strict tenant isolation rule (enforced at the query layer):
--   every SELECT / INSERT / UPDATE / DELETE on tenant tables MUST
--   include `org_id = $current_org_id`.

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE org_users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           CITEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin','member')),
    display_name    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX org_users_org_idx ON org_users (org_id);

CREATE TABLE sessions (
    token       TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES org_users(id) ON DELETE CASCADE,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role        TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
CREATE INDEX sessions_user_idx ON sessions (user_id);

-- Tenant-scope existing tables. We cascade-delete tenant data when
-- the org goes away, mirroring how onboarded users vanish with their
-- cluster.
ALTER TABLE clusters
    ADD COLUMN org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX clusters_org_idx ON clusters (org_id);

ALTER TABLE onboarded_users
    ADD COLUMN org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX onboarded_users_org_idx ON onboarded_users (org_id);

-- proxy_audit is append-only and high-volume; we don't FK it to keep
-- inserts cheap, but we do index by (org_id, ts) for the per-org
-- audit timeline view.
ALTER TABLE proxy_audit ADD COLUMN org_id UUID;
CREATE INDEX proxy_audit_org_ts_idx ON proxy_audit (org_id, ts DESC);
