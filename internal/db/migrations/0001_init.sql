-- 0001_init: clusters, onboarded users, proxy audit log.
--
-- Design notes:
--
-- - clusters.kubeconfig stores the raw YAML uploaded by an admin.
--   We do NOT encrypt at rest yet — that's deliberate Phase-B work
--   (envelope encryption with a key in a Secret). For now we rely on
--   Postgres' on-disk encryption + restricted DB user permissions.
--
-- - users.cluster_id is a hard FK with ON DELETE CASCADE: removing a
--   cluster wipes its onboarded users. The remote SA/Role/RoleBinding
--   cleanup is best-effort and runs at delete time.
--
-- - proxy_audit is append-only. We never UPDATE rows; we partition or
--   archive in Phase B if it grows.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE clusters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT UNIQUE NOT NULL,
    apiserver_url   TEXT NOT NULL,
    kubeconfig      TEXT NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      TEXT
);

CREATE INDEX clusters_created_at_idx ON clusters (created_at DESC);

CREATE TABLE onboarded_users (
    name              TEXT NOT NULL,
    cluster_id        UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    namespace         TEXT NOT NULL,
    scope             TEXT NOT NULL,
    description       TEXT,
    service_account   TEXT NOT NULL,
    role              TEXT NOT NULL,
    role_binding      TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by        TEXT,
    PRIMARY KEY (name, cluster_id)
);

CREATE INDEX onboarded_users_cluster_idx ON onboarded_users (cluster_id);

CREATE TABLE proxy_audit (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    cluster_id  UUID NOT NULL,
    user_name   TEXT,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    status      INT NOT NULL,
    duration_ms INT NOT NULL,
    client_ip   TEXT
);

CREATE INDEX proxy_audit_ts_idx        ON proxy_audit (ts DESC);
CREATE INDEX proxy_audit_user_idx      ON proxy_audit (user_name, ts DESC);
CREATE INDEX proxy_audit_cluster_idx   ON proxy_audit (cluster_id, ts DESC);
