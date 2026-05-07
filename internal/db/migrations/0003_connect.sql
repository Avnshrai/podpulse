-- 0003_connect.sql — agent-based cluster onboarding ("connect mode").
--
-- A customer cluster can be registered two ways:
--
--   1. paste a kubeconfig (mode='kubeconfig')   — works when PodPulse
--      can reach the apiserver directly.
--
--   2. install the pp-connect agent (mode='tunnel') — agent dials home
--      from inside the cluster, PodPulse tunnels kubectl traffic back
--      through that connection. Required when the apiserver is behind
--      a VPN or private endpoint.
--
-- pairing_tokens are short-lived (1h) one-shot secrets minted by an
-- admin. The agent presents one when it dials home; on success the
-- pairing row is consumed and the cluster row is created.

ALTER TABLE clusters
    ADD COLUMN IF NOT EXISTS connect_mode      text        NOT NULL DEFAULT 'kubeconfig',
    ADD COLUMN IF NOT EXISTS online            boolean     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS last_seen         timestamptz,
    ADD COLUMN IF NOT EXISTS agent_version     text,
    ADD COLUMN IF NOT EXISTS k8s_version       text;

-- Allow kubeconfig to be NULL when mode='tunnel' (agent provides RBAC).
ALTER TABLE clusters
    ALTER COLUMN kubeconfig DROP NOT NULL,
    ALTER COLUMN apiserver_url DROP NOT NULL;

CREATE TABLE IF NOT EXISTS pairing_tokens (
    token        text        PRIMARY KEY,
    org_id       uuid        REFERENCES organizations(id) ON DELETE CASCADE,
    name         text        NOT NULL,
    description  text        NOT NULL DEFAULT '',
    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    cluster_id   uuid        REFERENCES clusters(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS pairing_tokens_org_idx        ON pairing_tokens(org_id);
CREATE INDEX IF NOT EXISTS pairing_tokens_expires_at_idx ON pairing_tokens(expires_at);
