-- TAO Gateway — Postgres schema
-- Run once on a fresh database: psql $DATABASE_URL -f schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Customers ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL UNIQUE,
    name        TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active      BOOLEAN NOT NULL DEFAULT TRUE
);

-- ── API Keys ─────────────────────────────────────────────────────────────────
-- key_hash is SHA-256 of the raw key — we never store the raw key after creation
CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id  UUID NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    key_hash     TEXT NOT NULL UNIQUE,      -- SHA-256, hex-encoded
    key_prefix   TEXT NOT NULL,             -- first 12 chars e.g. sk_live_tao_ (for display)
    name         TEXT,                      -- human label e.g. "production"
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,               -- NULL = active
    quota_rpm    INT NOT NULL DEFAULT 60,   -- requests per minute limit
    quota_tpm    INT NOT NULL DEFAULT 100000 -- tokens per minute limit
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_customer ON api_keys (customer_id);

-- ── Usage Events ─────────────────────────────────────────────────────────────
-- Lightweight billing ledger. ClickHouse gets the full log later; this is
-- just enough to compute a customer's current spend.
CREATE TABLE IF NOT EXISTS usage_events (
    id              BIGSERIAL PRIMARY KEY,
    api_key_id      UUID NOT NULL REFERENCES api_keys(id),
    customer_id     UUID NOT NULL,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    subnet          TEXT NOT NULL,          -- e.g. SN64-Chutes
    model           TEXT NOT NULL,
    prompt_tokens   INT NOT NULL DEFAULT 0,
    completion_tokens INT NOT NULL DEFAULT 0,
    latency_ms      INT,
    status          TEXT NOT NULL DEFAULT 'ok', -- ok | error | fallback
    cost_usd        NUMERIC(12, 8)          -- what we charged
);

CREATE INDEX IF NOT EXISTS idx_usage_customer ON usage_events (customer_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_usage_key ON usage_events (api_key_id, ts DESC);

-- ── Seed: dev key for local testing ──────────────────────────────────────────
-- Raw key: sk_live_taogateway_dev
-- SHA-256:  echo -n "sk_live_taogateway_dev" | sha256sum
INSERT INTO customers (id, email, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'dev@taogateway.dev', 'Dev Account')
ON CONFLICT DO NOTHING;

INSERT INTO api_keys (customer_id, key_hash, key_prefix, name, quota_rpm, quota_tpm)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    encode(digest('sk_live_taogateway_dev', 'sha256'), 'hex'),
    'sk_live_tao',
    'local-dev',
    1000,
    10000000
)
ON CONFLICT DO NOTHING;
