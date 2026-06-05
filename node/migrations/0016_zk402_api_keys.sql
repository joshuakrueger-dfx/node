-- ZK402 dashboard API keys (Step 9: dashboard & operations).
--
-- A merchant authenticates to the dashboard with a bearer API key. Only
-- the SHA-256 hash of the key is stored — the plaintext is shown once at
-- issuance and never again. A key scopes every dashboard read to its
-- merchant, so a merchant can only ever see its own data.
--
-- No schema name is hardcoded (per-test search_path isolation, see
-- node/src/test_db.rs). Non-custodial: this table grants read access to
-- a merchant's own settlement view; it never holds or moves funds.
CREATE TABLE zk402_api_keys (
    id          TEXT        PRIMARY KEY,
    merchant_id TEXT        NOT NULL REFERENCES zk402_merchants(id),
    key_hash    BYTEA       NOT NULL,
    label       TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ,
    CHECK (octet_length(key_hash) = 32)
);

-- Auth lookup is by key hash; only non-revoked keys resolve.
CREATE UNIQUE INDEX zk402_api_keys_hash_uq ON zk402_api_keys (key_hash);
CREATE INDEX zk402_api_keys_merchant_idx ON zk402_api_keys (merchant_id, created_at);
