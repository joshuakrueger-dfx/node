-- ===========================================================================
-- 0020_zk402_agents_disputes.sql
--
-- Agent Economy Phase 1 — Layer 3 (Identity / delegation) + Layer 4 (Disputes).
-- See proposals/AGENT_ECONOMY_design.md §4.
--
--   * zk402_agents             — a self-sovereign agent identity keyed by its
--                                Schnorr identity key. NO owner column: the
--                                handle maps to a key, never to a human, so the
--                                zkCoins unlinkability property is preserved.
--   * zk402_agent_session_keys — delegated, scoped, revocable session keys. The
--                                identity key signs a `ZK402-AUTHORIZATION-V1`
--                                delegation; the session key then signs vouchers
--                                within the caps (closes the authorization seam).
--   * zk402_disputes           — append-only signed `ZK402-DISPUTE-V1` ratings
--                                bound to a settled receipt; feeds reputation.
--
-- Non-custodial: no funds, no balances, no payout — only identity, delegation,
-- and signed attestations.
-- ===========================================================================

CREATE TABLE zk402_agents (
    id                TEXT        PRIMARY KEY,          -- = identity key zkpayer_<x-only hex>
    handle            TEXT,                             -- optional handle@domain (UNIQUE below)
    capabilities_json TEXT        NOT NULL DEFAULT '[]',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX zk402_agents_handle_uq ON zk402_agents (handle) WHERE handle IS NOT NULL;

CREATE TABLE zk402_agent_session_keys (
    id                   TEXT        PRIMARY KEY,
    agent_id             TEXT        NOT NULL REFERENCES zk402_agents(id),
    session_pubkey       TEXT        NOT NULL,
    scope_json           TEXT        NOT NULL DEFAULT '{}',
    authorized_amount_sats        BIGINT NOT NULL DEFAULT 0,
    spend_limit_per_request_sats  BIGINT NOT NULL DEFAULT 0,
    spend_limit_total_sats        BIGINT NOT NULL DEFAULT 0,
    allowed_merchants_hash TEXT,
    allowed_merchants_json TEXT      NOT NULL DEFAULT '[]',   -- the signed set, for membership checks
    facilitator          TEXT        NOT NULL,
    network              TEXT        NOT NULL,
    valid_after          BIGINT      NOT NULL,          -- unix seconds (matches the signed message)
    valid_before         BIGINT      NOT NULL,
    revoked_at           TIMESTAMPTZ,
    delegation_signature TEXT        NOT NULL,          -- identity-key sig over ZK402-AUTHORIZATION-V1
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX zk402_agent_session_keys_agent_idx ON zk402_agent_session_keys (agent_id, created_at);
CREATE UNIQUE INDEX zk402_agent_session_keys_pubkey_uq ON zk402_agent_session_keys (session_pubkey);

CREATE TABLE zk402_disputes (
    id                     TEXT        PRIMARY KEY,
    receipt_id             TEXT        NOT NULL REFERENCES zk402_receipts(id),
    complainant            TEXT        NOT NULL,        -- = the receipt's payer (enforced in file_dispute)
    verdict                TEXT        NOT NULL,
    reason_hash            TEXT        NOT NULL,
    attestation_signature  TEXT        NOT NULL,        -- complainant sig over ZK402-DISPUTE-V1
    signed_timestamp       BIGINT      NOT NULL,        -- the signed timestamp, so the attestation is offline-verifiable
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (verdict IN ('ok','bad','refunded'))
);
CREATE INDEX zk402_disputes_receipt_idx ON zk402_disputes (receipt_id, created_at);
CREATE INDEX zk402_disputes_complainant_idx ON zk402_disputes (complainant, created_at);
