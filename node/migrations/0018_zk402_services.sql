-- ZK402 Agent Economy — Layer 1: service catalog (Bazaar discovery).
--
-- A *service* is a merchant's discoverable, machine-selectable offering:
-- what capability it sells, at what price, with what input/output schema,
-- on which (testnet) network, behind which facilitator. It is the supply
-- side an autonomous agent searches before it pays
-- (proposals/AGENT_ECONOMY_design.md, Layer 1). The catalog is served
-- verbatim by the x402 v2 discovery endpoints
-- (`GET /v2/x402/discovery/{resources,search}`), so any x402 agent can
-- find it; we differentiate on private settlement + reputation, not on a
-- bespoke registry.
--
-- Non-custodial: a service is OWNED by a merchant and inherits that
-- merchant's own `settlement_address` — it introduces NO balance, deposit,
-- treasury, or payout field. `price_policy_json` is a *quote* the buyer
-- signs against, never operator-held value. No schema name is hardcoded.
--
-- Testnet-only: `network` is validated against the supported set
-- (`zkcoins:{regtest,mutinynet,signet}`) in code at write time; there is
-- no `zkcoins:mainnet` path. `access_threshold` defaults to the
-- payment-proven `publisher_accepted`, never a weaker value.

CREATE TABLE zk402_services (
    id               TEXT        PRIMARY KEY,
    merchant_id      TEXT        NOT NULL REFERENCES zk402_merchants(id),
    capability       TEXT        NOT NULL,
    display_name     TEXT        NOT NULL,
    description      TEXT,
    endpoint         TEXT        NOT NULL,
    input_schema     TEXT,
    output_schema    TEXT,
    network          TEXT        NOT NULL,
    asset            TEXT        NOT NULL DEFAULT 'btc-sats',
    price_policy_json JSONB      NOT NULL,
    headline_amount_sats BIGINT  NOT NULL,
    access_threshold TEXT        NOT NULL DEFAULT 'publisher_accepted',
    resource_hash    TEXT        NOT NULL,
    facilitator      TEXT        NOT NULL,
    privacy_level    TEXT        NOT NULL DEFAULT 'private',
    status           TEXT        NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT zk402_services_status_chk
        CHECK (status IN ('active', 'disabled')),
    CONSTRAINT zk402_services_access_threshold_chk
        CHECK (access_threshold IN
            ('publisher_accepted', 'published', 'confirmed', 'final', 'verified_only')),
    CONSTRAINT zk402_services_privacy_level_chk
        CHECK (privacy_level IN ('private', 'public'))
);

-- Discovery reads filter by capability + active status and list a
-- merchant's own catalog.
CREATE INDEX zk402_services_capability_idx
    ON zk402_services (capability, status);
CREATE INDEX zk402_services_merchant_idx
    ON zk402_services (merchant_id);
