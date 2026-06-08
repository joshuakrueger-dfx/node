-- ===========================================================================
-- 0019_zk402_settlement_observation.sql
--
-- Real settlement finality: derive a ZK402 intent's status from the ACTUAL
-- zkCoins receive state — an incoming transfer on the intent's unique
-- receiving address — reaching `final` at >= 6 confirmations (Protocol Spec
-- §3.9), replacing the mocked batch settlement. Correlation is by a fresh
-- per-intent receiving address (1:1 intent <-> incoming coin), so NO memo /
-- reference field is required (zkCoins coins carry none).
--
-- Non-custodial: an observation is an append-only fact about on-chain depth;
-- no balance is ever stored (the schema lint still forbids deposit/treasury/
-- payout columns).
-- ===========================================================================

-- Per-intent unique zkCoins receiving address. The buyer pays THIS address,
-- so a receive on it identifies exactly this intent. Nullable: legacy intents
-- and exact payments that are not receive-correlated leave it NULL and never
-- advance past their current status (fail-closed).
ALTER TABLE zk402_payment_intents ADD COLUMN receiving_address TEXT;

-- Append-only observation log. Each row records a fact: "a transfer of
-- amount_sats to receiving_address was seen, anchored at block_height".
-- Written by the scanner / `/api/receive` seam (`record_receive_observation`);
-- read by `advance_intent_settlement`, which computes confirmations against
-- the current chain tip and maps depth -> published / confirmed / final.
CREATE TABLE zk402_settlement_observations (
    id                BIGSERIAL   PRIMARY KEY,
    payment_intent_id TEXT        REFERENCES zk402_payment_intents(id),
    receiving_address TEXT        NOT NULL,
    amount_sats       BIGINT      NOT NULL,
    block_height      BIGINT,
    observed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lookup by address (advance reads the latest observation for an intent's
-- receiving address) and by intent (audit / dashboard).
CREATE INDEX zk402_settlement_observations_address_idx
    ON zk402_settlement_observations (receiving_address, observed_at);
CREATE INDEX zk402_settlement_observations_intent_idx
    ON zk402_settlement_observations (payment_intent_id, observed_at);
