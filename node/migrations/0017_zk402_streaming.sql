-- ZK402-Stream: metering channel + Flow-D usage ledger (improvement).
--
-- Upgrades an authorization session into a *metering channel* for
-- streaming / LLM-token billing (see proposals/ZK402_STREAM_design.md in
-- the context repo). The buyer signs an "up-to" voucher per inference
-- (ZK402-STREAM-V1) carrying a monotone cumulative ceiling; the server
-- meters ACTUAL usage (<= the per-voucher max) off-chain and advances a
-- usage cursor that can never exceed the signed cap. On-chain netting of
-- the metered total is deferred to the (pluggable) settlement backend.
--
-- Non-custodial: `metered_amount_sats` / `authorized_cumulative_sats`
-- are cap-accounting cursors over signed vouchers and the append-only
-- usage log — NOT an operator-held balance. No schema name hardcoded.

ALTER TABLE zk402_authorizations
    ADD COLUMN channel_mode TEXT NOT NULL DEFAULT 'authorization',
    ADD COLUMN authorized_cumulative_sats BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN metered_amount_sats BIGINT NOT NULL DEFAULT 0;

ALTER TABLE zk402_authorizations
    ADD CONSTRAINT zk402_authorizations_channel_mode_chk
    CHECK (channel_mode IN ('exact', 'authorization', 'metering'));

-- Append-only per-inference usage meter. `cost_sats` is the actual
-- charged amount (derived from quantity x unit_price_microsats); the sum
-- of a channel's cost_sats equals its `metered_amount_sats` cursor.
CREATE TABLE zk402_usage_events (
    id                   BIGSERIAL   PRIMARY KEY,
    channel_id           TEXT        NOT NULL REFERENCES zk402_authorizations(id),
    voucher_seq          BIGINT      NOT NULL,
    unit                 TEXT        NOT NULL,
    quantity             BIGINT      NOT NULL,
    unit_price_microsats BIGINT      NOT NULL,
    cost_sats            BIGINT      NOT NULL,
    model                TEXT,
    request_hash         TEXT        NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX zk402_usage_events_channel_idx
    ON zk402_usage_events (channel_id, created_at);
