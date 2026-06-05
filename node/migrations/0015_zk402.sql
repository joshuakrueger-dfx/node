-- ZK402 Publisher — Phase 1: Database & Domain (Step 1 of BIGBROTHER_ROADMAP.md).
--
-- ZK402 adds an x402-compatible payment layer *inside* the zkCoins
-- publisher layer (see context repo joshuakrueger-dfx/ZKcoins-x402-,
-- docs/DATA_MODEL.md and specs/x402-zkcoins-publisher-scheme.md). A
-- buyer's agent signs a canonical payment voucher; the facilitator
-- verifies it, records a payment intent, drives it through a settlement
-- state machine, and batches merchant-directed value into the zkCoins
-- publisher path. This migration lands the persistence layer for that
-- flow.
--
-- NON-CUSTODIAL by construction (prompts/00-master-context.md hard
-- rule): there is deliberately NO table or column that holds buyer
-- deposits, a session treasury, or an operator-controlled merchant
-- payout balance. Merchant accounting is an append-only *settlement
-- view* (`zk402_merchant_settlements`), never a mutable custodial
-- balance. A schema lint in the test-suite asserts the absence of any
-- column named `deposit_amount`, `treasury`, or `payout_balance`.
--
-- TESTNET-ONLY: no mainnet defaults. The `network` columns carry the
-- x402 network label (`zkcoins:regtest|mutinynet|signet`); nothing here
-- defaults to `zkcoins:mainnet`.
--
-- Schema conventions match the existing migrations:
--   * `TEXT` primary keys are the externally-surfaced ids the scheme
--     assigns (intentId / voucherId / receiptId / batchId …); they are
--     opaque strings minted by the application, per docs/DATA_MODEL.md.
--   * Enumerations use `TEXT` + `CHECK (col IN (...))` so an
--     application typo surfaces as a Postgres violation, mirroring
--     `jobs.status` (migration 0014) and `pending_inscriptions.kind`.
--   * `TIMESTAMPTZ NOT NULL DEFAULT now()` for `created_at`/`updated_at`;
--     per-state milestone timestamps are nullable and filled as a row
--     advances through the settlement state machine.
--   * No schema name is hardcoded (no `public.`, `CREATE SCHEMA`, or
--     `SET search_path`) so the per-test `search_path` schema isolation
--     in `node/src/test_db.rs` keeps working — see that module's
--     "Migration SQL precondition".

-- ---------------------------------------------------------------------------
-- zk402_merchants — a payee that receives x402 settlements.
--
-- `settlement_address` is the merchant's own zkCoins account/address;
-- the operator never custodies merchant funds. Address rotation is
-- delay-enforced: a change stages `pending_settlement_address` with an
-- `effective_at` in the future; the batch worker keeps paying the
-- current address until the delay elapses, then promotes the pending
-- one. `fee_bps` / `fixed_fee_sats` are the facilitator's fee terms.
-- ---------------------------------------------------------------------------
CREATE TABLE zk402_merchants (
    id                                     TEXT        PRIMARY KEY,
    display_name                           TEXT        NOT NULL,
    settlement_address                     TEXT        NOT NULL,
    settlement_address_verified_at         TIMESTAMPTZ,
    pending_settlement_address             TEXT,
    pending_settlement_address_effective_at TIMESTAMPTZ,
    address_change_delay_seconds           INTEGER     NOT NULL DEFAULT 86400,
    username                               TEXT        UNIQUE,
    status                                 TEXT        NOT NULL DEFAULT 'active',
    fee_bps                                INTEGER     NOT NULL DEFAULT 100,
    fixed_fee_sats                         BIGINT      NOT NULL DEFAULT 0,
    created_at                             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status IN ('active','disabled','suspended'))
);

-- ---------------------------------------------------------------------------
-- zk402_authorizations — a buyer-signed spending mandate (Mode 2).
--
-- The buyer signs caps (per-request + total), an expiry window, an
-- allowed-merchant set, and the facilitator origin. The facilitator may
-- accept vouchers only *within* these signed caps — it can never raise
-- them. `authorized_amount_sats` is the signed ceiling; `accepted_` /
-- `published_amount_sats` are denormalized running totals of spend
-- against that ceiling (cap accounting, NOT an operator-held balance).
-- ---------------------------------------------------------------------------
CREATE TABLE zk402_authorizations (
    id                            TEXT        PRIMARY KEY,
    payer                         TEXT        NOT NULL,
    network                       TEXT        NOT NULL,
    asset                         TEXT        NOT NULL DEFAULT 'btc-sats',
    authorized_amount_sats        BIGINT      NOT NULL,
    accepted_amount_sats          BIGINT      NOT NULL DEFAULT 0,
    published_amount_sats         BIGINT      NOT NULL DEFAULT 0,
    status                        TEXT        NOT NULL DEFAULT 'pending',
    valid_after                   TIMESTAMPTZ NOT NULL,
    valid_before                  TIMESTAMPTZ NOT NULL,
    spend_limit_per_request_sats  BIGINT,
    spend_limit_total_sats        BIGINT,
    allowed_merchants             JSONB       NOT NULL DEFAULT '[]'::jsonb,
    facilitator_origin            TEXT        NOT NULL,
    session_public_key            TEXT,
    authorization_signature       TEXT        NOT NULL,
    publisher_acceptance_id       TEXT,
    created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status IN ('pending','active','revoking','revoked','expired','failed'))
);

-- ---------------------------------------------------------------------------
-- zk402_payment_intents — one verified voucher / unit of payment.
--
-- `voucher_id` and `nonce` are globally unique (enforced by the unique
-- indexes below): a duplicate voucher or replayed nonce is rejected at
-- the database, which is the backstop behind the facilitator's
-- `replay_detected` path. `canonical_message` / `signature_scheme` /
-- `signature` capture exactly what the buyer signed (hashes, not private
-- descriptions — metadata privacy). The 15-value `status` enum is the
-- authoritative settlement-state list. `access_threshold` is the signed
-- finality the buyer requires before paid access; it defaults to
-- `publisher_accepted` and never to a mainnet-only or weaker setting.
-- The `*_at` milestone columns are written as the row advances.
-- ---------------------------------------------------------------------------
CREATE TABLE zk402_payment_intents (
    id                   TEXT        PRIMARY KEY,
    voucher_id           TEXT        NOT NULL,
    authorization_id     TEXT        REFERENCES zk402_authorizations(id),
    payer                TEXT        NOT NULL,
    merchant_id          TEXT        NOT NULL REFERENCES zk402_merchants(id),
    network              TEXT        NOT NULL,
    asset                TEXT        NOT NULL DEFAULT 'btc-sats',
    amount_sats          BIGINT      NOT NULL,
    fee_amount_sats      BIGINT      NOT NULL DEFAULT 0,
    resource_hash        TEXT        NOT NULL,
    request_hash         TEXT        NOT NULL,
    nonce                TEXT        NOT NULL,
    valid_after          TIMESTAMPTZ NOT NULL,
    valid_before         TIMESTAMPTZ NOT NULL,
    canonical_message    TEXT        NOT NULL,
    signature_scheme     TEXT        NOT NULL,
    signature            TEXT        NOT NULL,
    status               TEXT        NOT NULL DEFAULT 'received',
    failure_code         TEXT,
    failure_message      TEXT,
    access_threshold     TEXT        NOT NULL DEFAULT 'publisher_accepted',
    publisher_acceptance_id TEXT,
    -- settlement-state milestone timestamps (filled as the row advances)
    authorized_at        TIMESTAMPTZ,
    publisher_accepted_at TIMESTAMPTZ,
    queued_at            TIMESTAMPTZ,
    batched_at           TIMESTAMPTZ,
    published_at         TIMESTAMPTZ,
    confirmed_at         TIMESTAMPTZ,
    final_at             TIMESTAMPTZ,
    reorged_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status IN (
        'received','verified','authorized','publisher_accepted','queued',
        'batching','settling','published','confirmed','final','expired',
        'failed_recoverable','failed_terminal','reorged','reversed'
    )),
    CHECK (access_threshold IN (
        'publisher_accepted','published','confirmed','final','verified_only'
    ))
);

-- ---------------------------------------------------------------------------
-- zk402_receipts — the facilitator's signed receipt for an intent.
--
-- One receipt per payment intent (unique index below). `receipt_json`
-- is the canonical signed receipt body (Ed25519 at issuance); it
-- deliberately carries only `settlementState` as of issuance and NOT the
-- batch/proof/txid detail that becomes known later (those would
-- invalidate the issuance signature). Evolving detail is served unsigned
-- from the intent/batch rows.
-- ---------------------------------------------------------------------------
CREATE TABLE zk402_receipts (
    id                  TEXT        PRIMARY KEY,
    payment_intent_id   TEXT        NOT NULL REFERENCES zk402_payment_intents(id),
    status              TEXT        NOT NULL,
    receipt_json        JSONB       NOT NULL,
    facilitator_signature TEXT      NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- zk402_batches — a group of intents settled together via the zkCoins
-- publisher path. `merchant_id` is nullable (a batch may span the
-- native multi-merchant publisher mode). The 11-value `status` enum is
-- the batch-level state machine; a batch has no `confirmed` state —
-- `observed` is the batch-level equivalent. Proof/commit/reveal ids are
-- filled by the settlement integration (Step 8); a non-empty value here
-- never feeds back into a receipt signature.
-- ---------------------------------------------------------------------------
CREATE TABLE zk402_batches (
    id                 TEXT        PRIMARY KEY,
    network            TEXT        NOT NULL,
    merchant_id        TEXT        REFERENCES zk402_merchants(id),
    status             TEXT        NOT NULL DEFAULT 'open',
    gross_amount_sats  BIGINT      NOT NULL DEFAULT 0,
    fee_amount_sats    BIGINT      NOT NULL DEFAULT 0,
    net_amount_sats    BIGINT      NOT NULL DEFAULT 0,
    intent_count       INTEGER     NOT NULL DEFAULT 0,
    zkcoins_proof_id   TEXT,
    commit_txid        TEXT,
    reveal_txid        TEXT,
    failure_code       TEXT,
    failure_message    TEXT,
    retry_count        INTEGER     NOT NULL DEFAULT 0,
    -- batch-level milestone timestamps
    proof_started_at   TIMESTAMPTZ,
    proof_finished_at  TIMESTAMPTZ,
    published_at       TIMESTAMPTZ,
    observed_at        TIMESTAMPTZ,
    final_at           TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status IN (
        'open','locked','proof_generating','ready_to_publish','publishing',
        'published','observed','final','failed_recoverable','failed_terminal',
        'reorged'
    ))
);

-- ---------------------------------------------------------------------------
-- zk402_batch_items — membership of an intent in a batch. Composite PK
-- (batch_id, payment_intent_id); a partial-free unique index on
-- payment_intent_id alone enforces "one batch per intent".
-- ---------------------------------------------------------------------------
CREATE TABLE zk402_batch_items (
    batch_id          TEXT   NOT NULL REFERENCES zk402_batches(id),
    payment_intent_id TEXT   NOT NULL REFERENCES zk402_payment_intents(id),
    amount_sats       BIGINT NOT NULL,
    fee_sats          BIGINT NOT NULL,
    net_sats          BIGINT NOT NULL,
    PRIMARY KEY (batch_id, payment_intent_id)
);

-- ---------------------------------------------------------------------------
-- zk402_merchant_settlements — append-only ledger view of value owed /
-- moved to a merchant. This is the non-custodial accounting surface:
-- each row is an immutable entry (no `updated_at`), NOT a mutable
-- balance the operator controls. `kind` distinguishes the settlement
-- lifecycle and fee/reversal entries; the merchant's balance is a
-- derived sum over these rows, never a stored payout balance.
-- ---------------------------------------------------------------------------
CREATE TABLE zk402_merchant_settlements (
    id                TEXT        PRIMARY KEY,
    merchant_id       TEXT        NOT NULL REFERENCES zk402_merchants(id),
    payment_intent_id TEXT        REFERENCES zk402_payment_intents(id),
    batch_id          TEXT        REFERENCES zk402_batches(id),
    kind              TEXT        NOT NULL,
    amount_sats       BIGINT      NOT NULL,
    status            TEXT        NOT NULL DEFAULT 'pending',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (kind   IN ('accepted','published','confirmed','final','fee','reversal')),
    CHECK (status IN ('pending','posted','reversed'))
);

-- ---------------------------------------------------------------------------
-- zk402_audit_events — append-only domain audit trail. Extends the
-- node's existing request_log (migration 0007) with ZK402-domain events
-- the generic HTTP log does not capture: every verification, publisher
-- acceptance, settlement, replay rejection, batch status change,
-- settlement-address change, and admin action. `event_json` carries the
-- structured detail; `entity_type` + `entity_id` locate the subject.
-- ---------------------------------------------------------------------------
CREATE TABLE zk402_audit_events (
    id          BIGSERIAL   PRIMARY KEY,
    actor       TEXT        NOT NULL,
    entity_type TEXT        NOT NULL,
    entity_id   TEXT        NOT NULL,
    event_type  TEXT        NOT NULL,
    event_json  JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---- Indexes (docs/DATA_MODEL.md "Required Indexes") ----------------------
-- Uniqueness backstops for replay protection and one-receipt/one-batch
-- invariants:
CREATE UNIQUE INDEX zk402_payment_intents_voucher_id_uq ON zk402_payment_intents (voucher_id);
CREATE UNIQUE INDEX zk402_payment_intents_nonce_uq      ON zk402_payment_intents (nonce);
CREATE UNIQUE INDEX zk402_receipts_payment_intent_id_uq ON zk402_receipts (payment_intent_id);
CREATE UNIQUE INDEX zk402_batch_items_intent_active_uq  ON zk402_batch_items (payment_intent_id);

-- Hot-path lookup indexes:
--   * queue_idx — partial index over just the `queued` intents the batch
--     worker selects, so the queue scan is O(pending) not O(total).
CREATE INDEX zk402_payment_intents_queue_idx
    ON zk402_payment_intents (merchant_id, network, created_at)
    WHERE status = 'queued';
CREATE INDEX zk402_payment_intents_authorization_idx
    ON zk402_payment_intents (authorization_id, created_at);
CREATE INDEX zk402_batches_status_idx
    ON zk402_batches (status, created_at);
CREATE INDEX zk402_merchant_settlements_merchant_created_idx
    ON zk402_merchant_settlements (merchant_id, created_at);
CREATE INDEX zk402_audit_events_entity_idx
    ON zk402_audit_events (entity_type, entity_id, created_at);
