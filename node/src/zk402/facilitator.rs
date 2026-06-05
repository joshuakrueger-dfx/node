//! ZK402 facilitator core — `verify` and `settle` (Step 3).
//!
//! These are the DB-backed, transport-agnostic engines behind
//! `POST /v2/x402/verify` and `POST /v2/x402/settle`
//! (`docs/API_SPEC.md`). The HTTP layer in `routes.rs` is a thin shell
//! over them; the tests exercise the engines directly against a real
//! Postgres schema.
//!
//! Non-custodial + idempotent by construction:
//! * the payment intent is persisted BEFORE publisher acceptance, so a
//!   crash mid-settle leaves a recoverable `verified`/`received` row, not
//!   a granted-but-unrecorded payment;
//! * a replayed voucher returns the SAME receipt (idempotency), while a
//!   voucher id reused with ANY changed signed field is `replay_detected`
//!   — proving merchant/amount/fee are immutable after the buyer's
//!   signature;
//! * `nonce`/`voucher_id` uniqueness is enforced at the database.

use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use sqlx::PgPool;

use super::canonical::canonical_voucher_message;
use super::error::Zk402Error;
use super::payload::ParsedPayment;
use super::receipt::{ReceiptBody, ReceiptSigner};
use super::signature::verify_voucher_signature;
use super::store;
use super::types::{MerchantStatus, NewPaymentIntent, PaymentIntentStatus};

/// Pluggable zkCoins publisher-acceptance hook. Today's mock /
/// `verified_only` paths stand in for the (currently unimplemented)
/// zkCoins pending-spend reservation; Step 8 swaps in the real send/
/// commit path behind the same interface.
pub trait PublisherAcceptance: Send + Sync {
    /// Reserve/accept a merchant-directed signed intent, returning the
    /// `publisher_acceptance_id`, or a structured failure.
    fn accept(&self, payload: &ParsedPayment) -> Result<String, Zk402Error>;
}

/// Default mock: accepts everything (testnet), echoing a deterministic
/// acceptance id derived from the voucher.
pub struct MockPublisherAccept;

impl PublisherAcceptance for MockPublisherAccept {
    fn accept(&self, payload: &ParsedPayment) -> Result<String, Zk402Error> {
        Ok(format!("pubacc_{}", payload.voucher_id))
    }
}

/// A mock that always fails publisher acceptance — for the
/// `publisher_acceptance_failed` settle path test.
pub struct FailingPublisherAccept;

impl PublisherAcceptance for FailingPublisherAccept {
    fn accept(&self, _payload: &ParsedPayment) -> Result<String, Zk402Error> {
        Err(Zk402Error::PublisherAcceptanceFailed)
    }
}

/// Result of a successful `verify`.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyOutcome {
    pub payer: String,
    pub intent_id: String,
    pub authorization_id: Option<String>,
    pub voucher_id: String,
    pub request_hash: String,
}

/// Result of a successful `settle`.
#[derive(Debug, Clone, PartialEq)]
pub struct SettleOutcome {
    pub payer: String,
    pub receipt_id: String,
    pub status: String,
    pub settlement_state: String,
    pub access_threshold: String,
    pub voucher_id: String,
    pub network: String,
    pub amount_sats: i64,
    /// The signed receipt envelope (also persisted in `zk402_receipts`).
    pub receipt_json: serde_json::Value,
    pub kid: String,
    /// True when this was an idempotent replay of an already-settled voucher.
    pub idempotent_replay: bool,
}

fn to_ts(unix: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(unix, 0).single().unwrap_or_else(Utc::now)
}

/// RFC-3339 UTC `...Z` rendering for receipt timestamps.
fn rfc3339(unix: i64) -> String {
    to_ts(unix).format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// The non-DB half of `verify`: structure, temporal window, and the
/// buyer's Schnorr signature over the canonical message.
fn verify_payload_crypto(payload: &ParsedPayment, now: i64) -> Result<(), Zk402Error> {
    payload.validate(now)?;
    verify_voucher_signature(&payload.voucher_fields(), &payload.signature)
}

/// `verify`: syntactically + cryptographically acceptable, and the
/// merchant resolves and is enabled. Does NOT settle or persist.
pub async fn verify(
    pool: &PgPool,
    payload: &ParsedPayment,
    now: i64,
) -> Result<VerifyOutcome, Zk402Error> {
    verify_payload_crypto(payload, now)?;

    let merchant = store::load_merchant(pool, &payload.merchant)
        .await
        .map_err(|_| Zk402Error::InvalidPayload)?
        .ok_or(Zk402Error::MerchantNotFound)?;
    if merchant.status != MerchantStatus::Active {
        return Err(Zk402Error::MerchantDisabled);
    }

    Ok(VerifyOutcome {
        payer: payload.payer.clone(),
        intent_id: payload.intent_id.clone(),
        authorization_id: payload.authorization_id.clone(),
        voucher_id: payload.voucher_id.clone(),
        request_hash: payload.request_hash.clone(),
    })
}

/// True when the stored intent's signed fields differ from the incoming
/// payload — i.e. the voucher id was reused with a tampered body.
fn signed_fields_differ(stored: &super::types::PaymentIntent, p: &ParsedPayment) -> bool {
    stored.merchant_id != p.merchant
        || stored.amount_sats != p.amount_sats
        || stored.fee_amount_sats != p.fee_amount_sats
        || stored.resource_hash != p.resource_hash
        || stored.request_hash != p.request_hash
        || stored.nonce != p.nonce
        || stored.signature != p.signature
}

/// `settle`: verify, persist the intent, run publisher acceptance, and
/// issue a signed receipt. Idempotent on `voucher_id`.
pub async fn settle(
    pool: &PgPool,
    signer: &ReceiptSigner,
    publisher: &Arc<dyn PublisherAcceptance>,
    payload: &ParsedPayment,
    now: i64,
) -> Result<SettleOutcome, Zk402Error> {
    // Full verify gate first (signature, window, merchant).
    verify(pool, payload, now).await?;

    // Idempotency: an already-settled voucher returns its existing
    // receipt; a reused voucher id with a changed signed field is a replay.
    if let Some(existing) = store::load_payment_intent_by_voucher(pool, &payload.voucher_id)
        .await
        .map_err(|_| Zk402Error::InvalidPayload)?
    {
        if signed_fields_differ(&existing, payload) {
            return Err(Zk402Error::ReplayDetected);
        }
        let receipt = store::load_receipt_for_intent(pool, &existing.id)
            .await
            .map_err(|_| Zk402Error::InvalidPayload)?
            .ok_or(Zk402Error::SettlementQueueUnavailable)?;
        return Ok(SettleOutcome {
            payer: existing.payer,
            receipt_id: receipt.id,
            status: receipt.status,
            settlement_state: existing.status.as_str().to_owned(),
            access_threshold: existing.access_threshold.as_str().to_owned(),
            voucher_id: existing.voucher_id,
            network: existing.network,
            amount_sats: existing.amount_sats,
            receipt_json: receipt.receipt_json,
            kid: signer.kid.clone(),
            idempotent_replay: true,
        });
    }

    // Persist the intent BEFORE authorizing (crash-safe, non-custodial).
    // A nonce/voucher unique violation here is a concurrent replay.
    let access_threshold = payload
        .access_threshold
        .parse::<super::types::AccessThreshold>()
        .map_err(|_| Zk402Error::InvalidPayload)?;
    let new_intent = NewPaymentIntent {
        id: payload.intent_id.clone(),
        voucher_id: payload.voucher_id.clone(),
        authorization_id: payload.authorization_id.clone(),
        payer: payload.payer.clone(),
        merchant_id: payload.merchant.clone(),
        network: payload.network.clone(),
        asset: payload.asset.clone(),
        amount_sats: payload.amount_sats,
        fee_amount_sats: payload.fee_amount_sats,
        resource_hash: payload.resource_hash.clone(),
        request_hash: payload.request_hash.clone(),
        nonce: payload.nonce.clone(),
        valid_after: to_ts(payload.valid_after),
        valid_before: to_ts(payload.valid_before),
        canonical_message: String::from_utf8(canonical_voucher_message(&payload.voucher_fields()))
            .unwrap_or_default(),
        signature_scheme: payload.signature_scheme.clone(),
        signature: payload.signature.clone(),
        status: PaymentIntentStatus::Verified,
        access_threshold,
    };
    match store::insert_payment_intent(pool, &new_intent).await {
        Ok(true) => {}
        Ok(false) => return Err(Zk402Error::ReplayDetected), // id already present
        Err(sqlx::Error::Database(db)) if db.constraint().is_some() => {
            // voucher_id / nonce unique violation == concurrent replay.
            return Err(Zk402Error::ReplayDetected);
        }
        Err(_) => return Err(Zk402Error::SettlementQueueUnavailable),
    }

    // Publisher acceptance (mocked today). On failure, record the
    // terminal reason on the intent and surface the structured error.
    let publisher_acceptance_id = match publisher.accept(payload) {
        Ok(id) => id,
        Err(e) => {
            let _ = store::fail_payment_intent(
                pool,
                &payload.intent_id,
                PaymentIntentStatus::FailedRecoverable,
                e.code(),
                "publisher acceptance failed",
            )
            .await;
            return Err(e);
        }
    };

    // Advance to publisher_accepted, then queued for batch settlement.
    let now_dt = to_ts(now);
    let _ = store::update_payment_intent_status(
        pool,
        &payload.intent_id,
        PaymentIntentStatus::PublisherAccepted,
        now_dt,
    )
    .await;
    let _ = store::update_payment_intent_status(
        pool,
        &payload.intent_id,
        PaymentIntentStatus::Queued,
        now_dt,
    )
    .await;
    let _ = publisher_acceptance_id; // persisted with the intent in Step 8

    // Issue + persist the signed receipt. status = publisher_accepted
    // (the access-granting state), settlementState = queued (as of issuance).
    let receipt_id = format!("zkr_{}", payload.voucher_id.trim_start_matches("zkv_"));
    let body = ReceiptBody {
        receipt_id: receipt_id.clone(),
        network: payload.network.clone(),
        mode: payload.mode.clone(),
        status: "publisher_accepted".to_owned(),
        settlement_state: "queued".to_owned(),
        access_threshold: payload.access_threshold.clone(),
        payer: payload.payer.clone(),
        merchant: payload.merchant.clone(),
        amount_sats: payload.amount_sats,
        fee_amount_sats: payload.fee_amount_sats,
        resource_hash: payload.resource_hash.clone(),
        request_hash: payload.request_hash.clone(),
        voucher_id: payload.voucher_id.clone(),
        intent_id: payload.intent_id.clone(),
        authorization_id: payload.authorization_id.clone(),
        created_at: rfc3339(now),
        expires_at: rfc3339(payload.valid_before),
    };
    let receipt_json = signer.signed_receipt_json(&body);
    store::insert_receipt(
        pool,
        &receipt_id,
        &payload.intent_id,
        "publisher_accepted",
        &receipt_json,
        signer.sign(&body).as_str(),
    )
    .await
    .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;

    Ok(SettleOutcome {
        payer: payload.payer.clone(),
        receipt_id,
        status: "publisher_accepted".to_owned(),
        settlement_state: "queued".to_owned(),
        access_threshold: payload.access_threshold.clone(),
        voucher_id: payload.voucher_id.clone(),
        network: payload.network.clone(),
        amount_sats: payload.amount_sats,
        receipt_json,
        kid: signer.kid.clone(),
        idempotent_replay: false,
    })
}
