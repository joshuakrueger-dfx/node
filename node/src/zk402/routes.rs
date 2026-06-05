//! HTTP shell for the ZK402 facilitator (Step 3): the x402 v2 endpoints
//! `POST /v2/x402/verify` and `POST /v2/x402/settle`, as a self-contained
//! sub-router merged into the main app router (`router::create_router`).
//!
//! Response shapes follow `docs/API_SPEC.md` and the
//! `payment-response-{success,failure}.zk402.json` fixtures: verify
//! answers `{isValid, ...}`, settle answers `{success, ...}` — payment
//! failures are protocol results, not HTTP errors, so both endpoints
//! return 200 with a structured body.

use std::sync::Arc;

use axum::{extract::State, routing::post, Json, Router};
use serde_json::{json, Value};
use sqlx::PgPool;

use super::error::Zk402Error;
use super::facilitator::{self, PublisherAcceptance};
use super::payload::ParsedPayment;
use super::receipt::ReceiptSigner;

/// State for the ZK402 sub-router. Deliberately smaller than the app's
/// `AppState`: the facilitator needs the pool, the receipt signer, and
/// the (pluggable, Step-8) publisher-acceptance hook — nothing else.
#[derive(Clone)]
pub struct Zk402State {
    pub pool: Arc<PgPool>,
    pub signer: Arc<ReceiptSigner>,
    pub publisher: Arc<dyn PublisherAcceptance>,
}

/// Build the finalized ZK402 router (state applied), ready to be
/// `merge`d into the main router.
pub fn create_zk402_router(state: Zk402State) -> Router {
    Router::new()
        .route("/v2/x402/verify", post(verify_handler))
        .route("/v2/x402/settle", post(settle_handler))
        .with_state(state)
}

/// Pull the `paymentPayload` object out of the x402 v2 request envelope
/// (`{ x402Version, paymentPayload, paymentRequirements }`).
fn parse_envelope(req: &Value) -> Result<ParsedPayment, Zk402Error> {
    let payment_payload = req
        .get("paymentPayload")
        .ok_or(Zk402Error::InvalidPayload)?;
    ParsedPayment::from_decoded(payment_payload)
}

fn human_message(e: Zk402Error) -> &'static str {
    match e {
        Zk402Error::InvalidSignature => "Payment signature does not verify",
        Zk402Error::ReplayDetected => "Voucher or nonce was already used with different terms",
        Zk402Error::PublisherAcceptanceFailed => {
            "zkCoins publisher could not accept the signed intent"
        }
        _ => "Payment payload was rejected",
    }
}

async fn verify_handler(State(s): State<Zk402State>, Json(req): Json<Value>) -> Json<Value> {
    let now = chrono::Utc::now().timestamp();
    let payload = match parse_envelope(&req) {
        Ok(p) => p,
        Err(e) => {
            return Json(json!({
                "isValid": false,
                "payer": "",
                "invalidReason": e.code(),
                "invalidMessage": human_message(e),
            }))
        }
    };
    match facilitator::verify(&s.pool, &payload, now).await {
        Ok(o) => Json(json!({
            "isValid": true,
            "payer": o.payer,
            "extra": { "zk402": {
                "intentId": o.intent_id,
                "authorizationId": o.authorization_id,
                "voucherId": o.voucher_id,
                "requestHash": o.request_hash,
            }},
        })),
        Err(e) => Json(json!({
            "isValid": false,
            "payer": payload.payer,
            "invalidReason": e.code(),
            "invalidMessage": human_message(e),
        })),
    }
}

async fn settle_handler(State(s): State<Zk402State>, Json(req): Json<Value>) -> Json<Value> {
    let now = chrono::Utc::now().timestamp();
    let payload = match parse_envelope(&req) {
        Ok(p) => p,
        Err(e) => {
            return Json(json!({
                "success": false,
                "errorReason": e.code(),
                "payer": "",
                "transaction": "",
                "network": "",
                "amount": "",
                "extensions": { "zk402": { "invalidMessage": human_message(e) } },
            }))
        }
    };
    match facilitator::settle(&s.pool, &s.signer, &s.publisher, &payload, now).await {
        Ok(o) => Json(json!({
            "success": true,
            "payer": o.payer,
            "transaction": o.receipt_id,
            "network": o.network,
            "amount": o.amount_sats.to_string(),
            "extensions": { "zk402": {
                "receiptId": o.receipt_id,
                "status": o.status,
                "settlementState": o.settlement_state,
                "accessThreshold": o.access_threshold,
                "voucherId": o.voucher_id,
                "facilitatorSignature": o.receipt_json["signature"],
                "kid": o.kid,
            }},
        })),
        Err(e) => Json(json!({
            "success": false,
            "errorReason": e.code(),
            "payer": payload.payer,
            "transaction": "",
            "network": payload.network,
            "amount": payload.amount_sats.to_string(),
            "extensions": { "zk402": { "invalidMessage": human_message(e) } },
        })),
    }
}
