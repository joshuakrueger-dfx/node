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

use axum::{
    extract::{Path, State},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;

use super::authorization::{self, NewAuthorizationRequest};
use super::error::Zk402Error;
use super::facilitator::{self, PublisherAcceptance};
use super::payload::ParsedPayment;
use super::receipt::ReceiptSigner;
use super::types::Authorization;

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
        .route(
            "/api/zk402/authorizations",
            post(create_authorization_handler),
        )
        .route(
            "/api/zk402/authorizations/:id",
            axum::routing::get(get_authorization_handler),
        )
        .route(
            "/api/zk402/authorizations/:id/revoke",
            post(revoke_authorization_handler),
        )
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

// ---- authorization session endpoints (Step 4) -------------------------------

fn auth_error_json(e: Zk402Error) -> Json<Value> {
    Json(json!({ "error": e.code(), "message": human_message(e) }))
}

fn auth_response_json(a: &Authorization) -> Json<Value> {
    let remaining = a
        .spend_limit_total_sats
        .unwrap_or(a.authorized_amount_sats)
        .min(a.authorized_amount_sats)
        - a.accepted_amount_sats;
    Json(json!({
        "authorizationId": a.id,
        "status": a.status.as_str(),
        "remainingAuthorizedAmount": remaining.max(0).to_string(),
        "acceptedAmount": a.accepted_amount_sats.to_string(),
        "expiresAt": a.valid_before.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    }))
}

fn parse_rfc3339(v: &Value, key: &str) -> Result<DateTime<Utc>, Zk402Error> {
    v.get(key)
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
        .ok_or(Zk402Error::InvalidPayload)
}

fn parse_amount_str(v: &Value, key: &str) -> Result<Option<i64>, Zk402Error> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s
            .parse::<i64>()
            .map(Some)
            .map_err(|_| Zk402Error::InvalidPayload),
        Some(_) => Err(Zk402Error::InvalidPayload),
    }
}

/// `POST /api/zk402/authorizations` — register a buyer-signed bounded
/// spend policy. Moves no funds.
async fn create_authorization_handler(
    State(s): State<Zk402State>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let parse = || -> Result<NewAuthorizationRequest, Zk402Error> {
        let allowed_merchants = match req.get("allowedMerchants") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) => a
                .iter()
                .map(|m| {
                    m.as_str()
                        .map(str::to_owned)
                        .ok_or(Zk402Error::InvalidPayload)
                })
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => return Err(Zk402Error::InvalidPayload),
        };
        // `spendLimitTotal` doubles as the authorized ceiling when no
        // separate field is given (the API_SPEC request carries only the
        // spend limits).
        let total = parse_amount_str(&req, "spendLimitTotal")?.ok_or(Zk402Error::InvalidPayload)?;
        Ok(NewAuthorizationRequest {
            payer: req
                .get("payer")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(Zk402Error::InvalidPayload)?,
            network: req
                .get("network")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(Zk402Error::InvalidPayload)?,
            authorized_amount_sats: total,
            valid_after: Utc::now(),
            valid_before: parse_rfc3339(&req, "expiresAt")?,
            spend_limit_per_request_sats: parse_amount_str(&req, "spendLimitPerRequest")?,
            spend_limit_total_sats: Some(total),
            allowed_merchants,
            facilitator_origin: req
                .get("facilitator")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            session_public_key: req
                .get("sessionPublicKey")
                .and_then(Value::as_str)
                .map(str::to_owned),
            signature: req
                .get("signature")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        })
    };
    let parsed = match parse() {
        Ok(p) => p,
        Err(e) => return auth_error_json(e),
    };
    let id = format!("zkauth_{}", uuid::Uuid::new_v4().simple());
    match authorization::create_authorization(&s.pool, &id, &parsed).await {
        Ok(a) => auth_response_json(&a),
        Err(e) => auth_error_json(e),
    }
}

/// `GET /api/zk402/authorizations/:id` — session state.
async fn get_authorization_handler(
    State(s): State<Zk402State>,
    Path(id): Path<String>,
) -> Json<Value> {
    match super::store::load_authorization(&s.pool, &id).await {
        Ok(Some(a)) => auth_response_json(&a),
        Ok(None) => auth_error_json(Zk402Error::AuthorizationNotFound),
        Err(_) => auth_error_json(Zk402Error::SettlementQueueUnavailable),
    }
}

/// `POST /api/zk402/authorizations/:id/revoke` — revoke for future
/// vouchers (idempotent).
async fn revoke_authorization_handler(
    State(s): State<Zk402State>,
    Path(id): Path<String>,
) -> Json<Value> {
    match authorization::revoke_authorization(&s.pool, &id).await {
        Ok(a) => auth_response_json(&a),
        Err(e) => auth_error_json(e),
    }
}
