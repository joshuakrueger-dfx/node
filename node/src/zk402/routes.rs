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
        // Dashboard & operations (Step 9). NOTE: deliberately NO
        // withdraw/payout route exists — the operator custodies nothing.
        .route(
            "/api/zk402/receipt-keys",
            axum::routing::get(receipt_keys_handler),
        )
        .route("/api/zk402/merchants", post(onboard_handler))
        .route(
            "/api/zk402/receipts/:id",
            axum::routing::get(get_receipt_handler),
        )
        .route(
            "/api/zk402/dashboard/summary",
            axum::routing::get(dashboard_summary_handler),
        )
        .route(
            "/api/zk402/dashboard/batches",
            axum::routing::get(dashboard_batches_handler),
        )
        .route(
            "/api/zk402/dashboard/payments",
            axum::routing::get(dashboard_payments_handler),
        )
        .route(
            "/api/zk402/dashboard/channels",
            axum::routing::get(dashboard_channels_handler),
        )
        .route(
            "/api/zk402/dashboard/usage",
            axum::routing::get(dashboard_usage_handler),
        )
        // ZK402-Stream (Flow-D) metering — the LLM-token billing hot path.
        .route("/v2/x402/stream/meter", post(stream_meter_handler))
        // Agent Economy Layer 1: x402 v2 capability advert + Bazaar
        // discovery (read-only, public — discovery is meant to be
        // crawled) and merchant-scoped service registration.
        .route("/v2/x402/supported", axum::routing::get(supported_handler))
        .route(
            "/v2/x402/discovery/resources",
            axum::routing::get(discovery_resources_handler),
        )
        .route(
            "/v2/x402/discovery/search",
            axum::routing::get(discovery_search_handler),
        )
        .route("/api/zk402/services", post(register_service_handler))
        .route(
            "/api/zk402/services/:id/reputation",
            axum::routing::get(service_reputation_handler),
        )
        .route(
            "/api/zk402/dashboard/services",
            axum::routing::get(dashboard_services_handler),
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

// ---- dashboard & operations (Step 9) ----------------------------------------

use axum::http::HeaderMap;

/// Extract the bearer API key from `Authorization: Bearer` or `X-API-Key`.
fn api_key_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(v.to_owned());
    }
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
}

/// Resolve the authenticated merchant, or return a 401 JSON body.
async fn authed_merchant(
    s: &Zk402State,
    headers: &HeaderMap,
) -> Result<String, (u16, Json<Value>)> {
    let key = api_key_from_headers(headers).ok_or((
        401u16,
        Json(json!({ "error": "unauthorized", "message": "missing API key" })),
    ))?;
    match super::dashboard::authenticate(&s.pool, &key).await {
        Ok(Some(m)) => Ok(m),
        Ok(None) => Err((
            401,
            Json(json!({ "error": "unauthorized", "message": "invalid or revoked API key" })),
        )),
        Err(_) => Err((503, Json(json!({ "error": "unavailable" })))),
    }
}

async fn onboard_handler(
    State(s): State<Zk402State>,
    Json(req): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let id = req.get("merchantId").and_then(Value::as_str);
    let name = req.get("displayName").and_then(Value::as_str);
    let addr = req.get("settlementAddress").and_then(Value::as_str);
    let (id, name, addr) = match (id, name, addr) {
        (Some(i), Some(n), Some(a)) => (i, n, a),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_payload" })),
            )
        }
    };
    // Issue a fresh secret key (shown once).
    let key = format!("zk402_sk_{}", random_token());
    match super::dashboard::onboard_merchant(&s.pool, id, name, addr, &key).await {
        Ok(o) => (
            StatusCode::CREATED,
            Json(json!({ "merchantId": o.merchant_id, "apiKey": o.api_key })),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.code() }))),
    }
}

/// 24-byte base64url random token (API-key suffix), from the OS CSPRNG
/// via ring.
pub fn random_token() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 24];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("system RNG");
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b)
}

async fn dashboard_summary_handler(
    State(s): State<Zk402State>,
    headers: HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let merchant = match authed_merchant(&s, &headers).await {
        Ok(m) => m,
        Err((code, body)) => return (StatusCode::from_u16(code).unwrap(), body),
    };
    let summary = super::dashboard::settlement_summary(&s.pool, &merchant)
        .await
        .unwrap_or_default();
    let fees = super::dashboard::fee_analytics(&s.pool, &merchant)
        .await
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "merchantId": merchant,
            "settlement": {
                "acceptedSats": summary.accepted_sats.to_string(),
                "publishedSats": summary.published_sats.to_string(),
                "confirmedSats": summary.confirmed_sats.to_string(),
                "finalSats": summary.final_sats.to_string(),
                "feeSats": summary.fee_sats.to_string(),
                "reversalSats": summary.reversal_sats.to_string(),
            },
            "analytics": {
                "intentCount": fees.intent_count,
                "grossSats": fees.gross_sats.to_string(),
                "feeSats": fees.fee_sats.to_string(),
                "netSats": fees.net_sats.to_string(),
            },
        })),
    )
}

async fn dashboard_batches_handler(
    State(s): State<Zk402State>,
    headers: HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let merchant = match authed_merchant(&s, &headers).await {
        Ok(m) => m,
        Err((code, body)) => return (StatusCode::from_u16(code).unwrap(), body),
    };
    let batches = super::dashboard::list_batches(&s.pool, &merchant)
        .await
        .unwrap_or_default();
    let items: Vec<Value> = batches
        .iter()
        .map(|b| {
            json!({
                "id": b.id,
                "status": b.status.as_str(),
                "grossSats": b.gross_amount_sats.to_string(),
                "feeSats": b.fee_amount_sats.to_string(),
                "netSats": b.net_amount_sats.to_string(),
                "intentCount": b.intent_count,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "merchantId": merchant, "batches": items })),
    )
}

/// `GET /api/zk402/receipt-keys` — the active receipt-signing key
/// registry (Step 10). Third parties resolve a receipt's `kid` here to
/// verify its Ed25519 signature offline.
async fn receipt_keys_handler(State(s): State<Zk402State>) -> Json<Value> {
    let registry = super::hardening::KeyRegistry::new(&s.signer.kid, s.signer.public_key_bytes());
    Json(registry.to_json())
}

// ---- streaming meter + dashboard reads (test environment / frontend) --------

use axum::extract::Query;

/// Accept a JSON integer that may arrive as a number or a numeric string.
fn as_i64(v: &Value, key: &str) -> Result<i64, Zk402Error> {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_i64().ok_or(Zk402Error::InvalidPayload),
        Some(Value::String(s)) => s.parse::<i64>().map_err(|_| Zk402Error::InvalidPayload),
        _ => Err(Zk402Error::InvalidPayload),
    }
}

fn as_str_field(v: &Value, key: &str) -> Result<String, Zk402Error> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Zk402Error::InvalidPayload)
}

/// `POST /v2/x402/stream/meter` — meter actual usage under a signed
/// ZK402-STREAM-V1 voucher. Body:
/// `{ streamVoucher: {...}, signature, usage: [{unit,quantity,unitPriceMicrosats,model}] }`.
async fn stream_meter_handler(State(s): State<Zk402State>, Json(req): Json<Value>) -> Json<Value> {
    let now = chrono::Utc::now().timestamp();
    let build = || -> Result<(super::canonical::StreamVoucherFields, String, Vec<super::streaming::Usage>), Zk402Error> {
        let v = req.get("streamVoucher").ok_or(Zk402Error::InvalidPayload)?;
        let fields = super::canonical::StreamVoucherFields {
            network: as_str_field(v, "network")?,
            channel_id: as_str_field(v, "channelId")?,
            voucher_seq: as_i64(v, "voucherSeq")?,
            payer: as_str_field(v, "payer")?,
            merchant: as_str_field(v, "merchant")?,
            max_amount_sats: as_i64(v, "maxAmount")?,
            cumulative_authorized_sats: as_i64(v, "cumulativeAuthorized")?,
            resource_hash: as_str_field(v, "resourceHash")?,
            request_hash: as_str_field(v, "requestHash")?,
            valid_after: as_i64(v, "validAfter")?,
            valid_before: as_i64(v, "validBefore")?,
            facilitator: as_str_field(v, "facilitator")?,
            access_threshold: as_str_field(v, "accessThreshold")?,
        };
        let signature = as_str_field(&req, "signature")?;
        let usage = req
            .get("usage")
            .and_then(Value::as_array)
            .ok_or(Zk402Error::InvalidPayload)?
            .iter()
            .map(|u| {
                Ok(super::streaming::Usage {
                    unit: as_str_field(u, "unit")?,
                    quantity: as_i64(u, "quantity")?,
                    unit_price_microsats: as_i64(u, "unitPriceMicrosats")?,
                    model: u.get("model").and_then(Value::as_str).map(str::to_owned),
                })
            })
            .collect::<Result<Vec<_>, Zk402Error>>()?;
        Ok((fields, signature, usage))
    };
    let (fields, signature, usage) = match build() {
        Ok(x) => x,
        Err(e) => return Json(json!({ "success": false, "errorReason": e.code() })),
    };
    match super::streaming::meter(&s.pool, &fields, &signature, &usage, now).await {
        Ok(o) => Json(json!({
            "success": true,
            "channelId": fields.channel_id,
            "actualCostSats": o.actual_cost_sats.to_string(),
            "unspentSats": o.unspent_sats.to_string(),
            "meteredTotalSats": o.metered_total_sats.to_string(),
            "cumulativeAuthorizedSats": o.cumulative_authorized_sats.to_string(),
        })),
        Err(e) => Json(json!({
            "success": false,
            "errorReason": e.code(),
            "message": human_message(e),
        })),
    }
}

async fn dashboard_payments_handler(
    State(s): State<Zk402State>,
    headers: HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let merchant = match authed_merchant(&s, &headers).await {
        Ok(m) => m,
        Err((code, body)) => return (StatusCode::from_u16(code).unwrap(), body),
    };
    let intents = super::store::list_payment_intents_for_merchant(&s.pool, &merchant, 100)
        .await
        .unwrap_or_default();
    let items: Vec<Value> = intents
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "voucherId": p.voucher_id,
                "amountSats": p.amount_sats.to_string(),
                "feeSats": p.fee_amount_sats.to_string(),
                "status": p.status.as_str(),
                "accessThreshold": p.access_threshold.as_str(),
                "createdAt": p.created_at.to_rfc3339(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "merchantId": merchant, "payments": items })),
    )
}

async fn dashboard_channels_handler(
    State(s): State<Zk402State>,
    headers: HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let merchant = match authed_merchant(&s, &headers).await {
        Ok(m) => m,
        Err((code, body)) => return (StatusCode::from_u16(code).unwrap(), body),
    };
    let channels = super::store::list_channels_for_merchant(&s.pool, &merchant, 100)
        .await
        .unwrap_or_default();
    let items: Vec<Value> = channels
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "payer": c.payer,
                "status": c.status,
                "meteredSats": c.metered_amount_sats.to_string(),
                "cumulativeAuthorizedSats": c.authorized_cumulative_sats.to_string(),
                "capSats": c.authorized_amount_sats.to_string(),
                "validBefore": c.valid_before.to_rfc3339(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "merchantId": merchant, "channels": items })),
    )
}

#[derive(serde::Deserialize)]
struct ChannelQuery {
    channel: String,
}

async fn dashboard_usage_handler(
    State(s): State<Zk402State>,
    headers: HeaderMap,
    Query(q): Query<ChannelQuery>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let merchant = match authed_merchant(&s, &headers).await {
        Ok(m) => m,
        Err((code, body)) => return (StatusCode::from_u16(code).unwrap(), body),
    };
    let events = super::store::list_usage_events(&s.pool, &q.channel, 100)
        .await
        .unwrap_or_default();
    let items: Vec<Value> = events
        .iter()
        .map(|e| {
            json!({
                "voucherSeq": e.voucher_seq,
                "unit": e.unit,
                "quantity": e.quantity,
                "costSats": e.cost_sats.to_string(),
                "model": e.model,
                "createdAt": e.created_at.to_rfc3339(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "merchantId": merchant, "channel": q.channel, "usage": items })),
    )
}

/// `GET /api/zk402/receipts/:id` — the full signed receipt (public,
/// offline-verifiable against `/api/zk402/receipt-keys`).
async fn get_receipt_handler(
    State(s): State<Zk402State>,
    Path(id): Path<String>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    match super::store::load_receipt_json(&s.pool, &id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "unavailable" })),
        ),
    }
}

// ---- Agent Economy Layer 1: discovery + service registration ----------------

/// `GET /v2/x402/supported` — advertise the scheme(s) + (testnet)
/// networks this facilitator settles, x402 `/supported` shape.
async fn supported_handler(State(_s): State<Zk402State>) -> Json<Value> {
    let kinds: Vec<Value> = super::payload::SUPPORTED_NETWORKS
        .iter()
        .map(|n| json!({ "scheme": super::payload::SCHEME, "network": n }))
        .collect();
    Json(json!({ "x402Version": 2, "kinds": kinds }))
}

/// Build discovery items for a batch of services, each enriched with its
/// derived reputation (one aggregate query, no N+1). Returns
/// `(item_json, score)` so callers can rank. Services with no payment
/// history get the neutral default reputation.
async fn items_with_reputation(
    s: &Zk402State,
    services: &[super::types::Service],
) -> Vec<(Value, i64)> {
    let hashes: Vec<String> = services
        .iter()
        .map(|svc| svc.resource_hash.clone())
        .collect();
    let signals = super::reputation::signals_for_resources(&s.pool, &hashes)
        .await
        .unwrap_or_default();
    let now = chrono::Utc::now();
    services
        .iter()
        .map(|svc| {
            let rep = super::reputation::from_signals(
                signals.get(&svc.resource_hash).cloned().unwrap_or_default(),
            );
            let item = super::services::discovery_item_with_reputation(
                svc,
                Some(super::reputation::reputation_json(&rep, now)),
            );
            (item, rep.score)
        })
        .collect()
}

#[derive(serde::Deserialize)]
struct ResourcesQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

/// `GET /v2/x402/discovery/resources` — paginated catalog of active
/// services in the x402 Bazaar wire format, each carrying its derived
/// reputation in `metadata.reputation`.
async fn discovery_resources_handler(
    State(s): State<Zk402State>,
    Query(q): Query<ResourcesQuery>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let offset = q.offset.unwrap_or(0).max(0);
    match super::store::list_active_services(&s.pool, limit, offset).await {
        Ok((services, total)) => {
            let items: Vec<Value> = items_with_reputation(&s, &services)
                .await
                .into_iter()
                .map(|(item, _)| item)
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "x402Version": 2,
                    "items": items,
                    "pagination": { "limit": limit, "offset": offset, "total": total },
                })),
            )
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "unavailable" })),
        ),
    }
}

#[derive(serde::Deserialize)]
struct SearchQuery {
    query: Option<String>,
    network: Option<String>,
    #[serde(rename = "maxPriceSats")]
    max_price_sats: Option<i64>,
    limit: Option<i64>,
}

/// How many recency-ordered candidates to pull from the store before
/// ranking by reputation. Ranking only the first `limit` rows would let a
/// newer low-score service hide an older high-score one — defeating the
/// "score > N" contract — so we rank over a wider pool, then trim.
const SEARCH_RANK_POOL: i64 = 200;

/// `GET /v2/x402/discovery/search` — text search over the active catalog
/// in the x402 Bazaar search shape, **ranked by reputation** (score
/// descending; recency breaks ties via the store's ordering). This is the
/// "cheapest provider with score > N" lever agents rank on.
async fn discovery_search_handler(
    State(s): State<Zk402State>,
    Query(q): Query<SearchQuery>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let query = q.query.unwrap_or_default();
    let limit = q.limit.unwrap_or(20).clamp(1, 20);
    // Fetch a wide recency pool, rank the whole pool by score, then trim to
    // the requested limit — so reputation ranking is global, not windowed.
    match super::store::search_active_services(
        &s.pool,
        &query,
        q.network.as_deref(),
        q.max_price_sats,
        SEARCH_RANK_POOL,
    )
    .await
    {
        Ok(services) => {
            // `partialResults` is honest: true only if the candidate pool
            // itself was capped (there may be matches we did not rank).
            let pool_capped = services.len() as i64 >= SEARCH_RANK_POOL;
            let mut ranked = items_with_reputation(&s, &services).await;
            // Stable sort by score desc; equal scores keep store order
            // (recency), so the result is deterministic.
            ranked.sort_by_key(|(_, score)| std::cmp::Reverse(*score));
            let trimmed = ranked.len() as i64 > limit;
            let resources: Vec<Value> = ranked
                .into_iter()
                .take(limit as usize)
                .map(|(item, _)| item)
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "x402Version": 2,
                    "resources": resources,
                    "partialResults": pool_capped || trimmed,
                    "searchMethod": "text",
                })),
            )
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "unavailable" })),
        ),
    }
}

/// `GET /api/zk402/services/:id/reputation` — the derived, read-only
/// reputation snapshot for one service (public; recomputable from signed
/// payment history, never a stored score).
async fn service_reputation_handler(
    State(s): State<Zk402State>,
    Path(id): Path<String>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let svc = match super::store::load_service(&s.pool, &id).await {
        Ok(Some(svc)) => svc,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))),
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "unavailable" })),
            )
        }
    };
    match super::reputation::for_resource(&s.pool, &svc.resource_hash).await {
        Ok(rep) => (
            StatusCode::OK,
            Json(json!({
                "serviceId": svc.id,
                "merchantId": svc.merchant_id,
                "capability": svc.capability,
                "reputation": super::reputation::reputation_json(&rep, chrono::Utc::now()),
            })),
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "unavailable" })),
        ),
    }
}

/// `POST /api/zk402/services` — register a service for the authenticated
/// merchant (API key). The merchant id comes from the key, never the
/// body; the resource hash is derived, never trusted.
async fn register_service_handler(
    State(s): State<Zk402State>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let merchant = match authed_merchant(&s, &headers).await {
        Ok(m) => m,
        Err((code, body)) => return (StatusCode::from_u16(code).unwrap(), body),
    };

    let get = |k: &str| req.get(k).and_then(Value::as_str).map(str::to_owned);
    let (capability, display_name, endpoint, network, facilitator) = match (
        get("capability"),
        get("displayName"),
        get("endpoint"),
        get("network"),
        get("facilitator"),
    ) {
        (Some(c), Some(d), Some(e), Some(n), Some(f)) => (c, d, e, n, f),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_payload",
                    "message": "capability, displayName, endpoint, network, facilitator are required" })),
            )
        }
    };

    let price_policy = req.get("pricePolicy").cloned().unwrap_or_else(|| json!({}));
    // Headline price: explicit field, else the policy's amountSats.
    let headline = req
        .get("headlineAmountSats")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .or_else(|| {
            price_policy.get("amountSats").and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
        })
        .unwrap_or(0);

    let access_threshold = match req
        .get("accessThreshold")
        .and_then(Value::as_str)
        .unwrap_or("publisher_accepted")
        .parse::<super::types::AccessThreshold>()
    {
        Ok(a) => a,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_payload", "message": "invalid accessThreshold" })),
            )
        }
    };

    let service_id =
        get("serviceId").unwrap_or_else(|| format!("svc_{}", uuid::Uuid::new_v4().simple()));
    let privacy_level = get("privacyLevel").unwrap_or_else(|| "private".to_owned());

    let input = super::services::NewServiceInput {
        service_id,
        merchant_id: merchant,
        capability,
        display_name,
        description: get("description"),
        endpoint,
        input_schema: get("inputSchema"),
        output_schema: get("outputSchema"),
        network,
        price_policy,
        headline_amount_sats: headline,
        access_threshold,
        facilitator,
        privacy_level,
    };

    match super::services::register_service(&s.pool, input).await {
        Ok(svc) => (
            StatusCode::CREATED,
            Json(json!({
                "serviceId": svc.id,
                "merchantId": svc.merchant_id,
                "resourceHash": svc.resource_hash,
                "resource": super::services::discovery_item(&svc),
            })),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e.code() }))),
    }
}

/// `GET /api/zk402/dashboard/services` — the authenticated merchant's own
/// catalog (any status).
async fn dashboard_services_handler(
    State(s): State<Zk402State>,
    headers: HeaderMap,
) -> (axum::http::StatusCode, Json<Value>) {
    use axum::http::StatusCode;
    let merchant = match authed_merchant(&s, &headers).await {
        Ok(m) => m,
        Err((code, body)) => return (StatusCode::from_u16(code).unwrap(), body),
    };
    match super::store::list_services_for_merchant(&s.pool, &merchant).await {
        Ok(services) => {
            let items: Vec<Value> = services
                .iter()
                .map(super::services::discovery_item)
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "merchantId": merchant, "services": items })),
            )
        }
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "unavailable" })),
        ),
    }
}
