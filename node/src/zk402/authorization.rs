//! Non-custodial authorization sessions (Step 4).
//!
//! An authorization is a buyer-signed, bounded spend policy — never a
//! deposit. Creating one moves no funds (`docs/API_SPEC.md`); it records
//! caps the facilitator may accept vouchers within, and the buyer can
//! revoke it for future vouchers at any time.
//!
//! Enforcement layers, in order, when a voucher carries
//! `authorizationId`:
//!  1. session exists → `authorization_not_found`
//!  2. session revoked/expired-status → `authorization_revoked` / window
//!     check against injected `now` → `expired_payment`
//!  3. payer + network match the session, merchant is in the signed
//!     allow-list, amount ≤ per-request cap → `authorization_limit_exceeded`
//!  4. ATOMIC total-cap reservation (`store::try_reserve_authorization`)
//!     — the only check that must be concurrency-safe, and it is, by a
//!     single conditional UPDATE: 100 parallel vouchers cannot overspend
//!     the signed cap.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use super::error::Zk402Error;
use super::payload::ParsedPayment;
use super::store;
use super::types::{Authorization, AuthorizationStatus, NewAuthorization};

/// Creation request for an authorization session (the POST body,
/// already JSON-parsed). Amount strings follow the wire convention.
#[derive(Debug, Clone)]
pub struct NewAuthorizationRequest {
    pub payer: String,
    pub network: String,
    pub authorized_amount_sats: i64,
    pub valid_after: DateTime<Utc>,
    pub valid_before: DateTime<Utc>,
    pub spend_limit_per_request_sats: Option<i64>,
    pub spend_limit_total_sats: Option<i64>,
    pub allowed_merchants: Vec<String>,
    pub facilitator_origin: String,
    pub session_public_key: Option<String>,
    /// Buyer signature over the policy. Verified structurally for now —
    /// the canonical authorization message has no spec fixture yet; the
    /// cap enforcement below is independent of it.
    pub signature: String,
}

/// Register a session. No funds move; the row IS the policy.
pub async fn create_authorization(
    pool: &PgPool,
    id: &str,
    req: &NewAuthorizationRequest,
) -> Result<Authorization, Zk402Error> {
    if req.authorized_amount_sats <= 0
        || req.signature.is_empty()
        || req.payer.is_empty()
        || req.valid_before <= req.valid_after
    {
        return Err(Zk402Error::InvalidPayload);
    }
    if !super::payload::SUPPORTED_NETWORKS.contains(&req.network.as_str()) {
        return Err(Zk402Error::UnsupportedNetwork);
    }
    let new = NewAuthorization {
        id: id.to_owned(),
        payer: req.payer.clone(),
        network: req.network.clone(),
        asset: "btc-sats".to_owned(),
        authorized_amount_sats: req.authorized_amount_sats,
        status: AuthorizationStatus::Active,
        valid_after: req.valid_after,
        valid_before: req.valid_before,
        spend_limit_per_request_sats: req.spend_limit_per_request_sats,
        spend_limit_total_sats: req.spend_limit_total_sats,
        allowed_merchants: serde_json::json!(req.allowed_merchants),
        facilitator_origin: req.facilitator_origin.clone(),
        session_public_key: req.session_public_key.clone(),
        authorization_signature: req.signature.clone(),
    };
    store::insert_authorization(pool, &new)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    store::load_authorization(pool, id)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?
        .ok_or(Zk402Error::AuthorizationNotFound)
}

/// Revoke a session for future vouchers. Idempotent; already-accepted
/// vouchers remain governed by settlement state.
pub async fn revoke_authorization(pool: &PgPool, id: &str) -> Result<Authorization, Zk402Error> {
    let auth = store::load_authorization(pool, id)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?
        .ok_or(Zk402Error::AuthorizationNotFound)?;
    if auth.status != AuthorizationStatus::Revoked {
        store::update_authorization_status(pool, id, AuthorizationStatus::Revoked)
            .await
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    }
    store::load_authorization(pool, id)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?
        .ok_or(Zk402Error::AuthorizationNotFound)
}

/// True when `merchant` is allowed by the session's signed allow-list
/// (an empty list means "any merchant").
fn merchant_allowed(auth: &Authorization, merchant: &str) -> bool {
    match auth.allowed_merchants.as_array() {
        Some(list) if !list.is_empty() => list.iter().any(|m| m.as_str() == Some(merchant)),
        _ => true,
    }
}

/// Validate a voucher against its session and atomically reserve the
/// amount against the total cap. Called from `facilitator::settle` when
/// `authorizationId` is present.
pub async fn accept_voucher_against_authorization(
    pool: &PgPool,
    payload: &ParsedPayment,
    now: i64,
) -> Result<(), Zk402Error> {
    let auth_id = payload
        .authorization_id
        .as_deref()
        .ok_or(Zk402Error::InvalidPayload)?;
    let auth = store::load_authorization(pool, auth_id)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?
        .ok_or(Zk402Error::AuthorizationNotFound)?;

    match auth.status {
        AuthorizationStatus::Active => {}
        AuthorizationStatus::Revoked | AuthorizationStatus::Revoking => {
            return Err(Zk402Error::AuthorizationRevoked)
        }
        _ => return Err(Zk402Error::AuthorizationNotFound),
    }
    // Session window against the injected clock (deterministic in tests).
    if now < auth.valid_after.timestamp() || now > auth.valid_before.timestamp() {
        return Err(Zk402Error::ExpiredPayment);
    }
    // The voucher must belong to this session's payer/network and an
    // allowed merchant, within the per-request cap.
    if auth.payer != payload.payer || auth.network != payload.network {
        return Err(Zk402Error::InvalidPayload);
    }
    if !merchant_allowed(&auth, &payload.merchant) {
        return Err(Zk402Error::AuthorizationLimitExceeded);
    }
    if let Some(per_request) = auth.spend_limit_per_request_sats {
        if payload.amount_sats > per_request {
            return Err(Zk402Error::AuthorizationLimitExceeded);
        }
    }
    // Atomic total-cap reservation — the concurrency-safe guard.
    let reserved = store::try_reserve_authorization(pool, auth_id, payload.amount_sats)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    if !reserved {
        return Err(Zk402Error::AuthorizationLimitExceeded);
    }
    Ok(())
}
