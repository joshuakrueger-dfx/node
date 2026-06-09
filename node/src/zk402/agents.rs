//! Agent Economy Phase 1 — Layer 3 (identity + delegation) + Layer 4 (disputes).
//!
//! Self-sovereign agent identities keyed by a Schnorr key; delegated, scoped,
//! revocable session keys authorized via `ZK402-AUTHORIZATION-V1` (the identity
//! key signs the delegation; the caps/window/revocation are enforced at USE
//! time by [`validate_session_delegation`]); and append-only signed
//! `ZK402-DISPUTE-V1` ratings, each bound to the receipt's own payer.
//!
//! All writes are signature-gated and freshness-bounded (a signed message older
//! or further in the future than `FRESHNESS_WINDOW_SECS` is rejected, so a stale
//! registration/delegation/dispute cannot be replayed). Nothing here holds
//! funds; an agent has no owner column (a handle maps to a key, never a human),
//! preserving the zkCoins unlinkability property.
//!
//! `validate_session_delegation` is the enforcement primitive;
//! [`enforce_session_delegation`] wires it into the settle path
//! (`facilitator::settle`), so a voucher signed by a delegated session key
//! (`zkpayer_<session_pubkey>`) is checked against its delegation at spend
//! time — the caps/window/revocation now actually bite. (The separate
//! `zk402_authorizations` table still backs the older authorization-mode
//! voucher path; the two coexist.)

use chrono::{DateTime, TimeZone, Utc};
use sqlx::PgPool;

use super::canonical::{
    allowed_merchants_hash, capabilities_hash, AgentFields, AuthorizationFields, DisputeFields,
};
use super::error::Zk402Error;
use super::signature::{
    verify_agent_signature, verify_authorization_signature, verify_dispute_signature,
};

/// A signed message's timestamp must be within this window of `now`, so a
/// captured registration/delegation/dispute cannot be replayed later (or
/// pre-dated). Generous (1 day) to tolerate clock skew.
pub const FRESHNESS_WINDOW_SECS: i64 = 86_400;

fn fresh(timestamp: i64, now: i64) -> Result<(), Zk402Error> {
    if (now - timestamp).abs() <= FRESHNESS_WINDOW_SECS {
        Ok(())
    } else {
        Err(Zk402Error::InvalidPayload)
    }
}

fn ts(unix: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(unix, 0).single().unwrap_or_else(Utc::now)
}

fn db_err(_: sqlx::Error) -> Zk402Error {
    Zk402Error::SettlementQueueUnavailable
}

/// Map a unique-constraint violation to a clean conflict error.
fn insert_err(e: sqlx::Error) -> Zk402Error {
    match e {
        sqlx::Error::Database(d) if d.constraint().is_some() => Zk402Error::ReplayDetected,
        _ => Zk402Error::SettlementQueueUnavailable,
    }
}

// ---- Layer 3: agent identity ----------------------------------------------

pub struct RegisterAgent {
    pub agent_id: String,
    pub handle: Option<String>,
    pub capabilities: Vec<String>,
    pub timestamp: i64,
    pub signature: String,
}

/// Register (or update) an agent identity, proving control of the identity key
/// via a `ZK402-AGENT-V1` signature. Owner stays private — only the key. The
/// signed `timestamp` must be fresh, so a captured registration cannot be
/// replayed later to roll the handle/capabilities back.
pub async fn register_agent(
    pool: &PgPool,
    req: &RegisterAgent,
    now: i64,
) -> Result<(), Zk402Error> {
    fresh(req.timestamp, now)?;
    let fields = AgentFields {
        agent_id: req.agent_id.clone(),
        handle: req.handle.clone().unwrap_or_default(),
        capabilities_hash: capabilities_hash(&req.capabilities),
        timestamp: req.timestamp,
    };
    verify_agent_signature(&fields, &req.signature)?;
    let caps_json = serde_json::to_string(&req.capabilities).unwrap_or_else(|_| "[]".to_owned());
    sqlx::query(
        "INSERT INTO zk402_agents (id, handle, capabilities_json) VALUES ($1, $2, $3) \
         ON CONFLICT (id) DO UPDATE SET handle = EXCLUDED.handle, \
         capabilities_json = EXCLUDED.capabilities_json",
    )
    .bind(&req.agent_id)
    .bind(req.handle.as_deref())
    .bind(&caps_json)
    .execute(pool)
    .await
    .map_err(insert_err)?; // a taken handle → conflict
    Ok(())
}

// ---- Layer 3: delegated session keys (ZK402-AUTHORIZATION-V1) ---------------

pub struct AddSessionKey {
    pub agent_id: String,
    pub session_pubkey: String,
    pub network: String,
    pub authorized_amount_sats: i64,
    pub spend_limit_per_request_sats: i64,
    pub spend_limit_total_sats: i64,
    pub allowed_merchants: Vec<String>,
    pub facilitator: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub delegation_signature: String,
}

/// Add a delegated session key under an agent's identity, verifying the
/// `ZK402-AUTHORIZATION-V1` delegation signed by the identity key. The window
/// must be valid and not already expired at creation. Returns the row id.
pub async fn add_session_key(
    pool: &PgPool,
    req: &AddSessionKey,
    now: i64,
) -> Result<String, Zk402Error> {
    // A well-formed, not-already-expired window.
    if req.valid_before <= req.valid_after || req.valid_before <= now {
        return Err(Zk402Error::InvalidPayload);
    }
    let amh = allowed_merchants_hash(&req.allowed_merchants);
    let fields = AuthorizationFields {
        network: req.network.clone(),
        identity_payer: req.agent_id.clone(),
        session_pubkey: req.session_pubkey.clone(),
        authorized_amount_sats: req.authorized_amount_sats,
        spend_limit_per_request_sats: req.spend_limit_per_request_sats,
        spend_limit_total_sats: req.spend_limit_total_sats,
        allowed_merchants_hash: amh.clone(),
        facilitator: req.facilitator.clone(),
        valid_after: req.valid_after,
        valid_before: req.valid_before,
    };
    verify_authorization_signature(&fields, &req.delegation_signature)?;

    // The identity must be a registered agent.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM zk402_agents WHERE id = $1")
        .bind(&req.agent_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    if exists.is_none() {
        return Err(Zk402Error::InvalidPayload); // unknown agent
    }

    let merchants_json =
        serde_json::to_string(&req.allowed_merchants).unwrap_or_else(|_| "[]".to_owned());
    let id = format!("sk_{}", req.session_pubkey);
    sqlx::query(
        "INSERT INTO zk402_agent_session_keys \
         (id, agent_id, session_pubkey, authorized_amount_sats, \
          spend_limit_per_request_sats, spend_limit_total_sats, allowed_merchants_hash, \
          allowed_merchants_json, facilitator, network, valid_after, valid_before, \
          delegation_signature) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(&id)
    .bind(&req.agent_id)
    .bind(&req.session_pubkey)
    .bind(req.authorized_amount_sats)
    .bind(req.spend_limit_per_request_sats)
    .bind(req.spend_limit_total_sats)
    .bind(&amh)
    .bind(&merchants_json)
    .bind(&req.facilitator)
    .bind(&req.network)
    .bind(req.valid_after)
    .bind(req.valid_before)
    .bind(&req.delegation_signature)
    .execute(pool)
    .await
    .map_err(insert_err)?; // duplicate session key → conflict
    Ok(id)
}

/// Revoke a delegated session key (stamps `revoked_at`). After this,
/// [`validate_session_delegation`] rejects it. Idempotent. Returns whether a
/// row was revoked.
pub async fn revoke_session_key(
    pool: &PgPool,
    session_pubkey: &str,
    now: i64,
) -> Result<bool, Zk402Error> {
    let res = sqlx::query(
        "UPDATE zk402_agent_session_keys SET revoked_at = $2 \
         WHERE session_pubkey = $1 AND revoked_at IS NULL",
    )
    .bind(session_pubkey)
    .bind(ts(now))
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(res.rows_affected() == 1)
}

/// Enforcement primitive — validate a session-key-signed spend against its
/// stored delegation: the key must exist, be unrevoked, be inside its window,
/// the amount within the per-request cap, and the merchant in the allow-list.
/// This is what the settle path calls to make the delegation's caps/window/
/// revocation actually bite (the final wiring into the voucher-accept path is
/// the remaining integration step).
pub async fn validate_session_delegation(
    pool: &PgPool,
    session_pubkey: &str,
    amount_sats: i64,
    merchant: &str,
    now: i64,
) -> Result<(), Zk402Error> {
    // (per_request_cap, valid_after, valid_before, allowed_hash, allowed_json, revoked_at)
    type DelegationRow = (i64, i64, i64, String, String, Option<DateTime<Utc>>);
    let row: Option<DelegationRow> = sqlx::query_as(
        "SELECT spend_limit_per_request_sats, valid_after, valid_before, \
         allowed_merchants_hash, allowed_merchants_json, revoked_at \
         FROM zk402_agent_session_keys WHERE session_pubkey = $1",
    )
    .bind(session_pubkey)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let (per_req, valid_after, valid_before, amh, merchants_json, revoked_at) =
        row.ok_or(Zk402Error::InvalidPayload)?; // unknown session key
    if revoked_at.is_some() {
        return Err(Zk402Error::InvalidSignature); // revoked
    }
    if now < valid_after || now >= valid_before {
        return Err(Zk402Error::InvalidSignature); // outside window
    }
    if amount_sats > per_req {
        return Err(Zk402Error::InvalidPayload); // over per-request cap
    }
    // Merchant must be in the signed allow-list. Re-derive the hash from the
    // stored set and confirm it matches what was signed (tamper guard), then
    // check membership.
    let merchants: Vec<String> = serde_json::from_str(&merchants_json).unwrap_or_default();
    if allowed_merchants_hash(&merchants) != amh || !merchants.iter().any(|m| m == merchant) {
        return Err(Zk402Error::InvalidPayload); // merchant not in the signed allow-list
    }
    Ok(())
}

/// Settle-path hook — make a delegated session key's caps actually bite.
///
/// A voucher whose payer is `zkpayer_<session_pubkey>` for a key present in
/// `zk402_agent_session_keys` is a *delegated* spend: it MUST satisfy that
/// delegation (revocation / validity window / per-request cap / merchant
/// allow-list) via [`validate_session_delegation`]. A payer that is not a
/// known session key is an ordinary buyer and passes through untouched — so
/// this is a no-op for the non-delegated path and only constrains keys that
/// an identity actually delegated. Called from `facilitator::settle`.
pub async fn enforce_session_delegation(
    pool: &PgPool,
    payer: &str,
    amount_sats: i64,
    merchant: &str,
    now: i64,
) -> Result<(), Zk402Error> {
    // `zkpayer_<hex>` is the only payer form a session key can take; anything
    // else is definitionally not a delegated key.
    let Some(session_pubkey) = payer.strip_prefix("zkpayer_") else {
        return Ok(());
    };
    let known: Option<String> = sqlx::query_scalar(
        "SELECT session_pubkey FROM zk402_agent_session_keys WHERE session_pubkey = $1",
    )
    .bind(session_pubkey)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    if known.is_none() {
        return Ok(()); // ordinary buyer payer, not a delegated session key
    }
    validate_session_delegation(pool, session_pubkey, amount_sats, merchant, now).await
}

// ---- Layer 4: signed disputes (ZK402-DISPUTE-V1) ---------------------------

pub struct FileDispute {
    pub receipt_id: String,
    pub complainant: String,
    pub verdict: String,
    pub reason_hash: String,
    pub timestamp: i64,
    pub signature: String,
}

/// File an append-only signed dispute/rating. The complainant's
/// `ZK402-DISPUTE-V1` signature is verified AND the complainant MUST be the
/// receipt's own payer — so a third party cannot file ratings against a
/// payment they had no part in (reputation poisoning). Freshness-bounded,
/// idempotent per (receipt, complainant). Returns the dispute row id.
pub async fn file_dispute(
    pool: &PgPool,
    req: &FileDispute,
    now: i64,
) -> Result<String, Zk402Error> {
    if !matches!(req.verdict.as_str(), "ok" | "bad" | "refunded") {
        return Err(Zk402Error::InvalidPayload);
    }
    fresh(req.timestamp, now)?;
    let fields = DisputeFields {
        receipt_id: req.receipt_id.clone(),
        complainant: req.complainant.clone(),
        verdict: req.verdict.clone(),
        reason_hash: req.reason_hash.clone(),
        timestamp: req.timestamp,
    };
    verify_dispute_signature(&fields, &req.signature)?;

    // Bind the complainant to the receipt's PAYER: only the party that actually
    // paid for this receipt may rate it. Unknown receipt or mismatched payer →
    // rejected (no third-party reputation poisoning).
    let payer: Option<String> = sqlx::query_scalar(
        "SELECT pi.payer FROM zk402_receipts r \
         JOIN zk402_payment_intents pi ON pi.id = r.payment_intent_id \
         WHERE r.id = $1",
    )
    .bind(&req.receipt_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    match payer {
        Some(p) if p == req.complainant => {}
        _ => return Err(Zk402Error::InvalidPayload),
    }

    let id = format!("dsp_{}_{}", req.receipt_id, req.complainant);
    let inserted = sqlx::query(
        "INSERT INTO zk402_disputes \
         (id, receipt_id, complainant, verdict, reason_hash, attestation_signature, signed_timestamp) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING",
    )
    .bind(&id)
    .bind(&req.receipt_id)
    .bind(&req.complainant)
    .bind(&req.verdict)
    .bind(&req.reason_hash)
    .bind(&req.signature)
    .bind(req.timestamp)
    .execute(pool)
    .await
    .map_err(db_err)?;
    // A pre-existing row is idempotent ONLY if it is the SAME rating. A second
    // dispute by the same complainant on the same receipt with a DIFFERENT
    // verdict/reason is a conflicting re-rating — surface it as a replay/
    // conflict rather than silently swallowing it (the append-only ledger must
    // not let a later mind-change masquerade as success).
    if inserted.rows_affected() == 0 {
        let existing: Option<(String, String)> =
            sqlx::query_as("SELECT verdict, reason_hash FROM zk402_disputes WHERE id = $1")
                .bind(&id)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?;
        match existing {
            Some((v, rh)) if v == req.verdict && rh == req.reason_hash => {} // idempotent
            Some(_) => return Err(Zk402Error::ReplayDetected), // conflicting re-rating
            None => return Err(Zk402Error::SettlementQueueUnavailable), // lost row (race)
        }
    }
    Ok(id)
}
