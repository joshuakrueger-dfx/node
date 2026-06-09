//! Agent Economy Phase 1 — Layer 3 (identity + delegation) + Layer 4 (disputes).
//!
//! Self-sovereign agent identities keyed by a Schnorr key; delegated, scoped,
//! revocable session keys authorized via `ZK402-AUTHORIZATION-V1` (closing the
//! `authorization.rs` seam — the identity key signs the delegation, the session
//! key then signs vouchers within the caps); and append-only signed
//! `ZK402-DISPUTE-V1` ratings bound to a settled receipt.
//!
//! All writes are signature-gated. Nothing here holds funds, a handle maps to a
//! key (never a human), so the zkCoins unlinkability property is preserved.

use sqlx::PgPool;

use super::canonical::{
    allowed_merchants_hash, capabilities_hash, AgentFields, AuthorizationFields, DisputeFields,
};
use super::error::Zk402Error;
use super::signature::{
    verify_agent_signature, verify_authorization_signature, verify_dispute_signature,
};

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
/// via a `ZK402-AGENT-V1` signature. Owner stays private — only the key.
pub async fn register_agent(pool: &PgPool, req: &RegisterAgent) -> Result<(), Zk402Error> {
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
    pub scope_json: String,
    pub delegation_signature: String,
}

/// Add a delegated session key under an agent's identity, verifying the
/// `ZK402-AUTHORIZATION-V1` delegation signed by the identity key. Returns the
/// session-key row id.
pub async fn add_session_key(pool: &PgPool, req: &AddSessionKey) -> Result<String, Zk402Error> {
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

    let id = format!("sk_{}", req.session_pubkey);
    sqlx::query(
        "INSERT INTO zk402_agent_session_keys \
         (id, agent_id, session_pubkey, scope_json, authorized_amount_sats, \
          spend_limit_per_request_sats, spend_limit_total_sats, allowed_merchants_hash, \
          facilitator, network, valid_after, valid_before, delegation_signature) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(&id)
    .bind(&req.agent_id)
    .bind(&req.session_pubkey)
    .bind(&req.scope_json)
    .bind(req.authorized_amount_sats)
    .bind(req.spend_limit_per_request_sats)
    .bind(req.spend_limit_total_sats)
    .bind(&amh)
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

// ---- Layer 4: signed disputes (ZK402-DISPUTE-V1) ---------------------------

pub struct FileDispute {
    pub receipt_id: String,
    pub complainant: String,
    pub verdict: String,
    pub reason_hash: String,
    pub timestamp: i64,
    pub signature: String,
    pub counter_signature: Option<String>,
}

/// File an append-only signed dispute/rating bound to a settled receipt,
/// verifying the complainant's `ZK402-DISPUTE-V1` signature. Idempotent per
/// (receipt, complainant). Returns the dispute row id.
pub async fn file_dispute(pool: &PgPool, req: &FileDispute) -> Result<String, Zk402Error> {
    if !matches!(req.verdict.as_str(), "ok" | "bad" | "refunded") {
        return Err(Zk402Error::InvalidPayload);
    }
    let fields = DisputeFields {
        receipt_id: req.receipt_id.clone(),
        complainant: req.complainant.clone(),
        verdict: req.verdict.clone(),
        reason_hash: req.reason_hash.clone(),
        timestamp: req.timestamp,
    };
    verify_dispute_signature(&fields, &req.signature)?;

    // The receipt must exist (FK also enforces; check for a clean error).
    let receipt: Option<String> = sqlx::query_scalar("SELECT id FROM zk402_receipts WHERE id = $1")
        .bind(&req.receipt_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    if receipt.is_none() {
        return Err(Zk402Error::InvalidPayload); // unknown receipt
    }

    let id = format!("dsp_{}_{}", req.receipt_id, req.complainant);
    sqlx::query(
        "INSERT INTO zk402_disputes \
         (id, receipt_id, complainant, verdict, reason_hash, attestation_signature, counter_signature) \
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING",
    )
    .bind(&id)
    .bind(&req.receipt_id)
    .bind(&req.complainant)
    .bind(&req.verdict)
    .bind(&req.reason_hash)
    .bind(&req.signature)
    .bind(req.counter_signature.as_deref())
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(id)
}
