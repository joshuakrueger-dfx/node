//! ZK402 dashboard & operations (Step 9).
//!
//! Merchant onboarding, API-key auth, and merchant-scoped read views.
//! Two hard rules from the roadmap:
//!
//! * **Own data only** — every query is filtered by the authenticated
//!   merchant id; there is no cross-merchant read path.
//! * **No custody UI** — there is no withdraw/payout endpoint, because
//!   the operator custodies nothing. The dashboard exposes the merchant's
//!   append-only settlement *view* (accepted/published/confirmed/final
//!   shown separately) and fee analytics, nothing movable.

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

use super::error::Zk402Error;
use super::types::{MerchantStatus, NewMerchant};

fn db_err(_: sqlx::Error) -> Zk402Error {
    Zk402Error::SettlementQueueUnavailable
}

fn hash_key(plaintext: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(plaintext.as_bytes());
    h.finalize().to_vec()
}

/// Result of onboarding: the merchant id + the plaintext API key (shown
/// ONCE — only its hash is stored).
#[derive(Debug, Clone)]
pub struct Onboarded {
    pub merchant_id: String,
    pub api_key: String,
}

/// Onboard a merchant and issue its first API key.
pub async fn onboard_merchant(
    pool: &PgPool,
    merchant_id: &str,
    display_name: &str,
    settlement_address: &str,
    api_key_plaintext: &str,
) -> Result<Onboarded, Zk402Error> {
    let inserted = super::store::insert_merchant(
        pool,
        &NewMerchant {
            id: merchant_id.to_owned(),
            display_name: display_name.to_owned(),
            settlement_address: settlement_address.to_owned(),
            username: None,
            status: MerchantStatus::Active,
            fee_bps: 100,
            fixed_fee_sats: 0,
        },
    )
    .await
    .map_err(db_err)?;
    if !inserted {
        return Err(Zk402Error::InvalidPayload); // merchant id already exists
    }
    issue_api_key(pool, merchant_id, "default", api_key_plaintext).await?;
    Ok(Onboarded {
        merchant_id: merchant_id.to_owned(),
        api_key: api_key_plaintext.to_owned(),
    })
}

/// Issue an additional API key for an existing merchant. Stores only the
/// hash; returns the key id.
pub async fn issue_api_key(
    pool: &PgPool,
    merchant_id: &str,
    label: &str,
    plaintext: &str,
) -> Result<String, Zk402Error> {
    let id = format!("zkak_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO zk402_api_keys (id, merchant_id, key_hash, label) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(merchant_id)
    .bind(hash_key(plaintext))
    .bind(label)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(id)
}

/// Resolve an API key to its merchant id, or `None` if unknown/revoked.
pub async fn authenticate(pool: &PgPool, api_key: &str) -> Result<Option<String>, Zk402Error> {
    let merchant: Option<String> = sqlx::query_scalar(
        "SELECT merchant_id FROM zk402_api_keys \
         WHERE key_hash = $1 AND revoked_at IS NULL",
    )
    .bind(hash_key(api_key))
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    Ok(merchant)
}

/// Revoke an API key (operator action). Idempotent.
pub async fn revoke_api_key(pool: &PgPool, key_id: &str) -> Result<bool, Zk402Error> {
    let res = sqlx::query(
        "UPDATE zk402_api_keys SET revoked_at = now() \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(key_id)
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(res.rows_affected() == 1)
}

/// Per-settlement-state totals for a merchant — the four lifecycle
/// stages shown SEPARATELY (never collapsed into one "balance"), plus
/// fees. Sats, derived from the append-only ledger.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SettlementSummary {
    pub accepted_sats: i64,
    pub published_sats: i64,
    pub confirmed_sats: i64,
    pub final_sats: i64,
    pub fee_sats: i64,
    pub reversal_sats: i64,
}

/// Fee + volume analytics for a merchant (derived from its intents).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FeeAnalytics {
    pub intent_count: i64,
    pub gross_sats: i64,
    pub fee_sats: i64,
    pub net_sats: i64,
}

/// Settlement summary for one merchant, grouped by ledger `kind`.
pub async fn settlement_summary(
    pool: &PgPool,
    merchant_id: &str,
) -> Result<SettlementSummary, Zk402Error> {
    let rows = sqlx::query(
        "SELECT kind, COALESCE(SUM(amount_sats), 0)::bigint AS total \
         FROM zk402_merchant_settlements WHERE merchant_id = $1 GROUP BY kind",
    )
    .bind(merchant_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let mut s = SettlementSummary::default();
    for r in rows {
        let kind: String = r.try_get("kind").map_err(db_err)?;
        let total: i64 = r.try_get("total").map_err(db_err)?;
        match kind.as_str() {
            "accepted" => s.accepted_sats = total,
            "published" => s.published_sats = total,
            "confirmed" => s.confirmed_sats = total,
            "final" => s.final_sats = total,
            "fee" => s.fee_sats = total,
            "reversal" => s.reversal_sats = total,
            _ => {}
        }
    }
    Ok(s)
}

/// Fee analytics for one merchant.
pub async fn fee_analytics(pool: &PgPool, merchant_id: &str) -> Result<FeeAnalytics, Zk402Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) AS n, \
                COALESCE(SUM(amount_sats), 0)::bigint AS gross, \
                COALESCE(SUM(fee_amount_sats), 0)::bigint AS fee \
         FROM zk402_payment_intents WHERE merchant_id = $1",
    )
    .bind(merchant_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let intent_count: i64 = row.try_get("n").map_err(db_err)?;
    let gross_sats: i64 = row.try_get("gross").map_err(db_err)?;
    let fee_sats: i64 = row.try_get("fee").map_err(db_err)?;
    Ok(FeeAnalytics {
        intent_count,
        gross_sats,
        fee_sats,
        net_sats: gross_sats - fee_sats,
    })
}

/// List a merchant's batches (own data only).
pub async fn list_batches(
    pool: &PgPool,
    merchant_id: &str,
) -> Result<Vec<super::types::Batch>, Zk402Error> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM zk402_batches WHERE merchant_id = $1 ORDER BY created_at DESC",
    )
    .bind(merchant_id)
    .fetch_all(pool)
    .await
    .map_err(db_err)?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(b) = super::store::load_batch(pool, &id).await.map_err(db_err)? {
            out.push(b);
        }
    }
    Ok(out)
}

/// Reconciliation check: the sum of a merchant's `final` settlement
/// entries equals the sum of `net_amount_sats` over its `final` batches.
/// Exposed for the "exports reconcile with the ledger" guarantee.
pub async fn reconciles(pool: &PgPool, merchant_id: &str) -> Result<bool, Zk402Error> {
    let ledger_final: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_sats), 0)::bigint FROM zk402_merchant_settlements \
         WHERE merchant_id = $1 AND kind = 'final'",
    )
    .bind(merchant_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    let batch_final_net: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(net_amount_sats), 0)::bigint FROM zk402_batches \
         WHERE merchant_id = $1 AND status = 'final'",
    )
    .bind(merchant_id)
    .fetch_one(pool)
    .await
    .map_err(db_err)?;
    Ok(ledger_final == batch_final_net)
}
