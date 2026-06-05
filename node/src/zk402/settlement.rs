//! zkCoins settlement integration (Step 8) — behind a pluggable backend.
//!
//! Drives a `locked` batch through the publish state machine
//! (`docs/SETTLEMENT_STATE_MACHINE.md`):
//!
//! ```text
//! locked → proof_generating → ready_to_publish → publishing → published
//!        → observed (scanner) → final
//!   any failure → failed_recoverable (+ structured code) → retry → locked
//! ```
//!
//! The actual zkCoins send/commit path is NOT implemented upstream yet
//! (`PROTOCOL_STATUS.md`: nullifier system / publisher batching "Not
//! Implemented"), so the chain interaction lives behind
//! [`SettlementBackend`]. Today's implementations are mocks; when the
//! real primitives land they slot in behind the same trait without
//! touching the state machine, the ledger, or the tests.
//!
//! **Single credit point**: merchant value is credited exactly once, at
//! `final`, via a deterministic ledger id (`stl_final_<intent>`) +
//! `ON CONFLICT DO NOTHING` — retries can never double-credit. The
//! batching-time `accepted` entry flips `pending → posted` at the same
//! moment, closing the lifecycle.

use chrono::{DateTime, TimeZone, Utc};
use sqlx::PgPool;

use super::error::Zk402Error;
use super::store;
use super::types::{BatchStatus, PaymentIntentStatus};

/// The pluggable zkCoins chain interaction (mocked until the upstream
/// protocol primitives exist — see module docs).
pub trait SettlementBackend: Send + Sync {
    /// Generate the batch proof, returning the zkCoins proof id.
    fn generate_proof(&self, batch_id: &str) -> Result<String, Zk402Error>;
    /// Publish commit+reveal for the proven batch, returning the txids.
    fn publish(&self, batch_id: &str, proof_id: &str) -> Result<(String, String), Zk402Error>;
}

/// Happy-path mock: deterministic proof id + txids.
pub struct MockSettlement;

impl SettlementBackend for MockSettlement {
    fn generate_proof(&self, batch_id: &str) -> Result<String, Zk402Error> {
        Ok(format!("proof_{batch_id}"))
    }
    fn publish(&self, batch_id: &str, _proof_id: &str) -> Result<(String, String), Zk402Error> {
        Ok((format!("4242c_{batch_id}"), format!("4242r_{batch_id}")))
    }
}

/// Mock: prover offline.
pub struct ProverFailing;
impl SettlementBackend for ProverFailing {
    fn generate_proof(&self, _: &str) -> Result<String, Zk402Error> {
        Err(Zk402Error::ProverUnavailable)
    }
    fn publish(&self, _: &str, _: &str) -> Result<(String, String), Zk402Error> {
        unreachable!("publish is never reached when proving fails")
    }
}

/// Mock: publisher wallet has no UTXOs.
pub struct UnfundedPublisher;
impl SettlementBackend for UnfundedPublisher {
    fn generate_proof(&self, batch_id: &str) -> Result<String, Zk402Error> {
        Ok(format!("proof_{batch_id}"))
    }
    fn publish(&self, _: &str, _: &str) -> Result<(String, String), Zk402Error> {
        Err(Zk402Error::PublisherUnfunded)
    }
}

/// Mock: broadcast rejected by the network.
pub struct BroadcastFailing;
impl SettlementBackend for BroadcastFailing {
    fn generate_proof(&self, batch_id: &str) -> Result<String, Zk402Error> {
        Ok(format!("proof_{batch_id}"))
    }
    fn publish(&self, _: &str, _: &str) -> Result<(String, String), Zk402Error> {
        Err(Zk402Error::SettlementQueueUnavailable)
    }
}

fn ts(unix: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(unix, 0).single().unwrap_or_else(Utc::now)
}

fn db_err(_: sqlx::Error) -> Zk402Error {
    Zk402Error::SettlementQueueUnavailable
}

async fn set_batch_status(
    pool: &PgPool,
    batch_id: &str,
    from: &str,
    to: BatchStatus,
) -> Result<bool, Zk402Error> {
    let res = sqlx::query(
        "UPDATE zk402_batches SET status = $3, updated_at = now() \
         WHERE id = $1 AND status = $2",
    )
    .bind(batch_id)
    .bind(from)
    .bind(to.as_str())
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(res.rows_affected() == 1)
}

async fn intents_in_batch(pool: &PgPool, batch_id: &str) -> Result<Vec<(String, i64)>, Zk402Error> {
    let items = store::list_batch_items(pool, batch_id)
        .await
        .map_err(db_err)?;
    Ok(items
        .into_iter()
        .map(|i| (i.payment_intent_id, i.net_sats))
        .collect())
}

/// Drive a `locked` batch through proof + publish. On success the batch
/// is `published` (proof id + commit/reveal txids persisted, intents →
/// `published`); on failure it is `failed_recoverable` with the
/// structured code, ready for `batch::retry_failed_batch`.
pub async fn settle_batch(
    pool: &PgPool,
    backend: &dyn SettlementBackend,
    batch_id: &str,
    now: i64,
) -> Result<(), Zk402Error> {
    if !set_batch_status(pool, batch_id, "locked", BatchStatus::ProofGenerating).await? {
        return Err(Zk402Error::SettlementQueueUnavailable); // not locked / unknown
    }
    sqlx::query("UPDATE zk402_batches SET proof_started_at = $2 WHERE id = $1")
        .bind(batch_id)
        .bind(ts(now))
        .execute(pool)
        .await
        .map_err(db_err)?;

    let proof_id = match backend.generate_proof(batch_id) {
        Ok(p) => p,
        Err(e) => {
            super::batch::fail_batch(
                pool,
                batch_id,
                BatchStatus::FailedRecoverable,
                e.code(),
                "proof generation failed",
            )
            .await?;
            return Err(e);
        }
    };
    sqlx::query(
        "UPDATE zk402_batches SET status = 'ready_to_publish', zkcoins_proof_id = $2, \
         proof_finished_at = $3, updated_at = now() WHERE id = $1 AND status = 'proof_generating'",
    )
    .bind(batch_id)
    .bind(&proof_id)
    .bind(ts(now))
    .execute(pool)
    .await
    .map_err(db_err)?;

    set_batch_status(pool, batch_id, "ready_to_publish", BatchStatus::Publishing).await?;
    let (commit_txid, reveal_txid) = match backend.publish(batch_id, &proof_id) {
        Ok(t) => t,
        Err(e) => {
            super::batch::fail_batch(
                pool,
                batch_id,
                BatchStatus::FailedRecoverable,
                e.code(),
                "publish failed",
            )
            .await?;
            return Err(e);
        }
    };
    sqlx::query(
        "UPDATE zk402_batches SET status = 'published', commit_txid = $2, reveal_txid = $3, \
         published_at = $4, updated_at = now() WHERE id = $1 AND status = 'publishing'",
    )
    .bind(batch_id)
    .bind(&commit_txid)
    .bind(&reveal_txid)
    .bind(ts(now))
    .execute(pool)
    .await
    .map_err(db_err)?;

    for (intent_id, _) in intents_in_batch(pool, batch_id).await? {
        store::update_payment_intent_status(
            pool,
            &intent_id,
            PaymentIntentStatus::Published,
            ts(now),
        )
        .await
        .map_err(db_err)?;
    }
    Ok(())
}

/// Scanner observed the reveal on-chain: batch `published → observed`,
/// intents → `confirmed`.
pub async fn confirm_batch(pool: &PgPool, batch_id: &str, now: i64) -> Result<bool, Zk402Error> {
    if !set_batch_status(pool, batch_id, "published", BatchStatus::Observed).await? {
        return Ok(false);
    }
    sqlx::query("UPDATE zk402_batches SET observed_at = $2 WHERE id = $1")
        .bind(batch_id)
        .bind(ts(now))
        .execute(pool)
        .await
        .map_err(db_err)?;
    for (intent_id, _) in intents_in_batch(pool, batch_id).await? {
        store::update_payment_intent_status(
            pool,
            &intent_id,
            PaymentIntentStatus::Confirmed,
            ts(now),
        )
        .await
        .map_err(db_err)?;
    }
    Ok(true)
}

/// Finality depth reached: batch `observed → final`, intents → `final`,
/// and the SINGLE merchant credit per intent is posted exactly once
/// (deterministic id). Re-running is a no-op — no double credit.
pub async fn finalize_batch(pool: &PgPool, batch_id: &str, now: i64) -> Result<bool, Zk402Error> {
    if !set_batch_status(pool, batch_id, "observed", BatchStatus::Final).await? {
        return Ok(false);
    }
    sqlx::query("UPDATE zk402_batches SET final_at = $2 WHERE id = $1")
        .bind(batch_id)
        .bind(ts(now))
        .execute(pool)
        .await
        .map_err(db_err)?;

    let merchant: Option<String> =
        sqlx::query_scalar("SELECT merchant_id FROM zk402_batches WHERE id = $1")
            .bind(batch_id)
            .fetch_one(pool)
            .await
            .map_err(db_err)?;
    let merchant = merchant.ok_or(Zk402Error::SettlementQueueUnavailable)?;

    for (intent_id, net_sats) in intents_in_batch(pool, batch_id).await? {
        store::update_payment_intent_status(pool, &intent_id, PaymentIntentStatus::Final, ts(now))
            .await
            .map_err(db_err)?;
        // Exactly-once final credit (deterministic id).
        sqlx::query(
            "INSERT INTO zk402_merchant_settlements \
             (id, merchant_id, payment_intent_id, batch_id, kind, amount_sats, status) \
             VALUES ($1, $2, $3, $4, 'final', $5, 'posted') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(format!("stl_final_{intent_id}"))
        .bind(&merchant)
        .bind(&intent_id)
        .bind(batch_id)
        .bind(net_sats)
        .execute(pool)
        .await
        .map_err(db_err)?;
        // Close the lifecycle: the batching-time accepted entry is posted.
        sqlx::query(
            "UPDATE zk402_merchant_settlements SET status = 'posted' \
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(format!("stl_accepted_{intent_id}"))
        .execute(pool)
        .await
        .map_err(db_err)?;
    }
    Ok(true)
}

/// Boot-time resume: every batch stuck in a transient publish state is
/// returned to a retryable position. `proof_generating`/`publishing`/
/// `ready_to_publish` roll back to `locked` (their work is idempotent
/// and re-runnable); `published`/`observed` are left for the scanner.
pub async fn resume_pending_batches(pool: &PgPool) -> Result<u64, Zk402Error> {
    let res = sqlx::query(
        "UPDATE zk402_batches SET status = 'locked', updated_at = now() \
         WHERE status IN ('proof_generating','ready_to_publish','publishing')",
    )
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(res.rows_affected())
}
