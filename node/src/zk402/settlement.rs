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

// ===========================================================================
// Receive-driven finality (real zkCoins settlement, migration 0019).
//
// Instead of the mocked batch path above, a per-intent settlement is driven
// by the ACTUAL incoming transfer on the intent's unique receiving address:
// the scanner / `/api/receive` seam records an observation, and a runtime
// watcher advances the intent published -> confirmed -> final from the
// observed confirmation depth (PDF §3.9). Correlation is 1:1 by receiving
// address, so no memo field is needed. See docs/ZK402_SPEC_ALIGNMENT.md.
// ===========================================================================

/// Confirmation depth at which a settlement is final (Protocol Spec §3.9:
/// zkCoins fixes finality at 6 confirmations).
pub const FINALITY_CONFIRMATIONS: i64 = 6;

/// Confirmations of an inscription mined at `block_height` given the current
/// chain `tip_height`. The inclusion block counts as the first confirmation;
/// clamped to >= 0 (a not-yet-mined / forward anchor yields 0).
pub fn confirmations(tip_height: i64, block_height: i64) -> i64 {
    (tip_height - block_height + 1).max(0)
}

/// Map a confirmation depth to the ZK402 settlement status (PDF §3.10):
/// 0 = inscribed / in mempool → `published`; 1..5 → `confirmed`;
/// >= 6 → `final` (the receiver may credit).
pub fn settlement_state_for(confs: i64) -> PaymentIntentStatus {
    if confs >= FINALITY_CONFIRMATIONS {
        PaymentIntentStatus::Final
    } else if confs >= 1 {
        PaymentIntentStatus::Confirmed
    } else {
        PaymentIntentStatus::Published
    }
}

/// Forward-only rank of the receive-driven settlement states, so `advance`
/// never downgrades (e.g. a transient re-observation can't push `confirmed`
/// back to `published`). Non-settlement statuses rank 0 so the first real
/// observation can lift them.
fn settle_rank(status: &str) -> i32 {
    match status {
        "published" => 1,
        "confirmed" => 2,
        "final" => 3,
        _ => 0,
    }
}

/// Integration seam: record an on-chain receive crediting a per-intent
/// receiving address. The real scanner / `/api/receive` path calls this once
/// a `4242` inscription paying `receiving_address` is integrated (block_height
/// = the inclusion block, or `None` while still in mempool). Append-only.
pub async fn record_receive_observation(
    pool: &PgPool,
    payment_intent_id: Option<&str>,
    receiving_address: &str,
    amount_sats: i64,
    block_height: Option<i64>,
    now: i64,
) -> Result<(), Zk402Error> {
    sqlx::query(
        "INSERT INTO zk402_settlement_observations \
         (payment_intent_id, receiving_address, amount_sats, block_height, observed_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(payment_intent_id)
    .bind(receiving_address)
    .bind(amount_sats)
    .bind(block_height)
    .bind(ts(now))
    .execute(pool)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Advance one intent's settlement from the real receive state. Loads the
/// intent's receiving address + amount, takes the latest observation for that
/// address, computes confirmations against `tip_height`, and moves the intent
/// forward published → confirmed → final. At `final` it posts the SINGLE
/// merchant credit (deterministic id + `ON CONFLICT DO NOTHING`) — idempotent,
/// never double-credits — and flips the `accepted` ledger entry to `posted`.
///
/// Fail-closed and forward-only: no receiving address, no observation, an
/// under-amount, or no forward progress all leave the intent unchanged
/// (`Ok(None)`). Terminal intents are never touched.
pub async fn advance_intent_settlement(
    pool: &PgPool,
    intent_id: &str,
    tip_height: i64,
    now: i64,
) -> Result<Option<PaymentIntentStatus>, Zk402Error> {
    let row: Option<(Option<String>, i64, String, String)> = sqlx::query_as(
        "SELECT receiving_address, amount_sats, merchant_id, status \
         FROM zk402_payment_intents WHERE id = $1",
    )
    .bind(intent_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let (recv_addr, amount_sats, merchant, cur_status) = match row {
        Some((Some(a), amt, m, s)) if !a.is_empty() => (a, amt, m, s),
        _ => return Ok(None), // unknown / not receive-correlated
    };
    if matches!(
        cur_status.as_str(),
        "final" | "failed_terminal" | "reversed" | "expired"
    ) {
        return Ok(None);
    }

    let obs: Option<(i64, Option<i64>)> = sqlx::query_as(
        "SELECT amount_sats, block_height FROM zk402_settlement_observations \
         WHERE receiving_address = $1 ORDER BY observed_at DESC, id DESC LIMIT 1",
    )
    .bind(&recv_addr)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;
    let (obs_amount, block_height) = match obs {
        Some(o) => o,
        None => return Ok(None), // not received yet — fail-closed
    };
    if obs_amount < amount_sats {
        return Ok(None); // underpaid — do not credit
    }

    let confs = block_height.map_or(0, |h| confirmations(tip_height, h));
    let target = settlement_state_for(confs);
    if settle_rank(target.as_str()) <= settle_rank(&cur_status) {
        return Ok(None); // no forward progress
    }

    store::update_payment_intent_status(pool, intent_id, target, ts(now))
        .await
        .map_err(db_err)?;

    if target == PaymentIntentStatus::Final {
        // Single, exactly-once final credit (deterministic id).
        sqlx::query(
            "INSERT INTO zk402_merchant_settlements \
             (id, merchant_id, payment_intent_id, batch_id, kind, amount_sats, status) \
             VALUES ($1, $2, $3, NULL, 'final', $4, 'posted') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(format!("stl_final_{intent_id}"))
        .bind(&merchant)
        .bind(intent_id)
        .bind(amount_sats)
        .execute(pool)
        .await
        .map_err(db_err)?;
        sqlx::query(
            "UPDATE zk402_merchant_settlements SET status = 'posted' \
             WHERE id = $1 AND status = 'pending'",
        )
        .bind(format!("stl_accepted_{intent_id}"))
        .execute(pool)
        .await
        .map_err(db_err)?;
    }
    Ok(Some(target))
}
