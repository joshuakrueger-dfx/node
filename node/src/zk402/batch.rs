//! ZK402 batch worker (Step 7).
//!
//! Drains `queued` payment intents into per-merchant settlement batches
//! (`docs/BATCHING_STRATEGY.md`). Correctness properties, each pinned by
//! a test in `batch_tests.rs`:
//!
//! * **Transactional cycle** — selection (`FOR UPDATE SKIP LOCKED`),
//!   batch creation, item insertion, ledger posting and intent
//!   transitions commit atomically. A crash mid-cycle rolls back to
//!   clean `queued` state; the next cycle simply picks the work up
//!   again (crash-safe resume).
//! * **Exactly-once ledger** — settlement entries use deterministic ids
//!   (`stl_accepted_<intent>`) + `ON CONFLICT (id) DO NOTHING`, so
//!   re-running a cycle or retrying a batch can never double-post.
//! * **No expired work** — a queued intent whose `valid_before` has
//!   passed is marked `expired` and never batched.
//! * **Merchant grouping** — one batch per merchant per cycle (merchant
//!   value stays merchant-directed; non-custodial).

use chrono::{DateTime, TimeZone, Utc};
use sqlx::{PgPool, Row};

use super::error::Zk402Error;
use super::types::BatchStatus;

/// Worker policy knobs (BATCHING_STRATEGY defaults: max_intents 500,
/// max_age 300 s — age-based triggering is the scheduler's concern; the
/// cycle itself just drains what is eligible now).
#[derive(Debug, Clone)]
pub struct BatchPolicy {
    pub max_intents_per_cycle: i64,
}

impl Default for BatchPolicy {
    fn default() -> Self {
        Self {
            max_intents_per_cycle: 500,
        }
    }
}

fn ts(unix: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(unix, 0).single().unwrap_or_else(Utc::now)
}

/// Mark queued intents whose voucher window has lapsed as `expired`
/// (they must never be batched). Returns how many were expired.
pub async fn expire_stale_intents(pool: &PgPool, now: i64) -> Result<u64, Zk402Error> {
    let res = sqlx::query(
        "UPDATE zk402_payment_intents \
         SET status = 'expired', updated_at = now() \
         WHERE status = 'queued' AND valid_before < $1",
    )
    .bind(ts(now))
    .execute(pool)
    .await
    .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    Ok(res.rows_affected())
}

/// One worker cycle: drain eligible queued intents into per-merchant
/// `locked` batches. Returns the created batch ids (empty when there was
/// nothing to do). Fully transactional — see module docs.
pub async fn run_batch_cycle(
    pool: &PgPool,
    policy: &BatchPolicy,
    now: i64,
) -> Result<Vec<String>, Zk402Error> {
    expire_stale_intents(pool, now).await?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;

    // Claim eligible intents. SKIP LOCKED lets concurrent workers run
    // without deadlocking or double-claiming.
    // `NOT IN (batch_items)` makes selection idempotent at the source:
    // an intent already placed in a batch can never be re-selected, so
    // re-running a cycle (or a spurious requeue) cannot double-batch or
    // double-post — independent of, and complementary to, the
    // one-batch-per-intent unique index.
    let rows = sqlx::query(
        "SELECT id, merchant_id, network, amount_sats, fee_amount_sats \
         FROM zk402_payment_intents \
         WHERE status = 'queued' \
           AND id NOT IN (SELECT payment_intent_id FROM zk402_batch_items) \
         ORDER BY created_at \
         LIMIT $1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(policy.max_intents_per_cycle)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;

    if rows.is_empty() {
        return Ok(vec![]);
    }

    // Group by merchant (preserving created_at order within groups).
    let mut groups: Vec<(String, String, Vec<(String, i64, i64)>)> = Vec::new();
    for r in &rows {
        let merchant: String = r
            .try_get("merchant_id")
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
        let network: String = r
            .try_get("network")
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
        let intent: String = r
            .try_get("id")
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
        let amount: i64 = r
            .try_get("amount_sats")
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
        let fee: i64 = r
            .try_get("fee_amount_sats")
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
        match groups
            .iter_mut()
            .find(|(m, n, _)| *m == merchant && *n == network)
        {
            Some((_, _, items)) => items.push((intent, amount, fee)),
            None => groups.push((merchant, network, vec![(intent, amount, fee)])),
        }
    }

    let mut batch_ids = Vec::new();
    for (merchant, network, items) in groups {
        let batch_id = format!("zkb_{}", uuid::Uuid::new_v4().simple());
        let gross: i64 = items.iter().map(|(_, a, _)| a).sum();
        let fee: i64 = items.iter().map(|(_, _, f)| f).sum();
        let net = gross - fee;

        sqlx::query(
            "INSERT INTO zk402_batches \
             (id, network, merchant_id, status, gross_amount_sats, fee_amount_sats, \
              net_amount_sats, intent_count) \
             VALUES ($1, $2, $3, 'locked', $4, $5, $6, $7)",
        )
        .bind(&batch_id)
        .bind(&network)
        .bind(&merchant)
        .bind(gross)
        .bind(fee)
        .bind(net)
        .bind(items.len() as i32)
        .execute(&mut *tx)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;

        for (intent_id, amount, item_fee) in &items {
            sqlx::query(
                "INSERT INTO zk402_batch_items \
                 (batch_id, payment_intent_id, amount_sats, fee_sats, net_sats) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (batch_id, payment_intent_id) DO NOTHING",
            )
            .bind(&batch_id)
            .bind(intent_id)
            .bind(amount)
            .bind(item_fee)
            .bind(amount - item_fee)
            .execute(&mut *tx)
            .await
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;

            // Exactly-once accepted-entry per intent: deterministic id.
            sqlx::query(
                "INSERT INTO zk402_merchant_settlements \
                 (id, merchant_id, payment_intent_id, batch_id, kind, amount_sats, status) \
                 VALUES ($1, $2, $3, $4, 'accepted', $5, 'pending') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(format!("stl_accepted_{intent_id}"))
            .bind(&merchant)
            .bind(intent_id)
            .bind(&batch_id)
            .bind(amount - item_fee)
            .execute(&mut *tx)
            .await
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;

            sqlx::query(
                "UPDATE zk402_payment_intents \
                 SET status = 'batching', batched_at = $2, updated_at = now() \
                 WHERE id = $1",
            )
            .bind(intent_id)
            .bind(ts(now))
            .execute(&mut *tx)
            .await
            .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
        }
        batch_ids.push(batch_id);
    }

    tx.commit()
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    Ok(batch_ids)
}

/// Retry a `failed_recoverable` batch: back to `locked`, bump
/// `retry_count`. Items and ledger entries are NOT re-posted (their
/// deterministic ids make any re-posting a no-op anyway).
pub async fn retry_failed_batch(pool: &PgPool, batch_id: &str) -> Result<bool, Zk402Error> {
    let res = sqlx::query(
        "UPDATE zk402_batches \
         SET status = 'locked', retry_count = retry_count + 1, \
             failure_code = NULL, failure_message = NULL, updated_at = now() \
         WHERE id = $1 AND status = 'failed_recoverable'",
    )
    .bind(batch_id)
    .execute(pool)
    .await
    .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    Ok(res.rows_affected() == 1)
}

/// Record a batch failure with a structured code.
pub async fn fail_batch(
    pool: &PgPool,
    batch_id: &str,
    status: BatchStatus,
    code: &str,
    message: &str,
) -> Result<bool, Zk402Error> {
    let res = sqlx::query(
        "UPDATE zk402_batches \
         SET status = $2, failure_code = $3, failure_message = $4, updated_at = now() \
         WHERE id = $1",
    )
    .bind(batch_id)
    .bind(status.as_str())
    .bind(code)
    .bind(message)
    .execute(pool)
    .await
    .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    Ok(res.rows_affected() == 1)
}
