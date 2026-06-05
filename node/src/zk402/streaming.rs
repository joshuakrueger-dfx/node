//! ZK402-Stream metering (Flow-D) — the LLM-token billing hot path.
//!
//! Model (proposals/ZK402_STREAM_design.md, Part B): a metering channel
//! is an authorization with `channel_mode = 'metering'`. Per inference
//! the buyer signs ONE `ZK402-STREAM-V1` voucher carrying
//! `max_amount_sats` (the ceiling for this request) and a monotone
//! `cumulative_authorized_sats` (the running signed ceiling across the
//! channel — the replay guard). The server streams the work, measures
//! ACTUAL usage (Claude reports real token counts at stream end),
//! charges `actual ≤ max`, and appends a usage event.
//!
//! Safety properties (each pinned by `streaming_tests.rs`):
//! * the voucher signature covers max + cumulative + request binding —
//!   tampering invalidates it;
//! * cumulative is STRICTLY monotone per channel (a replayed or
//!   decreased cumulative is rejected) — one atomic conditional UPDATE;
//! * `metered_amount_sats` can NEVER exceed the signed channel cap, no
//!   matter how many meterings race;
//! * `sum(usage_events.cost_sats) == metered_amount_sats` (ledger
//!   consistency).
//!
//! On-chain netting of the metered total is deferred to the settlement
//! backend (one inscription per epoch) — never per token, never per
//! call. That is the whole point.

use sqlx::PgPool;

use super::canonical::{stream_signing_digest, StreamVoucherFields};
use super::error::Zk402Error;
use super::signature::{payer_to_xonly, verify_schnorr_raw};
use super::types::AuthorizationStatus;

/// Integer sats cost for `quantity` units priced in micro-sats per
/// unit, rounded UP (the merchant never undercharges by rounding).
pub fn cost_sats(quantity: i64, unit_price_microsats: i64) -> i64 {
    let micro = (quantity as i128) * (unit_price_microsats as i128);
    micro.div_euclid(1_000_000) as i64 + i64::from(micro.rem_euclid(1_000_000) != 0)
}

/// Verify a streaming voucher's BIP-340 signature.
pub fn verify_stream_signature(
    fields: &StreamVoucherFields,
    signature_hex: &str,
) -> Result<(), Zk402Error> {
    let pubkey = payer_to_xonly(&fields.payer)?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| Zk402Error::InvalidSignature)?;
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&sig_bytes)
        .map_err(|_| Zk402Error::InvalidSignature)?;
    if verify_schnorr_raw(&pubkey, &stream_signing_digest(fields), &sig) {
        Ok(())
    } else {
        Err(Zk402Error::InvalidSignature)
    }
}

/// One measured slice of usage to charge under a voucher.
#[derive(Debug, Clone)]
pub struct Usage {
    /// e.g. `input_tokens`, `output_tokens`, `cache_read`, `request`.
    pub unit: String,
    pub quantity: i64,
    pub unit_price_microsats: i64,
    /// e.g. `claude-sonnet-4-6` — recorded for analytics, never signed.
    pub model: Option<String>,
}

/// Outcome of a successful metering.
#[derive(Debug, Clone, PartialEq)]
pub struct MeterOutcome {
    pub actual_cost_sats: i64,
    pub unspent_sats: i64,
    pub metered_total_sats: i64,
    pub cumulative_authorized_sats: i64,
}

/// Settle a streaming voucher: verify the signature, charge the actual
/// usage (≤ the voucher max), and advance the channel cursors in one
/// atomic conditional UPDATE.
pub async fn meter(
    pool: &PgPool,
    fields: &StreamVoucherFields,
    signature_hex: &str,
    usage: &[Usage],
    now: i64,
) -> Result<MeterOutcome, Zk402Error> {
    // 1. Cryptographic + structural gate.
    verify_stream_signature(fields, signature_hex)?;
    if now < fields.valid_after || now > fields.valid_before {
        return Err(if now < fields.valid_after {
            Zk402Error::NotYetValid
        } else {
            Zk402Error::ExpiredPayment
        });
    }
    if fields.max_amount_sats <= 0 || fields.cumulative_authorized_sats <= 0 {
        return Err(Zk402Error::InvalidPayload);
    }

    // 2. The channel must exist, be a metering channel, be active, and
    //    belong to this payer.
    let auth = super::store::load_authorization(pool, &fields.channel_id)
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
    if auth.payer != fields.payer || auth.network != fields.network {
        return Err(Zk402Error::InvalidPayload);
    }

    // 3. The actual charge, measured by the server, capped by the voucher.
    let actual: i64 = usage
        .iter()
        .map(|u| cost_sats(u.quantity, u.unit_price_microsats))
        .sum();
    if actual < 0 || actual > fields.max_amount_sats {
        return Err(Zk402Error::AmountMismatch);
    }

    // 4. The atomic advance: monotone cumulative (replay guard) + the
    //    hard cap on both the signed ceiling and the metered usage.
    let res = sqlx::query(
        "UPDATE zk402_authorizations \
         SET authorized_cumulative_sats = $2, \
             metered_amount_sats = metered_amount_sats + $3, \
             channel_mode = 'metering', \
             updated_at = now() \
         WHERE id = $1 \
           AND status = 'active' \
           AND $2 > authorized_cumulative_sats \
           AND $2 <= authorized_amount_sats \
           AND metered_amount_sats + $3 <= authorized_amount_sats",
    )
    .bind(&fields.channel_id)
    .bind(fields.cumulative_authorized_sats)
    .bind(actual)
    .execute(pool)
    .await
    .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    if res.rows_affected() != 1 {
        // Non-monotone cumulative (replay) or cap breach — one code, the
        // caller cannot distinguish race-loser from overspend by design.
        return Err(Zk402Error::AuthorizationLimitExceeded);
    }

    // 5. Append the usage ledger rows (the meter's source of truth).
    for u in usage {
        sqlx::query(
            "INSERT INTO zk402_usage_events \
             (channel_id, voucher_seq, unit, quantity, unit_price_microsats, \
              cost_sats, model, request_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&fields.channel_id)
        .bind(fields.voucher_seq)
        .bind(&u.unit)
        .bind(u.quantity)
        .bind(u.unit_price_microsats)
        .bind(cost_sats(u.quantity, u.unit_price_microsats))
        .bind(u.model.as_deref())
        .bind(&fields.request_hash)
        .execute(pool)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    }

    let (metered, cumulative): (i64, i64) = sqlx::query_as(
        "SELECT metered_amount_sats, authorized_cumulative_sats \
         FROM zk402_authorizations WHERE id = $1",
    )
    .bind(&fields.channel_id)
    .fetch_one(pool)
    .await
    .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;

    Ok(MeterOutcome {
        actual_cost_sats: actual,
        unspent_sats: fields.max_amount_sats - actual,
        metered_total_sats: metered,
        cumulative_authorized_sats: cumulative,
    })
}

/// Channel meter state (dashboard / settlement view).
pub async fn channel_meter(pool: &PgPool, channel_id: &str) -> Result<(i64, i64, i64), Zk402Error> {
    let row: (i64, i64, i64) = sqlx::query_as(
        "SELECT metered_amount_sats, authorized_cumulative_sats, authorized_amount_sats \
         FROM zk402_authorizations WHERE id = $1",
    )
    .bind(channel_id)
    .fetch_one(pool)
    .await
    .map_err(|_| Zk402Error::AuthorizationNotFound)?;
    Ok(row)
}

/// Ledger consistency: sum of a channel's usage events.
pub async fn usage_total(pool: &PgPool, channel_id: &str) -> Result<i64, Zk402Error> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(cost_sats), 0)::bigint FROM zk402_usage_events WHERE channel_id = $1",
    )
    .bind(channel_id)
    .fetch_one(pool)
    .await
    .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    Ok(total)
}
