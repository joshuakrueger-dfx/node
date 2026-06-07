//! ZK402 Agent Economy — Layer 4 (v1): seller reputation as a
//! **recomputable read model** over already-signed artifacts.
//!
//! Reputation here is a deterministic function of the service's payment
//! history (`zk402_payment_intents`, keyed by `resource_hash` — the value
//! every buyer voucher binds), never a stored mutable score and never
//! writable by the merchant (proposals/AGENT_ECONOMY_design.md, Layer 4).
//! Because each underlying settle carries a buyer BIP-340 signature and
//! an Ed25519 facilitator receipt, anyone can recompute and audit these
//! numbers offline; v1 intentionally has NO snapshot table — derived
//! state stays derived.
//!
//! v1 signals (disputes land in Phase 1 and will add `dispute_rate`):
//!
//! * `settled_count` — intents at/past `publisher_accepted`,
//! * `failed_count` / `reversed_count` — terminal failures + reversals,
//! * volume (total + trailing 30 days, sats),
//! * median settle latency (created → publisher_accepted, ms),
//! * `score` — see [`score`]: success-rate damped by a volume-confidence
//!   term so a fresh, history-less service starts NEUTRAL (50), not
//!   perfect. Wash-settling your own service to inflate the score costs
//!   real settlements (the natural sybil tax, design decision D-A2).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

/// Statuses that count as a successful settle: at or past publisher
/// acceptance. Must stay a subset of `PaymentIntentStatus::ALL`
/// (lock-step pinned in `reputation_tests`).
pub const SETTLED_STATUSES: &[&str] = &[
    "publisher_accepted",
    "queued",
    "batching",
    "settling",
    "published",
    "confirmed",
    "final",
];

/// Raw aggregates for one service (one `resource_hash`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReputationSignals {
    pub settled_count: i64,
    pub failed_count: i64,
    pub reversed_count: i64,
    pub volume_sats: i64,
    pub volume_30d_sats: i64,
    pub median_settle_latency_ms: Option<f64>,
    pub first_settled_at: Option<DateTime<Utc>>,
}

/// Derived reputation: the deterministic score + its inputs.
#[derive(Debug, Clone, PartialEq)]
pub struct Reputation {
    pub score: i64,
    pub success_rate: f64,
    pub signals: ReputationSignals,
}

/// The v1 scoring function — small, documented, deterministic:
///
/// ```text
/// success_rate = settled / (settled + failed + reversed)   (1.0 if no history)
/// confidence   = ln(1 + settled) / ln(1 + 50)              (capped at 1)
/// score        = round(100 * success_rate * (0.5 + 0.5 * confidence))
/// ```
///
/// Properties: a service with no history scores 50 (neutral); a clean
/// record saturates toward 100 at ~50 settlements; failures pull the
/// rate (and thus the score) down immediately.
pub fn score(signals: &ReputationSignals) -> (i64, f64) {
    let denom = signals.settled_count + signals.failed_count + signals.reversed_count;
    let success_rate = if denom == 0 {
        1.0
    } else {
        signals.settled_count as f64 / denom as f64
    };
    let confidence = ((1.0 + signals.settled_count as f64).ln() / (51.0f64).ln()).clamp(0.0, 1.0);
    let score = (100.0 * success_rate * (0.5 + 0.5 * confidence)).round() as i64;
    (score, success_rate)
}

/// Compute reputation from raw signals.
pub fn from_signals(signals: ReputationSignals) -> Reputation {
    let (score, success_rate) = score(&signals);
    Reputation {
        score,
        success_rate,
        signals,
    }
}

fn settled_in_list() -> String {
    SETTLED_STATUSES
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One aggregate query for a set of services (batch — no N+1 in the
/// discovery page): signals grouped by `resource_hash`. Hashes with no
/// payment history are simply absent (callers default to
/// `ReputationSignals::default()`).
///
/// Latency is clamped to `>= 0`: `publisher_accepted_at` is stamped from
/// the handler's second-truncated clock while `created_at` is the DB's
/// microsecond `now()`, so a sub-second settle can read fractionally
/// negative — clamp instead of reporting nonsense to ranking agents.
pub async fn signals_for_resources(
    pool: &PgPool,
    resource_hashes: &[String],
) -> Result<HashMap<String, ReputationSignals>, sqlx::Error> {
    if resource_hashes.is_empty() {
        return Ok(HashMap::new());
    }
    let settled = settled_in_list();
    let rows = sqlx::query(&format!(
        "SELECT resource_hash, \
            COUNT(*) FILTER (WHERE status IN ({settled})) AS settled_count, \
            COUNT(*) FILTER (WHERE status = 'failed_terminal') AS failed_count, \
            COUNT(*) FILTER (WHERE status = 'reversed') AS reversed_count, \
            COALESCE(SUM(amount_sats) FILTER (WHERE status IN ({settled})), 0)::bigint \
                AS volume_sats, \
            COALESCE(SUM(amount_sats) FILTER (WHERE status IN ({settled}) \
                AND created_at > now() - interval '30 days'), 0)::bigint \
                AS volume_30d_sats, \
            percentile_cont(0.5) WITHIN GROUP (ORDER BY \
                GREATEST(0, EXTRACT(EPOCH FROM (publisher_accepted_at - created_at)) * 1000.0)) \
                FILTER (WHERE publisher_accepted_at IS NOT NULL) \
                AS median_settle_latency_ms, \
            MIN(publisher_accepted_at) AS first_settled_at \
         FROM zk402_payment_intents \
         WHERE resource_hash = ANY($1) \
         GROUP BY resource_hash"
    ))
    .bind(resource_hashes)
    .fetch_all(pool)
    .await?;
    let mut out = HashMap::with_capacity(rows.len());
    for r in rows {
        let hash: String = r.try_get("resource_hash")?;
        out.insert(
            hash,
            ReputationSignals {
                settled_count: r.try_get("settled_count")?,
                failed_count: r.try_get("failed_count")?,
                reversed_count: r.try_get("reversed_count")?,
                volume_sats: r.try_get("volume_sats")?,
                volume_30d_sats: r.try_get("volume_30d_sats")?,
                median_settle_latency_ms: r.try_get("median_settle_latency_ms")?,
                first_settled_at: r.try_get("first_settled_at")?,
            },
        );
    }
    Ok(out)
}

/// Reputation for a single service.
pub async fn for_resource(pool: &PgPool, resource_hash: &str) -> Result<Reputation, sqlx::Error> {
    let mut map = signals_for_resources(pool, &[resource_hash.to_owned()]).await?;
    Ok(from_signals(map.remove(resource_hash).unwrap_or_default()))
}

/// The wire shape embedded in discovery metadata and served by
/// `GET /api/zk402/services/:id/reputation`. Read-only, derived.
pub fn reputation_json(rep: &Reputation, as_of: DateTime<Utc>) -> Value {
    json!({
        "score": rep.score,
        "successRate": rep.success_rate,
        "settledCount": rep.signals.settled_count,
        "failedCount": rep.signals.failed_count,
        "reversedCount": rep.signals.reversed_count,
        "volumeSats": rep.signals.volume_sats.to_string(),
        "volume30dSats": rep.signals.volume_30d_sats.to_string(),
        "medianSettleLatencyMs": rep.signals.median_settle_latency_ms,
        "firstSettledAt": rep.signals.first_settled_at.map(|t| t.to_rfc3339()),
        "asOf": as_of.to_rfc3339(),
        "derivedFrom": "zk402_payment_intents (signed vouchers + receipts); recomputable, never stored",
    })
}
