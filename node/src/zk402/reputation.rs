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
//! * `settled_count` — intents the publisher ACCEPTED (status at/past
//!   `publisher_accepted`); this is acceptance, not on-chain finality,
//! * `distinct_payers` — distinct payer keys among those (the anti-wash
//!   confidence driver),
//! * `finalized_count` — intents that reached `published`/`confirmed`/
//!   `final` (on-chain finality), surfaced separately,
//! * `failed_count` / `reversed_count` — terminal failures + reversals,
//! * volume (total + trailing 30 days, sats),
//! * median settle latency (created → earliest settlement milestone, ms),
//! * `score` — see [`score`]: success-rate damped by a **distinct-payer**
//!   confidence term so a fresh service starts NEUTRAL (50) and a service
//!   wash-settling from one key cannot exceed ~59 — confidence rewards
//!   counterparty DIVERSITY, not self-dealt volume (design decision D-A2).
//!   This is the actual anti-sybil mechanism; raw settle count is NOT a
//!   moat (one key can mint many cheap self-payments). Stronger
//!   sat-weighted / dispute-aware scoring is a Phase-1 item.

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
    /// Payments the publisher accepted (status at/past `publisher_accepted`).
    /// "Settled" here means *accepted*, NOT on-chain final — see
    /// `finalized_count` for finality.
    pub settled_count: i64,
    /// DISTINCT payer keys among accepted payments. This — not raw
    /// settle count — drives the score's confidence, so wash-settling
    /// from a single key cannot buy a high score (see [`score`]).
    pub distinct_payers: i64,
    /// Payments that reached an on-chain-proven finality state
    /// (`published`/`confirmed`/`final`). Surfaced separately so an agent
    /// can see how much of the accepted volume actually finalized.
    pub finalized_count: i64,
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

/// Distinct counterparties at which the confidence term saturates. A
/// service must transact with this many DISTINCT payers to earn full
/// confidence — the anti-wash bar (a single key farming N settles yields
/// only one distinct payer).
pub const CONFIDENCE_SATURATION_PAYERS: f64 = 20.0;

/// The v1 scoring function — small, documented, deterministic:
///
/// ```text
/// success_rate = settled / (settled + failed + reversed)        (1.0 if no history)
/// confidence   = ln(1 + distinct_payers) / ln(1 + 20)           (clamped to 1)
/// score        = round(100 * success_rate * (0.5 + 0.5 * confidence))
/// ```
///
/// Properties: a service with no history scores 50 (neutral). Confidence
/// is driven by the number of DISTINCT payers, not raw settle volume, so
/// wash-settling from one key cannot lift the score past ~59 no matter how
/// many self-payments are made — diversity, not volume, is what the score
/// rewards. Failures/reversals pull `success_rate` (and thus the score)
/// down immediately. `success_rate` is over *accepted* payments
/// (publisher-acceptance), not on-chain finality; finality is surfaced
/// separately as `finalized_count`, and weighting the score on it is a
/// Phase-1 item once real settlement lands.
pub fn score(signals: &ReputationSignals) -> (i64, f64) {
    let denom = signals.settled_count + signals.failed_count + signals.reversed_count;
    let success_rate = if denom == 0 {
        1.0
    } else {
        signals.settled_count as f64 / denom as f64
    };
    let confidence = ((1.0 + signals.distinct_payers as f64).ln()
        / (1.0 + CONFIDENCE_SATURATION_PAYERS).ln())
    .clamp(0.0, 1.0);
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
/// Latency/first-settled derive from a COALESCED settlement timestamp
/// (the earliest finality milestone the payment reached, falling back to
/// publisher-acceptance) over the SAME accepted-row set as `settled_count`,
/// so they do not silently under-report payments that finalized without a
/// stamped `publisher_accepted_at`. Latency is clamped to `>= 0`: that
/// timestamp is second-truncated while `created_at` is microsecond `now()`,
/// so a sub-second settle can read fractionally negative — clamp instead of
/// reporting nonsense to ranking agents.
pub async fn signals_for_resources(
    pool: &PgPool,
    resource_hashes: &[String],
) -> Result<HashMap<String, ReputationSignals>, sqlx::Error> {
    if resource_hashes.is_empty() {
        return Ok(HashMap::new());
    }
    let settled = settled_in_list();
    // The COALESCED settlement instant: earliest finality milestone, else
    // publisher-acceptance. NULL only for an accepted row with no milestone
    // stamped at all.
    let settled_at = "COALESCE(final_at, confirmed_at, published_at, publisher_accepted_at)";
    let rows = sqlx::query(&format!(
        "SELECT resource_hash, \
            COUNT(*) FILTER (WHERE status IN ({settled})) AS settled_count, \
            COUNT(DISTINCT payer) FILTER (WHERE status IN ({settled})) AS distinct_payers, \
            COUNT(*) FILTER (WHERE status IN ('published','confirmed','final')) AS finalized_count, \
            COUNT(*) FILTER (WHERE status = 'failed_terminal') AS failed_count, \
            COUNT(*) FILTER (WHERE status = 'reversed') AS reversed_count, \
            COALESCE(SUM(amount_sats) FILTER (WHERE status IN ({settled})), 0)::bigint \
                AS volume_sats, \
            COALESCE(SUM(amount_sats) FILTER (WHERE status IN ({settled}) \
                AND created_at > now() - interval '30 days'), 0)::bigint \
                AS volume_30d_sats, \
            percentile_cont(0.5) WITHIN GROUP (ORDER BY \
                GREATEST(0, EXTRACT(EPOCH FROM ({settled_at} - created_at)) * 1000.0)) \
                FILTER (WHERE status IN ({settled}) AND {settled_at} IS NOT NULL) \
                AS median_settle_latency_ms, \
            MIN({settled_at}) FILTER (WHERE status IN ({settled})) AS first_settled_at \
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
                distinct_payers: r.try_get("distinct_payers")?,
                finalized_count: r.try_get("finalized_count")?,
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
        "distinctPayers": rep.signals.distinct_payers,
        "finalizedCount": rep.signals.finalized_count,
        "failedCount": rep.signals.failed_count,
        "reversedCount": rep.signals.reversed_count,
        "volumeSats": rep.signals.volume_sats.to_string(),
        "volume30dSats": rep.signals.volume_30d_sats.to_string(),
        "medianSettleLatencyMs": rep.signals.median_settle_latency_ms,
        "firstSettledAt": rep.signals.first_settled_at.map(|t| t.to_rfc3339()),
        "asOf": as_of.to_rfc3339(),
        "settledMeans": "publisher-accepted (not on-chain final); see finalizedCount",
        "derivedFrom": "zk402_payment_intents (signed vouchers + receipts); recomputable, never stored",
    })
}
