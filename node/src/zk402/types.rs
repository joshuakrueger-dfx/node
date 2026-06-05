//! ZK402 domain types — in-memory views of the `zk402_*` rows
//! (migration 0015).
//!
//! Conventions:
//!
//! * Status-like columns are `TEXT` + `CHECK` in Postgres; here they are
//!   real Rust enums with a fallible [`std::str::FromStr`] and an
//!   infallible `as_str()`. The DB `CHECK` and the enum variants must
//!   stay in lock-step — the round-trip tests in `zk402/tests.rs` pin
//!   both directions.
//! * Amounts are `i64` sats (`BIGINT`), timestamps are
//!   `chrono::DateTime<Utc>` (`TIMESTAMPTZ`), JSONB is
//!   `serde_json::Value` — same mapping the `jobs` table uses.
//! * There is intentionally NO type here that models a buyer deposit,
//!   session treasury, or operator-held merchant payout balance
//!   (non-custodial hard rule, prompts/00-master-context.md).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Error for parsing a `TEXT` enum column into its Rust enum. Carries
/// the offending value so a constraint drift between the migration
/// `CHECK` and the enum surfaces with context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEnumError {
    pub kind: &'static str,
    pub value: String,
}

impl std::fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid {} value: {:?}", self.kind, self.value)
    }
}

impl std::error::Error for ParseEnumError {}

/// Declares a string-backed enum with `as_str()` + `FromStr`, keeping
/// the variant↔string table in one place per enum.
macro_rules! zk402_str_enum {
    ($(#[$doc:meta])* $name:ident { $($variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $s),+
                }
            }

            /// Every variant, for exhaustive round-trip tests against
            /// the migration's `CHECK` constraint.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
        }

        impl std::str::FromStr for $name {
            type Err = ParseEnumError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($s => Ok(Self::$variant),)+
                    other => Err(ParseEnumError {
                        kind: stringify!($name),
                        value: other.to_owned(),
                    }),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

zk402_str_enum! {
    /// `zk402_merchants.status`.
    MerchantStatus {
        Active => "active",
        Disabled => "disabled",
        Suspended => "suspended",
    }
}

zk402_str_enum! {
    /// `zk402_authorizations.status`.
    AuthorizationStatus {
        Pending => "pending",
        Active => "active",
        Revoking => "revoking",
        Revoked => "revoked",
        Expired => "expired",
        Failed => "failed",
    }
}

zk402_str_enum! {
    /// `zk402_payment_intents.status` — the authoritative settlement
    /// state list (specs/x402-zkcoins-publisher-scheme.md).
    PaymentIntentStatus {
        Received => "received",
        Verified => "verified",
        Authorized => "authorized",
        PublisherAccepted => "publisher_accepted",
        Queued => "queued",
        Batching => "batching",
        Settling => "settling",
        Published => "published",
        Confirmed => "confirmed",
        Final => "final",
        Expired => "expired",
        FailedRecoverable => "failed_recoverable",
        FailedTerminal => "failed_terminal",
        Reorged => "reorged",
        Reversed => "reversed",
    }
}

zk402_str_enum! {
    /// `zk402_payment_intents.access_threshold` — the buyer-signed
    /// finality required before paid access. `VerifiedOnly` exists for
    /// demo flows only and must never gate value on mainnet.
    AccessThreshold {
        PublisherAccepted => "publisher_accepted",
        Published => "published",
        Confirmed => "confirmed",
        Final => "final",
        VerifiedOnly => "verified_only",
    }
}

zk402_str_enum! {
    /// `zk402_batches.status`. No `confirmed` — `observed` is the
    /// batch-level equivalent.
    BatchStatus {
        Open => "open",
        Locked => "locked",
        ProofGenerating => "proof_generating",
        ReadyToPublish => "ready_to_publish",
        Publishing => "publishing",
        Published => "published",
        Observed => "observed",
        Final => "final",
        FailedRecoverable => "failed_recoverable",
        FailedTerminal => "failed_terminal",
        Reorged => "reorged",
    }
}

zk402_str_enum! {
    /// `zk402_merchant_settlements.kind`.
    SettlementKind {
        Accepted => "accepted",
        Published => "published",
        Confirmed => "confirmed",
        Final => "final",
        Fee => "fee",
        Reversal => "reversal",
    }
}

zk402_str_enum! {
    /// `zk402_merchant_settlements.status`. Entries are append-only
    /// after `posted`.
    SettlementStatus {
        Pending => "pending",
        Posted => "posted",
        Reversed => "reversed",
    }
}

/// In-memory view of a `zk402_merchants` row.
#[derive(Debug, Clone, PartialEq)]
pub struct Merchant {
    pub id: String,
    pub display_name: String,
    pub settlement_address: String,
    pub settlement_address_verified_at: Option<DateTime<Utc>>,
    pub pending_settlement_address: Option<String>,
    pub pending_settlement_address_effective_at: Option<DateTime<Utc>>,
    pub address_change_delay_seconds: i32,
    pub username: Option<String>,
    pub status: MerchantStatus,
    pub fee_bps: i32,
    pub fixed_fee_sats: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert shape for a merchant (DB fills the timestamps).
#[derive(Debug, Clone)]
pub struct NewMerchant {
    pub id: String,
    pub display_name: String,
    pub settlement_address: String,
    pub username: Option<String>,
    pub status: MerchantStatus,
    pub fee_bps: i32,
    pub fixed_fee_sats: i64,
}

/// In-memory view of a `zk402_authorizations` row. The
/// `accepted_amount_sats` / `published_amount_sats` totals track spend
/// against the buyer-signed cap — they are cap accounting, not an
/// operator-held balance.
#[derive(Debug, Clone, PartialEq)]
pub struct Authorization {
    pub id: String,
    pub payer: String,
    pub network: String,
    pub asset: String,
    pub authorized_amount_sats: i64,
    pub accepted_amount_sats: i64,
    pub published_amount_sats: i64,
    pub status: AuthorizationStatus,
    pub valid_after: DateTime<Utc>,
    pub valid_before: DateTime<Utc>,
    pub spend_limit_per_request_sats: Option<i64>,
    pub spend_limit_total_sats: Option<i64>,
    pub allowed_merchants: serde_json::Value,
    pub facilitator_origin: String,
    pub session_public_key: Option<String>,
    pub authorization_signature: String,
    pub publisher_acceptance_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert shape for an authorization.
#[derive(Debug, Clone)]
pub struct NewAuthorization {
    pub id: String,
    pub payer: String,
    pub network: String,
    pub asset: String,
    pub authorized_amount_sats: i64,
    pub status: AuthorizationStatus,
    pub valid_after: DateTime<Utc>,
    pub valid_before: DateTime<Utc>,
    pub spend_limit_per_request_sats: Option<i64>,
    pub spend_limit_total_sats: Option<i64>,
    pub allowed_merchants: serde_json::Value,
    pub facilitator_origin: String,
    pub session_public_key: Option<String>,
    pub authorization_signature: String,
}

/// In-memory view of a `zk402_payment_intents` row.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentIntent {
    pub id: String,
    pub voucher_id: String,
    pub authorization_id: Option<String>,
    pub payer: String,
    pub merchant_id: String,
    pub network: String,
    pub asset: String,
    pub amount_sats: i64,
    pub fee_amount_sats: i64,
    pub resource_hash: String,
    pub request_hash: String,
    pub nonce: String,
    pub valid_after: DateTime<Utc>,
    pub valid_before: DateTime<Utc>,
    pub canonical_message: String,
    pub signature_scheme: String,
    pub signature: String,
    pub status: PaymentIntentStatus,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub access_threshold: AccessThreshold,
    pub publisher_acceptance_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert shape for a payment intent — exactly the fields the buyer's
/// signed voucher pins plus the facilitator bookkeeping ids. Milestone
/// timestamps are NOT here: they are written by status transitions.
#[derive(Debug, Clone)]
pub struct NewPaymentIntent {
    pub id: String,
    pub voucher_id: String,
    pub authorization_id: Option<String>,
    pub payer: String,
    pub merchant_id: String,
    pub network: String,
    pub asset: String,
    pub amount_sats: i64,
    pub fee_amount_sats: i64,
    pub resource_hash: String,
    pub request_hash: String,
    pub nonce: String,
    pub valid_after: DateTime<Utc>,
    pub valid_before: DateTime<Utc>,
    pub canonical_message: String,
    pub signature_scheme: String,
    pub signature: String,
    pub status: PaymentIntentStatus,
    pub access_threshold: AccessThreshold,
}

/// In-memory view of a `zk402_receipts` row.
#[derive(Debug, Clone, PartialEq)]
pub struct Receipt {
    pub id: String,
    pub payment_intent_id: String,
    pub status: String,
    pub receipt_json: serde_json::Value,
    pub facilitator_signature: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// In-memory view of a `zk402_batches` row.
#[derive(Debug, Clone, PartialEq)]
pub struct Batch {
    pub id: String,
    pub network: String,
    pub merchant_id: Option<String>,
    pub status: BatchStatus,
    pub gross_amount_sats: i64,
    pub fee_amount_sats: i64,
    pub net_amount_sats: i64,
    pub intent_count: i32,
    pub zkcoins_proof_id: Option<String>,
    pub commit_txid: Option<String>,
    pub reveal_txid: Option<String>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub retry_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insert shape for a `zk402_batches` row. The amount totals,
/// `intent_count`, `retry_count` and milestone timestamps all default at
/// the database and are advanced later by the batch state machine.
#[derive(Debug, Clone)]
pub struct NewBatch {
    pub id: String,
    pub network: String,
    pub merchant_id: Option<String>,
    pub status: BatchStatus,
}

/// In-memory view of a `zk402_batch_items` row.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchItem {
    pub batch_id: String,
    pub payment_intent_id: String,
    pub amount_sats: i64,
    pub fee_sats: i64,
    pub net_sats: i64,
}

/// In-memory view of a `zk402_merchant_settlements` row — one immutable
/// entry in the merchant's append-only settlement ledger.
#[derive(Debug, Clone, PartialEq)]
pub struct MerchantSettlement {
    pub id: String,
    pub merchant_id: String,
    pub payment_intent_id: Option<String>,
    pub batch_id: Option<String>,
    pub kind: SettlementKind,
    pub amount_sats: i64,
    pub status: SettlementStatus,
    pub created_at: DateTime<Utc>,
}

/// Insert shape for a `zk402_merchant_settlements` row. `created_at` is
/// stamped by the database; entries are immutable after `posted`.
#[derive(Debug, Clone)]
pub struct NewMerchantSettlement {
    pub id: String,
    pub merchant_id: String,
    pub payment_intent_id: Option<String>,
    pub batch_id: Option<String>,
    pub kind: SettlementKind,
    pub amount_sats: i64,
    pub status: SettlementStatus,
}

/// In-memory view of a `zk402_audit_events` row (`id` is the
/// `BIGSERIAL` the database assigned on insert).
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEvent {
    pub id: i64,
    pub actor: String,
    pub entity_type: String,
    pub entity_id: String,
    pub event_type: String,
    pub event_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Insert shape for a `zk402_audit_events` row. Mirrors the
/// `db::RequestLogEntry` pattern: plain owned fields, built by the
/// caller (or via [`super::store::audit_event`]), shipped to the insert
/// helper (awaited when the event must land before responding, or
/// `tokio::spawn`ed fire-and-forget).
#[derive(Debug, Clone)]
pub struct NewAuditEvent {
    pub actor: String,
    pub entity_type: String,
    pub entity_id: String,
    pub event_type: String,
    pub event_json: serde_json::Value,
}
