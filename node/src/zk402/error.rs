//! Structured ZK402 failure codes — the closed set from
//! `specs/x402-zkcoins-publisher-scheme.md` ("Failure Codes"). Wire
//! responses carry the snake_case `code()`; the enum keeps call sites
//! exhaustive so a new failure mode is a compile-time event, not a
//! stringly-typed drift.

/// One ZK402 failure code. `code()` is the wire string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zk402Error {
    UnsupportedScheme,
    UnsupportedNetwork,
    InvalidPayload,
    InvalidSignature,
    ExpiredPayment,
    NotYetValid,
    AmountMismatch,
    ResourceMismatch,
    RequestMismatch,
    ReplayDetected,
    AuthorizationNotFound,
    AuthorizationRevoked,
    AuthorizationLimitExceeded,
    PublisherAcceptanceFailed,
    InsufficientAccountBalance,
    MerchantNotFound,
    MerchantDisabled,
    SettlementQueueUnavailable,
    PublisherUnfunded,
    ProverUnavailable,
}

impl Zk402Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedScheme => "unsupported_scheme",
            Self::UnsupportedNetwork => "unsupported_network",
            Self::InvalidPayload => "invalid_payload",
            Self::InvalidSignature => "invalid_signature",
            Self::ExpiredPayment => "expired_payment",
            Self::NotYetValid => "not_yet_valid",
            Self::AmountMismatch => "amount_mismatch",
            Self::ResourceMismatch => "resource_mismatch",
            Self::RequestMismatch => "request_mismatch",
            Self::ReplayDetected => "replay_detected",
            Self::AuthorizationNotFound => "authorization_not_found",
            Self::AuthorizationRevoked => "authorization_revoked",
            Self::AuthorizationLimitExceeded => "authorization_limit_exceeded",
            Self::PublisherAcceptanceFailed => "publisher_acceptance_failed",
            Self::InsufficientAccountBalance => "insufficient_account_balance",
            Self::MerchantNotFound => "merchant_not_found",
            Self::MerchantDisabled => "merchant_disabled",
            Self::SettlementQueueUnavailable => "settlement_queue_unavailable",
            Self::PublisherUnfunded => "publisher_unfunded",
            Self::ProverUnavailable => "prover_unavailable",
        }
    }

    /// Every code, for exhaustive wire-format tests.
    pub const ALL: &'static [Self] = &[
        Self::UnsupportedScheme,
        Self::UnsupportedNetwork,
        Self::InvalidPayload,
        Self::InvalidSignature,
        Self::ExpiredPayment,
        Self::NotYetValid,
        Self::AmountMismatch,
        Self::ResourceMismatch,
        Self::RequestMismatch,
        Self::ReplayDetected,
        Self::AuthorizationNotFound,
        Self::AuthorizationRevoked,
        Self::AuthorizationLimitExceeded,
        Self::PublisherAcceptanceFailed,
        Self::InsufficientAccountBalance,
        Self::MerchantNotFound,
        Self::MerchantDisabled,
        Self::SettlementQueueUnavailable,
        Self::PublisherUnfunded,
        Self::ProverUnavailable,
    ];
}

impl std::fmt::Display for Zk402Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Zk402Error {}
