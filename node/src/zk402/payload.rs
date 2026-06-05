//! Parsing + validation of the `PAYMENT-SIGNATURE` payload (Step 2).
//!
//! The wire object (`specs/wire-format.md`) nests an `accepted` block
//! (scheme/network/amount/payTo/extra) and a `payload` block (the signed
//! voucher fields). This module turns the decoded JSON into a typed
//! [`ParsedPayment`], exposes the [`VoucherFields`] needed to rebuild the
//! canonical signed message, and runs the structural + temporal
//! `verify`-time checks, returning a structured [`Zk402Error`].
//!
//! It does NOT do the cryptographic, replay, merchant, or
//! authorization checks — those need the signature verifier
//! ([`super::signature`]) and the DB ([`super::store`]) and are wired in
//! Step 3.

use serde_json::Value;

use super::canonical::VoucherFields;
use super::error::Zk402Error;

const SCHEME: &str = "zkcoins-publisher";
const ASSET: &str = "btc-sats";
const SIGNATURE_SCHEME: &str = "bip340-schnorr";

/// Networks ZK402 accepts. Testnet only — `zkcoins:mainnet` is
/// deliberately absent (no mainnet default, `prompts/00-master-context`).
pub const SUPPORTED_NETWORKS: &[&str] = &["zkcoins:regtest", "zkcoins:mutinynet", "zkcoins:signet"];

const ACCESS_THRESHOLDS: &[&str] = &[
    "publisher_accepted",
    "published",
    "confirmed",
    "final",
    "verified_only",
];

/// Typed, validated-shape view of a `PAYMENT-SIGNATURE` payload.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedPayment {
    pub scheme: String,
    pub network: String,
    pub mode: String,
    pub facilitator: String,
    pub access_threshold: String,
    pub intent_id: String,
    pub authorization_id: Option<String>,
    pub voucher_id: String,
    pub payer: String,
    pub merchant: String,
    pub amount_sats: i64,
    pub fee_amount_sats: i64,
    pub asset: String,
    pub resource_hash: String,
    pub request_hash: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub nonce: String,
    pub signature_scheme: String,
    pub signature: String,
}

fn get_str(v: &Value, key: &str) -> Result<String, Zk402Error> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Zk402Error::InvalidPayload)
}

/// Parse a stringly-typed integer field (amounts/timestamps are JSON
/// strings on the wire, e.g. `"25"`). A non-numeric value is malformed.
fn get_int(v: &Value, key: &str) -> Result<i64, Zk402Error> {
    get_str(v, key)?
        .parse::<i64>()
        .map_err(|_| Zk402Error::InvalidPayload)
}

impl ParsedPayment {
    /// Parse the decoded `PAYMENT-SIGNATURE` object (the `decoded` body:
    /// `{ accepted: {.., extra}, payload: {..} }`).
    pub fn from_decoded(decoded: &Value) -> Result<Self, Zk402Error> {
        let accepted = decoded.get("accepted").ok_or(Zk402Error::InvalidPayload)?;
        let extra = accepted.get("extra").ok_or(Zk402Error::InvalidPayload)?;
        let payload = decoded.get("payload").ok_or(Zk402Error::InvalidPayload)?;

        let authorization_id = match payload.get("authorizationId") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(Zk402Error::InvalidPayload),
        };

        Ok(Self {
            scheme: get_str(accepted, "scheme")?,
            network: get_str(accepted, "network")?,
            mode: get_str(extra, "mode")?,
            facilitator: get_str(extra, "facilitator")?,
            access_threshold: get_str(extra, "accessThreshold")?,
            intent_id: get_str(payload, "intentId")?,
            authorization_id,
            voucher_id: get_str(payload, "voucherId")?,
            payer: get_str(payload, "payer")?,
            merchant: get_str(payload, "merchant")?,
            amount_sats: get_int(payload, "amount")?,
            fee_amount_sats: get_int(payload, "feeAmount")?,
            asset: get_str(payload, "asset")?,
            resource_hash: get_str(payload, "resourceHash")?,
            request_hash: get_str(payload, "requestHash")?,
            valid_after: get_int(payload, "validAfter")?,
            valid_before: get_int(payload, "validBefore")?,
            nonce: get_str(payload, "nonce")?,
            signature_scheme: get_str(payload, "signatureScheme")?,
            signature: get_str(payload, "signature")?,
        })
    }

    /// The canonical-message field view (the exact bytes the wallet signs).
    pub fn voucher_fields(&self) -> VoucherFields {
        VoucherFields {
            network: self.network.clone(),
            mode: self.mode.clone(),
            intent_id: self.intent_id.clone(),
            authorization_id: self.authorization_id.clone(),
            voucher_id: self.voucher_id.clone(),
            payer: self.payer.clone(),
            merchant: self.merchant.clone(),
            amount_sats: self.amount_sats,
            fee_amount_sats: self.fee_amount_sats,
            resource_hash: self.resource_hash.clone(),
            request_hash: self.request_hash.clone(),
            valid_after: self.valid_after,
            valid_before: self.valid_before,
            nonce: self.nonce.clone(),
            facilitator: self.facilitator.clone(),
            access_threshold: self.access_threshold.clone(),
        }
    }

    /// Structural + temporal validation (the non-cryptographic half of
    /// `verify`). `now` is unix seconds (injected so tests are
    /// deterministic). Does NOT verify the signature, replay, merchant,
    /// or authorization — those land in Step 3.
    pub fn validate(&self, now: i64) -> Result<(), Zk402Error> {
        if self.scheme != SCHEME {
            return Err(Zk402Error::UnsupportedScheme);
        }
        if !SUPPORTED_NETWORKS.contains(&self.network.as_str()) {
            return Err(Zk402Error::UnsupportedNetwork);
        }
        if self.asset != ASSET || self.signature_scheme != SIGNATURE_SCHEME {
            return Err(Zk402Error::InvalidPayload);
        }
        if self.amount_sats <= 0 || self.fee_amount_sats < 0 {
            return Err(Zk402Error::InvalidPayload);
        }
        if self.nonce.is_empty() || !ACCESS_THRESHOLDS.contains(&self.access_threshold.as_str()) {
            return Err(Zk402Error::InvalidPayload);
        }
        // `verified_only` must never gate value on a non-test network.
        if self.access_threshold == "verified_only" && self.network == "zkcoins:mainnet" {
            return Err(Zk402Error::InvalidPayload);
        }
        if self.valid_before <= self.valid_after {
            return Err(Zk402Error::InvalidPayload);
        }
        if now < self.valid_after {
            return Err(Zk402Error::NotYetValid);
        }
        if now > self.valid_before {
            return Err(Zk402Error::ExpiredPayment);
        }
        Ok(())
    }

    /// Cross-check the signed payload against the `accepted` requirement
    /// the resource server advertised (amount + resource binding). A
    /// mismatch means the buyer signed something other than what was
    /// quoted.
    pub fn check_against_accepted(
        &self,
        accepted_amount_sats: i64,
        accepted_resource_hash: &str,
    ) -> Result<(), Zk402Error> {
        if self.amount_sats != accepted_amount_sats {
            return Err(Zk402Error::AmountMismatch);
        }
        if self.resource_hash != accepted_resource_hash {
            return Err(Zk402Error::ResourceMismatch);
        }
        Ok(())
    }
}
