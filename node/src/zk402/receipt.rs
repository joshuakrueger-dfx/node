//! Ed25519-signed facilitator receipts (Step 3).
//!
//! Spec: `specs/receipt-signatures.md` + `fixtures/receipt-vector.json`.
//! The receipt is signed ONCE at issuance over a canonical JSON form:
//! UTF-8, keys sorted lexicographically, no insignificant whitespace,
//! monetary values as strings, RFC-3339 UTC timestamps, null fields
//! omitted, and the `signature` field excluded from the signed bytes.
//!
//! serde_json's map ordering is feature-dependent (`preserve_order`
//! is unioned across the workspace), so the canonical form is emitted
//! by a small deterministic serializer over an explicit sorted field
//! list instead of trusting `Map` iteration order.
//!
//! Ed25519 signing is deterministic, which the fixture exploits: the
//! tests load the fixture's PKCS8 key, re-sign the canonical bytes, and
//! must reproduce the fixture's exact signature.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use super::error::Zk402Error;

/// The unsigned receipt body. All fields land in the canonical JSON in
/// sorted-key order; `authorization_id = None` is omitted (never
/// serialized as null).
#[derive(Debug, Clone, PartialEq)]
pub struct ReceiptBody {
    pub receipt_id: String,
    pub network: String,
    pub mode: String,
    pub status: String,
    pub settlement_state: String,
    pub access_threshold: String,
    pub payer: String,
    pub merchant: String,
    pub amount_sats: i64,
    pub fee_amount_sats: i64,
    pub resource_hash: String,
    pub request_hash: String,
    pub voucher_id: String,
    pub intent_id: String,
    pub authorization_id: Option<String>,
    /// RFC-3339 UTC, e.g. `2026-05-28T00:00:00Z`.
    pub created_at: String,
    pub expires_at: String,
}

/// Escape a string as a JSON string literal (delegates to serde_json so
/// escaping stays standards-correct).
fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization is infallible")
}

impl ReceiptBody {
    /// The canonical JSON WITHOUT the `signature` field — the exact
    /// bytes that get signed. `kid`/`signatureAlgorithm` are part of the
    /// signed body (they pin which key the verifier must use).
    pub fn canonical_without_signature(&self, kid: &str) -> String {
        // (key, already-JSON-encoded value), assembled in sorted-key
        // order. authorizationId is omitted when None per spec.
        let mut fields: Vec<(&str, String)> = vec![
            ("accessThreshold", json_str(&self.access_threshold)),
            ("amount", json_str(&self.amount_sats.to_string())),
            ("asset", json_str("btc-sats")),
            ("createdAt", json_str(&self.created_at)),
            ("expiresAt", json_str(&self.expires_at)),
            ("feeAmount", json_str(&self.fee_amount_sats.to_string())),
            ("intentId", json_str(&self.intent_id)),
            ("kid", json_str(kid)),
            ("merchant", json_str(&self.merchant)),
            ("mode", json_str(&self.mode)),
            ("network", json_str(&self.network)),
            ("payer", json_str(&self.payer)),
            ("receiptId", json_str(&self.receipt_id)),
            ("requestHash", json_str(&self.request_hash)),
            ("resourceHash", json_str(&self.resource_hash)),
            ("scheme", json_str("zkcoins-publisher")),
            ("settlementState", json_str(&self.settlement_state)),
            ("signatureAlgorithm", json_str("Ed25519")),
            ("status", json_str(&self.status)),
            ("voucherId", json_str(&self.voucher_id)),
            ("x402Version", "2".to_owned()), // non-monetary number per fixture
        ];
        if let Some(auth) = &self.authorization_id {
            fields.push(("authorizationId", json_str(auth)));
        }
        fields.sort_by(|a, b| a.0.cmp(b.0));
        let inner: Vec<String> = fields
            .into_iter()
            .map(|(k, v)| format!("{}:{}", json_str(k), v))
            .collect();
        format!("{{{}}}", inner.join(","))
    }
}

/// The facilitator's receipt-signing identity: an Ed25519 keypair plus
/// the `kid` advertised in `GET /api/zk402/receipt-keys`.
pub struct ReceiptSigner {
    keypair: Ed25519KeyPair,
    pub kid: String,
}

impl ReceiptSigner {
    /// Load from PKCS8 DER bytes (v1 or v2 — the fixture key is v1, so
    /// the unchecked constructor is required; the key is operator
    /// config, not attacker input).
    pub fn from_pkcs8_der(pkcs8: &[u8], kid: &str) -> Result<Self, Zk402Error> {
        let keypair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8)
            .map_err(|_| Zk402Error::InvalidPayload)?;
        Ok(Self {
            keypair,
            kid: kid.to_owned(),
        })
    }

    /// Load from the base64url-no-pad PKCS8 form the fixtures/config use.
    pub fn from_pkcs8_base64url(pkcs8_b64: &str, kid: &str) -> Result<Self, Zk402Error> {
        let der = URL_SAFE_NO_PAD
            .decode(pkcs8_b64)
            .map_err(|_| Zk402Error::InvalidPayload)?;
        Self::from_pkcs8_der(&der, kid)
    }

    /// Generate a fresh signer (tests / first-boot provisioning).
    pub fn generate(kid: &str) -> Result<Self, Zk402Error> {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| Zk402Error::InvalidPayload)?;
        Self::from_pkcs8_der(doc.as_ref(), kid)
    }

    /// Raw 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> &[u8] {
        self.keypair.public_key().as_ref()
    }

    /// Sign a receipt body: returns the base64url-no-pad signature over
    /// the canonical JSON (deterministic for a given key + body).
    pub fn sign(&self, body: &ReceiptBody) -> String {
        self.sign_canonical(&body.canonical_without_signature(&self.kid))
    }

    /// Sign already-canonicalized bytes (base64url-no-pad). Exposed so
    /// the fixture cross-check can sign the vector's exact canonical
    /// string and reproduce its signature.
    pub fn sign_canonical(&self, canonical: &str) -> String {
        URL_SAFE_NO_PAD.encode(self.keypair.sign(canonical.as_bytes()).as_ref())
    }

    /// The full signed receipt envelope as wire JSON (canonical body
    /// fields + `signature`). Stored in `zk402_receipts.receipt_json`
    /// and returned to the buyer.
    pub fn signed_receipt_json(&self, body: &ReceiptBody) -> serde_json::Value {
        let signature = self.sign(body);
        let mut v = serde_json::json!({
            "receiptId": body.receipt_id,
            "x402Version": 2,
            "scheme": "zkcoins-publisher",
            "network": body.network,
            "mode": body.mode,
            "status": body.status,
            "settlementState": body.settlement_state,
            "accessThreshold": body.access_threshold,
            "payer": body.payer,
            "merchant": body.merchant,
            "amount": body.amount_sats.to_string(),
            "feeAmount": body.fee_amount_sats.to_string(),
            "asset": "btc-sats",
            "resourceHash": body.resource_hash,
            "requestHash": body.request_hash,
            "voucherId": body.voucher_id,
            "intentId": body.intent_id,
            "authorizationId": body.authorization_id,
            "createdAt": body.created_at,
            "expiresAt": body.expires_at,
            "kid": self.kid,
            "signatureAlgorithm": "Ed25519",
            "signature": signature,
        });
        // Wire envelope keeps authorizationId as explicit null (matches
        // the receipt-shape example); only the SIGNED canonical omits it.
        if body.authorization_id.is_none() {
            v["authorizationId"] = serde_json::Value::Null;
        }
        v
    }
}

/// Verify a receipt signature against an Ed25519 public key. Accepts
/// either the raw 32-byte key or an SPKI DER (the registry/fixture
/// form, 44 bytes with a 12-byte algorithm prefix).
pub fn verify_receipt_signature(
    public_key: &[u8],
    canonical_without_signature: &str,
    signature_b64url: &str,
) -> Result<bool, Zk402Error> {
    let raw_key: &[u8] = match public_key.len() {
        32 => public_key,
        44 => &public_key[12..],
        _ => return Err(Zk402Error::InvalidPayload),
    };
    let sig = URL_SAFE_NO_PAD
        .decode(signature_b64url)
        .map_err(|_| Zk402Error::InvalidSignature)?;
    let key = UnparsedPublicKey::new(&ED25519, raw_key);
    Ok(key
        .verify(canonical_without_signature.as_bytes(), &sig)
        .is_ok())
}
