//! BIP-340 Schnorr verification for ZK402 (Step 2).
//!
//! Reuses the node's existing secp256k1 stack (`bitcoin::secp256k1` +
//! the shared `SECP256K1` context, the same one `shared::commitment`
//! signs with) rather than introducing a second EC implementation.
//!
//! Two layers:
//! * [`verify_schnorr_raw`] / [`verify_schnorr_hex`] — raw BIP-340 over a
//!   32-byte message, pinned against the Bitcoin BIP-340 test vector.
//! * [`verify_voucher_signature`] — the ZK402 voucher check: rebuild the
//!   canonical `ZK402-V1` message, hash it, and verify the payer's
//!   Schnorr signature over that digest. Tampering with any signed field
//!   changes the digest and fails verification.

use bitcoin::secp256k1::{schnorr::Signature, Message, XOnlyPublicKey};
use shared::SECP256K1;

use super::canonical::{
    agent_signing_digest, authorization_signing_digest, dispute_signing_digest,
    voucher_signing_digest, AgentFields, AuthorizationFields, DisputeFields, VoucherFields,
};
use super::error::Zk402Error;

/// The payer identity prefix: `zkpayer_<64-hex-x-only-pubkey>`.
const PAYER_PREFIX: &str = "zkpayer_";

/// Verify a raw BIP-340 Schnorr signature over a 32-byte message.
pub fn verify_schnorr_raw(pubkey: &XOnlyPublicKey, msg32: &[u8; 32], sig: &Signature) -> bool {
    let Ok(msg) = Message::from_digest_slice(msg32) else {
        return false;
    };
    SECP256K1.verify_schnorr(sig, &msg, pubkey).is_ok()
}

/// Hex-string convenience over [`verify_schnorr_raw`] — used by the
/// fixture test (pubkey/msg/sig as lowercase or uppercase hex). Returns
/// `InvalidSignature` for any malformed input rather than panicking.
pub fn verify_schnorr_hex(
    pubkey_hex: &str,
    msg32_hex: &str,
    sig_hex: &str,
) -> Result<bool, Zk402Error> {
    let pubkey = parse_xonly_hex(pubkey_hex)?;
    let msg = parse_32(msg32_hex)?;
    let sig = parse_signature_hex(sig_hex)?;
    Ok(verify_schnorr_raw(&pubkey, &msg, &sig))
}

/// Parse `zkpayer_<hex>` into an x-only public key.
pub fn payer_to_xonly(payer: &str) -> Result<XOnlyPublicKey, Zk402Error> {
    let hex = payer
        .strip_prefix(PAYER_PREFIX)
        .ok_or(Zk402Error::InvalidPayload)?;
    parse_xonly_hex(hex)
}

/// Verify a voucher's Schnorr signature against its payer. The signed
/// message is the canonical `ZK402-V1` form of `fields`; the signature
/// is `bip340-schnorr` over its SHA-256 digest.
pub fn verify_voucher_signature(
    fields: &VoucherFields,
    signature_hex: &str,
) -> Result<(), Zk402Error> {
    let pubkey = payer_to_xonly(&fields.payer)?;
    let sig = parse_signature_hex(signature_hex)?;
    let digest = voucher_signing_digest(fields);
    if verify_schnorr_raw(&pubkey, &digest, &sig) {
        Ok(())
    } else {
        Err(Zk402Error::InvalidSignature)
    }
}

/// Verify an agent registration: the identity key (`agent_id`) signs the
/// canonical `ZK402-AGENT-V1` digest, proving control of the key.
pub fn verify_agent_signature(fields: &AgentFields, signature_hex: &str) -> Result<(), Zk402Error> {
    let pubkey = payer_to_xonly(&fields.agent_id)?;
    let sig = parse_signature_hex(signature_hex)?;
    let digest = agent_signing_digest(fields);
    if verify_schnorr_raw(&pubkey, &digest, &sig) {
        Ok(())
    } else {
        Err(Zk402Error::InvalidSignature)
    }
}

/// Verify a delegation: the agent's IDENTITY key (`identity_payer`) signs the
/// canonical `ZK402-AUTHORIZATION-V1` digest to authorize a session key. This
/// is the real signature check that closes the `authorization.rs` seam.
pub fn verify_authorization_signature(
    fields: &AuthorizationFields,
    signature_hex: &str,
) -> Result<(), Zk402Error> {
    let pubkey = payer_to_xonly(&fields.identity_payer)?;
    let sig = parse_signature_hex(signature_hex)?;
    let digest = authorization_signing_digest(fields);
    if verify_schnorr_raw(&pubkey, &digest, &sig) {
        Ok(())
    } else {
        Err(Zk402Error::InvalidSignature)
    }
}

/// Verify a dispute attestation: the complainant (payer) key signs the
/// canonical `ZK402-DISPUTE-V1` digest.
pub fn verify_dispute_signature(
    fields: &DisputeFields,
    signature_hex: &str,
) -> Result<(), Zk402Error> {
    let pubkey = payer_to_xonly(&fields.complainant)?;
    let sig = parse_signature_hex(signature_hex)?;
    let digest = dispute_signing_digest(fields);
    if verify_schnorr_raw(&pubkey, &digest, &sig) {
        Ok(())
    } else {
        Err(Zk402Error::InvalidSignature)
    }
}

fn parse_xonly_hex(s: &str) -> Result<XOnlyPublicKey, Zk402Error> {
    let bytes = hex::decode(s).map_err(|_| Zk402Error::InvalidPayload)?;
    XOnlyPublicKey::from_slice(&bytes).map_err(|_| Zk402Error::InvalidPayload)
}

fn parse_32(s: &str) -> Result<[u8; 32], Zk402Error> {
    let bytes = hex::decode(s).map_err(|_| Zk402Error::InvalidPayload)?;
    bytes.try_into().map_err(|_| Zk402Error::InvalidPayload)
}

fn parse_signature_hex(s: &str) -> Result<Signature, Zk402Error> {
    let bytes = hex::decode(s).map_err(|_| Zk402Error::InvalidSignature)?;
    Signature::from_slice(&bytes).map_err(|_| Zk402Error::InvalidSignature)
}
