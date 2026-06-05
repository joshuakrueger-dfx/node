//! Step-2 tests: canonical messages + BIP-340 signatures.
//!
//! Pinned against the spec fixtures (copied into `test_fixtures/`):
//! * `canonical-request-vector.json` — canonical request string → request_hash
//! * `bip340-test-vector.json` — raw BIP-340 Schnorr verify
//! * `payment-signature.zk402.json` — wire payload parse/validate
//!
//! Acceptance (prompts/02): canonical output byte-stable; changed
//! amount / resource_hash / request_hash invalidate the signature;
//! expired / not-yet-valid / unsupported-network / malformed-amount fail.

use bitcoin::secp256k1::{Keypair, XOnlyPublicKey};
use serde_json::Value;
use shared::SECP256K1;

use super::canonical::{
    canonical_request_string, canonical_voucher_message, request_hash, sha256_tagged,
    CanonicalRequestParts, VoucherFields,
};
use super::error::Zk402Error;
use super::payload::ParsedPayment;
use super::signature::{verify_schnorr_hex, verify_schnorr_raw, verify_voucher_signature};

const CANONICAL_REQUEST_VECTOR: &str = include_str!("test_fixtures/canonical-request-vector.json");
const BIP340_VECTOR: &str = include_str!("test_fixtures/bip340-test-vector.json");
const PAYMENT_SIGNATURE_VECTOR: &str = include_str!("test_fixtures/payment-signature.zk402.json");

fn json(s: &str) -> Value {
    serde_json::from_str(s).expect("fixture is valid json")
}

// ---- canonical request hash -------------------------------------------------

#[test]
fn canonical_request_matches_fixture() {
    let v = json(CANONICAL_REQUEST_VECTOR);
    let req = &v["request"];
    let (scheme, host, path, query) =
        super::canonical::split_http_url(req["url"].as_str().unwrap()).unwrap();

    let headers: Vec<(String, String)> = req["headers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, val)| (k.clone(), val.as_str().unwrap().to_owned()))
        .collect();
    let body = hex::decode(req["bodyHex"].as_str().unwrap()).unwrap();

    let parts = CanonicalRequestParts {
        method: req["method"].as_str().unwrap().to_owned(),
        scheme,
        host,
        path,
        query,
        headers,
        body,
        resource_hash: v["resourceHash"].as_str().unwrap().to_owned(),
    };

    // Byte-stable canonical string and request hash both match the fixture.
    assert_eq!(
        canonical_request_string(&parts),
        v["canonical"].as_str().unwrap()
    );
    assert_eq!(request_hash(&parts), v["requestHash"].as_str().unwrap());
}

#[test]
fn canonical_query_sorts_and_keeps_duplicates() {
    // `?b=2&a=1&a=0` → `a=0&a=1&b=2` (spec example).
    assert_eq!(
        super::canonical::canonical_query("b=2&a=1&a=0"),
        "a=0&a=1&b=2"
    );
    assert_eq!(super::canonical::canonical_query(""), "");
}

#[test]
fn normalize_path_resolves_dot_segments() {
    assert_eq!(super::canonical::normalize_path("/a/./b/../c"), "/a/c");
    assert_eq!(super::canonical::normalize_path(""), "/");
    assert_eq!(super::canonical::normalize_path("/a/b/"), "/a/b/");
}

#[test]
fn empty_selected_headers_hash_is_the_empty_sha256() {
    // The spec pins this exact constant for "no selected headers".
    assert_eq!(
        sha256_tagged(b""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // `authorization` is never selected, so a request carrying only it
    // hashes to the empty-headers constant.
    assert_eq!(
        super::canonical::canonical_selected_headers(&[(
            "authorization".to_owned(),
            "Bearer x".to_owned(),
        )]),
        ""
    );
}

#[test]
fn changed_path_changes_request_hash() {
    let base = CanonicalRequestParts {
        method: "GET".to_owned(),
        scheme: "https".to_owned(),
        host: "api.example.com".to_owned(),
        path: "/v1/a".to_owned(),
        query: String::new(),
        headers: vec![],
        body: vec![],
        resource_hash: "sha256:aa".to_owned(),
    };
    let mut changed = base.clone();
    changed.path = "/v1/b".to_owned();
    assert_ne!(request_hash(&base), request_hash(&changed));
}

// ---- raw BIP-340 ------------------------------------------------------------

#[test]
fn bip340_fixture_verifies() {
    let v = json(BIP340_VECTOR);
    let ok = verify_schnorr_hex(
        v["publicKey"].as_str().unwrap(),
        v["message"].as_str().unwrap(),
        v["signature"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(ok, v["verificationResult"].as_bool().unwrap());
    assert!(ok);
}

#[test]
fn bip340_tampered_message_fails() {
    let v = json(BIP340_VECTOR);
    // Flip the message: a valid signature must no longer verify.
    let bad_msg = "1111111111111111111111111111111111111111111111111111111111111111";
    let ok = verify_schnorr_hex(
        v["publicKey"].as_str().unwrap(),
        bad_msg,
        v["signature"].as_str().unwrap(),
    )
    .unwrap();
    assert!(!ok);
}

#[test]
fn malformed_signature_inputs_are_errors_not_panics() {
    assert_eq!(
        verify_schnorr_hex("zz", "00", "00").unwrap_err(),
        Zk402Error::InvalidPayload
    );
}

// ---- voucher signature round-trip (sign → verify → tamper) -----------------

fn sample_fields() -> VoucherFields {
    VoucherFields {
        network: "zkcoins:regtest".to_owned(),
        mode: "exact-payment-intent".to_owned(),
        intent_id: "zkintent_1".to_owned(),
        authorization_id: None,
        voucher_id: "zkv_1".to_owned(),
        payer: String::new(), // filled in after we know the key
        merchant: "merchant_1".to_owned(),
        amount_sats: 25,
        fee_amount_sats: 1,
        resource_hash: "sha256:aa".to_owned(),
        request_hash: "sha256:bb".to_owned(),
        valid_after: 1_779_900_000,
        valid_before: 1_779_900_030,
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        facilitator: "https://facilitator.test".to_owned(),
        access_threshold: "publisher_accepted".to_owned(),
    }
}

/// Deterministic test keypair (BIP-340 vector secret key = 3).
fn test_keypair() -> (Keypair, XOnlyPublicKey, String) {
    let sk = [0u8; 32];
    let mut sk = sk;
    sk[31] = 3;
    let kp = Keypair::from_seckey_slice(&SECP256K1, &sk).unwrap();
    let xonly = kp.x_only_public_key().0;
    let payer = format!("zkpayer_{}", hex::encode(xonly.serialize()));
    (kp, xonly, payer)
}

fn sign_fields(fields: &VoucherFields, kp: &Keypair) -> String {
    let digest = super::canonical::voucher_signing_digest(fields);
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&digest).unwrap();
    let sig = SECP256K1.sign_schnorr_no_aux_rand(&msg, kp);
    hex::encode(sig.serialize())
}

#[test]
fn canonical_voucher_message_is_byte_stable() {
    let f = sample_fields();
    let a = canonical_voucher_message(&f);
    let b = canonical_voucher_message(&f.clone());
    assert_eq!(a, b);
    // Exact prefix + field order (ASCII, LF, no trailing newline).
    let s = String::from_utf8(a).unwrap();
    assert!(s.starts_with("ZK402-V1\nscheme=zkcoins-publisher\nnetwork=zkcoins:regtest\n"));
    assert!(s.contains("\nasset=btc-sats\n"));
    assert!(s.ends_with("\naccess_threshold=publisher_accepted"));
    // Empty authorization_id renders as the empty value.
    assert!(s.contains("\nauthorization_id=\n"));
}

#[test]
fn valid_voucher_signature_verifies_and_tamper_fails() {
    let (kp, _xonly, payer) = test_keypair();
    let mut fields = sample_fields();
    fields.payer = payer;
    let sig = sign_fields(&fields, &kp);

    // Positive: the signature verifies against the untouched voucher.
    verify_voucher_signature(&fields, &sig).expect("valid signature must verify");

    // Negative: changing any signed field invalidates the signature.
    for tamper in [
        |f: &mut VoucherFields| f.amount_sats = 26,
        |f: &mut VoucherFields| f.resource_hash = "sha256:ff".to_owned(),
        |f: &mut VoucherFields| f.request_hash = "sha256:ff".to_owned(),
        |f: &mut VoucherFields| f.merchant = "merchant_2".to_owned(),
        |f: &mut VoucherFields| f.valid_before = 1_779_900_999,
        |f: &mut VoucherFields| f.access_threshold = "final".to_owned(),
    ] {
        let mut bad = fields.clone();
        tamper(&mut bad);
        assert_eq!(
            verify_voucher_signature(&bad, &sig).unwrap_err(),
            Zk402Error::InvalidSignature
        );
    }
}

#[test]
fn raw_verify_with_parsed_xonly() {
    // payer-encoded x-only key round-trips and verifies the raw vector.
    let v = json(BIP340_VECTOR);
    let payer = format!(
        "zkpayer_{}",
        v["publicKey"].as_str().unwrap().to_lowercase()
    );
    let xonly = super::signature::payer_to_xonly(&payer).unwrap();
    let msg: [u8; 32] = hex::decode(v["message"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(
        &hex::decode(v["signature"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(verify_schnorr_raw(&xonly, &msg, &sig));
}

// ---- payload parse + validate ----------------------------------------------

#[test]
fn payload_parses_from_wire_fixture() {
    let v = json(PAYMENT_SIGNATURE_VECTOR);
    let p = ParsedPayment::from_decoded(&v["decoded"]).unwrap();
    assert_eq!(p.scheme, "zkcoins-publisher");
    assert_eq!(p.network, "zkcoins:mutinynet");
    assert_eq!(p.mode, "exact-payment-intent");
    assert_eq!(p.amount_sats, 25);
    assert_eq!(p.fee_amount_sats, 1);
    assert_eq!(p.authorization_id, None);
    assert_eq!(p.signature_scheme, "bip340-schnorr");
    assert_eq!(p.valid_after, 1_779_900_000);
    assert_eq!(p.valid_before, 1_779_900_030);
    // mutinynet is supported; validate within the window passes.
    p.validate(1_779_900_010).unwrap();
    // The voucher_fields view reproduces the signed amount/threshold.
    let f = p.voucher_fields();
    assert_eq!(f.amount_sats, 25);
    assert_eq!(f.access_threshold, "publisher_accepted");
}

#[test]
fn payload_validation_temporal_and_structural_failures() {
    let v = json(PAYMENT_SIGNATURE_VECTOR);
    let base = ParsedPayment::from_decoded(&v["decoded"]).unwrap();

    // not yet valid / expired around the [validAfter, validBefore] window.
    assert_eq!(
        base.validate(1_779_899_999).unwrap_err(),
        Zk402Error::NotYetValid
    );
    assert_eq!(
        base.validate(1_779_900_031).unwrap_err(),
        Zk402Error::ExpiredPayment
    );

    // unsupported network.
    let mut bad = base.clone();
    bad.network = "zkcoins:mainnet".to_owned();
    assert_eq!(
        bad.validate(1_779_900_010).unwrap_err(),
        Zk402Error::UnsupportedNetwork
    );

    // unsupported scheme.
    let mut bad = base.clone();
    bad.scheme = "evm-exact".to_owned();
    assert_eq!(
        bad.validate(1_779_900_010).unwrap_err(),
        Zk402Error::UnsupportedScheme
    );

    // malformed amount (non-positive).
    let mut bad = base.clone();
    bad.amount_sats = 0;
    assert_eq!(
        bad.validate(1_779_900_010).unwrap_err(),
        Zk402Error::InvalidPayload
    );

    // amount / resource mismatch against the advertised requirement.
    assert_eq!(
        base.check_against_accepted(26, &base.resource_hash)
            .unwrap_err(),
        Zk402Error::AmountMismatch
    );
    assert_eq!(
        base.check_against_accepted(base.amount_sats, "sha256:other")
            .unwrap_err(),
        Zk402Error::ResourceMismatch
    );
    base.check_against_accepted(base.amount_sats, &base.resource_hash)
        .unwrap();
}

#[test]
fn malformed_amount_string_is_invalid_payload() {
    let mut v = json(PAYMENT_SIGNATURE_VECTOR);
    v["decoded"]["payload"]["amount"] = Value::String("not-a-number".to_owned());
    assert_eq!(
        ParsedPayment::from_decoded(&v["decoded"]).unwrap_err(),
        Zk402Error::InvalidPayload
    );
}

#[test]
fn all_failure_codes_have_distinct_wire_strings() {
    let mut seen = std::collections::HashSet::new();
    for e in Zk402Error::ALL {
        assert!(seen.insert(e.code()), "duplicate code {}", e.code());
    }
    assert_eq!(seen.len(), 20);
    assert_eq!(Zk402Error::ReplayDetected.code(), "replay_detected");
}
