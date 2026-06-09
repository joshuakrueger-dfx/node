//! Step-3 tests: facilitator verify/settle + Ed25519 receipts.
//!
//! DB-backed (real per-test schema via `setup_pool`). Covers the
//! acceptance criteria: valid payload verifies/settles; invalid
//! signature and unknown/disabled merchant fail with structured codes;
//! settle persists the intent + a signed receipt; an idempotent replay
//! returns the same receipt; a voucher reused with changed terms (or a
//! reused nonce) is `replay_detected`; publisher-acceptance failure is
//! recorded; and the receipt canonical form + Ed25519 signature match
//! the spec fixture byte-for-byte.

use std::sync::Arc;

use bitcoin::secp256k1::Keypair;
use serde_json::{json, Value};
use shared::SECP256K1;

use crate::test_db::setup_pool;

use super::agents::{
    add_session_key, register_agent, revoke_session_key, AddSessionKey, RegisterAgent,
};
use super::canonical::{
    agent_signing_digest, allowed_merchants_hash, authorization_signing_digest, capabilities_hash,
    voucher_signing_digest, AgentFields, AuthorizationFields,
};
use super::error::Zk402Error;
use super::facilitator::{
    settle, verify, FailingPublisherAccept, MockPublisherAccept, PublisherAcceptance,
};
use super::payload::ParsedPayment;
use super::receipt::{verify_receipt_signature, ReceiptBody, ReceiptSigner};
use super::store;
use super::types::{MerchantStatus, NewMerchant};

const RECEIPT_VECTOR: &str = include_str!("test_fixtures/receipt-vector.json");

fn test_keypair() -> (Keypair, String) {
    let mut sk = [0u8; 32];
    sk[31] = 7;
    let kp = Keypair::from_seckey_slice(&SECP256K1, &sk).unwrap();
    let payer = format!(
        "zkpayer_{}",
        hex::encode(kp.x_only_public_key().0.serialize())
    );
    (kp, payer)
}

/// Build a fully-signed `ParsedPayment` for `merchant`, valid around
/// `now` (window [now-10, now+30]).
fn signed_payload(
    kp: &Keypair,
    payer: &str,
    merchant: &str,
    voucher: &str,
    nonce: &str,
    amount: i64,
    now: i64,
) -> ParsedPayment {
    let mut p = ParsedPayment {
        scheme: "zkcoins-publisher".to_owned(),
        network: "zkcoins:regtest".to_owned(),
        mode: "exact-payment-intent".to_owned(),
        facilitator: "https://facilitator.test".to_owned(),
        access_threshold: "publisher_accepted".to_owned(),
        intent_id: format!("zkintent_{voucher}"),
        authorization_id: None,
        voucher_id: voucher.to_owned(),
        payer: payer.to_owned(),
        merchant: merchant.to_owned(),
        amount_sats: amount,
        fee_amount_sats: 1,
        asset: "btc-sats".to_owned(),
        resource_hash: "sha256:aa".to_owned(),
        request_hash: "sha256:bb".to_owned(),
        valid_after: now - 10,
        valid_before: now + 30,
        nonce: nonce.to_owned(),
        signature_scheme: "bip340-schnorr".to_owned(),
        signature: String::new(),
    };
    let digest = voucher_signing_digest(&p.voucher_fields());
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&digest).unwrap();
    p.signature = hex::encode(SECP256K1.sign_schnorr_no_aux_rand(&msg, kp).serialize());
    p
}

async fn active_merchant(pool: &sqlx::PgPool, id: &str) {
    store::insert_merchant(
        pool,
        &NewMerchant {
            id: id.to_owned(),
            display_name: "M".to_owned(),
            settlement_address: "zk1qm".to_owned(),
            username: None,
            status: MerchantStatus::Active,
            fee_bps: 100,
            fixed_fee_sats: 0,
        },
    )
    .await
    .unwrap();
}

fn signer() -> Arc<ReceiptSigner> {
    Arc::new(ReceiptSigner::generate("receipt-key-001").unwrap())
}

fn mock_publisher() -> Arc<dyn PublisherAcceptance> {
    Arc::new(MockPublisherAccept)
}

#[tokio::test]
async fn verify_valid_payload_succeeds() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    let (kp, payer) = test_keypair();
    let now = 1_779_900_000;
    let p = signed_payload(&kp, &payer, "merchant_1", "zkv_1", "n1", 25, now);

    let out = verify(pool, &p, now).await.unwrap();
    assert_eq!(out.payer, payer);
    assert_eq!(out.voucher_id, "zkv_1");
}

#[tokio::test]
async fn verify_rejects_bad_signature_and_merchant() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (kp, payer) = test_keypair();
    let now = 1_779_900_000;

    // Unknown merchant (no row).
    let p = signed_payload(&kp, &payer, "merchant_missing", "zkv_1", "n1", 25, now);
    assert_eq!(
        verify(pool, &p, now).await.unwrap_err(),
        Zk402Error::MerchantNotFound
    );

    // Disabled merchant.
    active_merchant(pool, "merchant_1").await;
    store::update_merchant_status(pool, "merchant_1", MerchantStatus::Disabled)
        .await
        .unwrap();
    let p = signed_payload(&kp, &payer, "merchant_1", "zkv_2", "n2", 25, now);
    assert_eq!(
        verify(pool, &p, now).await.unwrap_err(),
        Zk402Error::MerchantDisabled
    );

    // Tampered signature (flip a byte) over an active merchant.
    store::update_merchant_status(pool, "merchant_1", MerchantStatus::Active)
        .await
        .unwrap();
    let mut bad = signed_payload(&kp, &payer, "merchant_1", "zkv_3", "n3", 25, now);
    bad.amount_sats = 26; // signature no longer matches the canonical message
    assert_eq!(
        verify(pool, &bad, now).await.unwrap_err(),
        Zk402Error::InvalidSignature
    );
}

#[tokio::test]
async fn settle_persists_intent_and_signed_receipt() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    let (kp, payer) = test_keypair();
    let now = 1_779_900_000;
    let p = signed_payload(&kp, &payer, "merchant_1", "zkv_1", "n1", 25, now);
    let signer = signer();
    let publisher = mock_publisher();

    let out = settle(pool, &signer, &publisher, &p, now).await.unwrap();
    assert!(!out.idempotent_replay);
    assert_eq!(out.status, "publisher_accepted");
    assert_eq!(out.settlement_state, "queued");
    assert_eq!(out.amount_sats, 25);

    // Intent persisted and advanced to queued.
    let intent = store::load_payment_intent_by_voucher(pool, "zkv_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(intent.status, super::types::PaymentIntentStatus::Queued);
    assert_eq!(intent.merchant_id, "merchant_1");

    // Receipt persisted and its signature verifies against the signer key.
    let receipt = store::load_receipt_for_intent(pool, &intent.id)
        .await
        .unwrap()
        .unwrap();
    let body = ReceiptBody {
        receipt_id: receipt.id.clone(),
        network: "zkcoins:regtest".to_owned(),
        mode: "exact-payment-intent".to_owned(),
        status: "publisher_accepted".to_owned(),
        settlement_state: "queued".to_owned(),
        access_threshold: "publisher_accepted".to_owned(),
        payer: payer.clone(),
        merchant: "merchant_1".to_owned(),
        amount_sats: 25,
        fee_amount_sats: 1,
        resource_hash: "sha256:aa".to_owned(),
        request_hash: "sha256:bb".to_owned(),
        voucher_id: "zkv_1".to_owned(),
        intent_id: "zkintent_zkv_1".to_owned(),
        authorization_id: None,
        created_at: out.receipt_json["createdAt"].as_str().unwrap().to_owned(),
        expires_at: out.receipt_json["expiresAt"].as_str().unwrap().to_owned(),
    };
    let canonical = body.canonical_without_signature(&signer.kid);
    let sig = out.receipt_json["signature"].as_str().unwrap();
    assert!(verify_receipt_signature(signer.public_key_bytes(), &canonical, sig).unwrap());
}

#[tokio::test]
async fn settle_is_idempotent_on_voucher() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    let (kp, payer) = test_keypair();
    let now = 1_779_900_000;
    let p = signed_payload(&kp, &payer, "merchant_1", "zkv_1", "n1", 25, now);
    let signer = signer();
    let publisher = mock_publisher();

    let first = settle(pool, &signer, &publisher, &p, now).await.unwrap();
    let second = settle(pool, &signer, &publisher, &p, now).await.unwrap();
    assert!(!first.idempotent_replay);
    assert!(second.idempotent_replay);
    assert_eq!(first.receipt_id, second.receipt_id);

    // Exactly one intent + one receipt exist.
    let (intents,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM zk402_payment_intents")
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(intents, 1);
}

#[tokio::test]
async fn settle_replay_with_changed_terms_is_rejected() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    let (kp, payer) = test_keypair();
    let now = 1_779_900_000;
    let signer = signer();
    let publisher = mock_publisher();

    let p = signed_payload(&kp, &payer, "merchant_1", "zkv_1", "n1", 25, now);
    settle(pool, &signer, &publisher, &p, now).await.unwrap();

    // Same voucher id, re-signed for a different amount → replay_detected
    // (proves amount is immutable after the buyer's signature).
    let tampered = signed_payload(&kp, &payer, "merchant_1", "zkv_1", "n1", 99, now);
    assert_eq!(
        settle(pool, &signer, &publisher, &tampered, now)
            .await
            .unwrap_err(),
        Zk402Error::ReplayDetected
    );
}

#[tokio::test]
async fn settle_reused_nonce_is_replay_detected() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    let (kp, payer) = test_keypair();
    let now = 1_779_900_000;
    let signer = signer();
    let publisher = mock_publisher();

    settle(
        pool,
        &signer,
        &publisher,
        &signed_payload(&kp, &payer, "merchant_1", "zkv_1", "shared_nonce", 25, now),
        now,
    )
    .await
    .unwrap();

    // Different voucher, SAME nonce → DB nonce unique violation → replay.
    let err = settle(
        pool,
        &signer,
        &publisher,
        &signed_payload(&kp, &payer, "merchant_1", "zkv_2", "shared_nonce", 25, now),
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(err, Zk402Error::ReplayDetected);
}

#[tokio::test]
async fn settle_publisher_failure_marks_intent_failed() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    let (kp, payer) = test_keypair();
    let now = 1_779_900_000;
    let p = signed_payload(&kp, &payer, "merchant_1", "zkv_1", "n1", 25, now);
    let signer = signer();
    let publisher: Arc<dyn PublisherAcceptance> = Arc::new(FailingPublisherAccept);

    assert_eq!(
        settle(pool, &signer, &publisher, &p, now)
            .await
            .unwrap_err(),
        Zk402Error::PublisherAcceptanceFailed
    );

    // The intent was persisted before acceptance and is now marked failed
    // with the structured code (recoverable, non-custodial).
    let intent = store::load_payment_intent_by_voucher(pool, "zkv_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        intent.status,
        super::types::PaymentIntentStatus::FailedRecoverable
    );
    assert_eq!(
        intent.failure_code.as_deref(),
        Some("publisher_acceptance_failed")
    );
    // No receipt was issued for a failed settle.
    assert!(store::load_receipt_for_intent(pool, &intent.id)
        .await
        .unwrap()
        .is_none());
}

// ---- receipt fixture cross-check (Ed25519 is deterministic) -----------------

fn fixture() -> Value {
    serde_json::from_str(RECEIPT_VECTOR).unwrap()
}

#[test]
fn receipt_fixture_signature_reproduces_exactly() {
    let f = fixture();
    let signer = ReceiptSigner::from_pkcs8_base64url(
        f["privateKeyPkcs8DerBase64urlForFixtureOnly"]
            .as_str()
            .unwrap(),
        f["kid"].as_str().unwrap(),
    )
    .unwrap();
    // Re-sign the fixture's exact canonical bytes; Ed25519 determinism
    // means we must reproduce the fixture's signature byte-for-byte.
    let canonical = f["canonicalWithoutSignature"].as_str().unwrap();
    assert_eq!(
        signer.sign_canonical(canonical),
        f["signatureBase64url"].as_str().unwrap()
    );
}

#[test]
fn receipt_fixture_verifies_against_spki_key() {
    let f = fixture();
    let ok = verify_receipt_signature(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            f["publicKeySpkiDerBase64url"].as_str().unwrap(),
        )
        .unwrap(),
        f["canonicalWithoutSignature"].as_str().unwrap(),
        f["signatureBase64url"].as_str().unwrap(),
    )
    .unwrap();
    assert!(ok);
}

#[test]
fn our_canonical_matches_fixture_field_set() {
    // Build a ReceiptBody from the fixture receipt and confirm our
    // deterministic canonical serializer reproduces the fixture's
    // canonical string exactly (sorted keys, omitted null, number x402Version).
    let f = fixture();
    let r = &f["receipt"];
    let body = ReceiptBody {
        receipt_id: r["receiptId"].as_str().unwrap().to_owned(),
        network: r["network"].as_str().unwrap().to_owned(),
        mode: r["mode"].as_str().unwrap().to_owned(),
        status: r["status"].as_str().unwrap().to_owned(),
        settlement_state: r["settlementState"].as_str().unwrap().to_owned(),
        access_threshold: r["accessThreshold"].as_str().unwrap().to_owned(),
        payer: r["payer"].as_str().unwrap().to_owned(),
        merchant: r["merchant"].as_str().unwrap().to_owned(),
        amount_sats: r["amount"].as_str().unwrap().parse().unwrap(),
        fee_amount_sats: r["feeAmount"].as_str().unwrap().parse().unwrap(),
        resource_hash: r["resourceHash"].as_str().unwrap().to_owned(),
        request_hash: r["requestHash"].as_str().unwrap().to_owned(),
        voucher_id: r["voucherId"].as_str().unwrap().to_owned(),
        intent_id: r["intentId"].as_str().unwrap().to_owned(),
        authorization_id: None,
        created_at: r["createdAt"].as_str().unwrap().to_owned(),
        expires_at: r["expiresAt"].as_str().unwrap().to_owned(),
    };
    assert_eq!(
        body.canonical_without_signature(r["kid"].as_str().unwrap()),
        f["canonicalWithoutSignature"].as_str().unwrap()
    );
    // sanity: the verify response shape we mirror in routes::settle_handler
    let _ = json!({"success": true});
}

#[tokio::test]
async fn settle_persists_publisher_acceptance_id() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    let (kp, payer) = test_keypair();
    let now = 1_779_900_000;
    let p = signed_payload(&kp, &payer, "merchant_1", "zkv_1", "n1", 25, now);
    settle(pool, &signer(), &mock_publisher(), &p, now)
        .await
        .unwrap();
    let intent = store::load_payment_intent_by_voucher(pool, "zkv_1")
        .await
        .unwrap()
        .unwrap();
    // MockPublisherAccept returns "pubacc_<voucher>" — it is now persisted.
    assert_eq!(
        intent.publisher_acceptance_id.as_deref(),
        Some("pubacc_zkv_1")
    );
}

// ---- session-key delegation enforcement in the settle path ------------------

fn kp(seed: u8) -> (Keypair, String) {
    let mut sk = [0u8; 32];
    sk[31] = seed;
    let k = Keypair::from_seckey_slice(&SECP256K1, &sk).unwrap();
    let payer = format!(
        "zkpayer_{}",
        hex::encode(k.x_only_public_key().0.serialize())
    );
    (k, payer)
}

fn sign_digest(d: &[u8; 32], k: &Keypair) -> String {
    let m = bitcoin::secp256k1::Message::from_digest_slice(d).unwrap();
    hex::encode(SECP256K1.sign_schnorr_no_aux_rand(&m, k).serialize())
}

/// Register `agent_id` (signed by `kp_id`) and delegate a session key to
/// `sess_pub` with the given per-request cap / merchant allow-list / window.
#[allow(clippy::too_many_arguments)]
async fn delegate(
    pool: &sqlx::PgPool,
    kp_id: &Keypair,
    agent_id: &str,
    sess_pub: &str,
    merchants: Vec<String>,
    per_req: i64,
    va: i64,
    vb: i64,
    created_at: i64,
) {
    let caps = vec!["pay".to_owned()];
    let af = AgentFields {
        agent_id: agent_id.to_owned(),
        handle: String::new(),
        capabilities_hash: capabilities_hash(&caps),
        timestamp: created_at,
    };
    register_agent(
        pool,
        &RegisterAgent {
            agent_id: agent_id.to_owned(),
            handle: None,
            capabilities: caps,
            timestamp: created_at,
            signature: sign_digest(&agent_signing_digest(&af), kp_id),
        },
        created_at,
    )
    .await
    .unwrap();
    let auth = AuthorizationFields {
        network: "zkcoins:regtest".to_owned(),
        identity_payer: agent_id.to_owned(),
        session_pubkey: sess_pub.to_owned(),
        authorized_amount_sats: 1_000_000,
        spend_limit_per_request_sats: per_req,
        spend_limit_total_sats: 1_000_000,
        allowed_merchants_hash: allowed_merchants_hash(&merchants),
        facilitator: "https://facilitator.test".to_owned(),
        valid_after: va,
        valid_before: vb,
    };
    add_session_key(
        pool,
        &AddSessionKey {
            agent_id: agent_id.to_owned(),
            session_pubkey: sess_pub.to_owned(),
            network: "zkcoins:regtest".to_owned(),
            authorized_amount_sats: 1_000_000,
            spend_limit_per_request_sats: per_req,
            spend_limit_total_sats: 1_000_000,
            allowed_merchants: merchants,
            facilitator: "https://facilitator.test".to_owned(),
            valid_after: va,
            valid_before: vb,
            delegation_signature: sign_digest(&authorization_signing_digest(&auth), kp_id),
        },
        created_at,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn settle_enforces_session_key_delegation() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;

    let (kp_id, agent_id) = kp(31);
    let (kp_sess, sess_payer) = kp(32);
    let sess_pub = sess_payer.strip_prefix("zkpayer_").unwrap().to_owned();
    let now = 1_779_900_000;
    // Per-request cap 1000 sats; only merchant_1 allowed; window covers `now`.
    delegate(
        pool,
        &kp_id,
        &agent_id,
        &sess_pub,
        vec!["merchant_1".to_owned()],
        1_000,
        now - 100,
        now + 100_000,
        now,
    )
    .await;

    // Within caps + allowed merchant → accepted (the delegation passes).
    let p = signed_payload(
        &kp_sess,
        &sess_payer,
        "merchant_1",
        "zkv_ok",
        "n_ok",
        500,
        now,
    );
    let out = settle(pool, &signer(), &mock_publisher(), &p, now)
        .await
        .unwrap();
    assert_eq!(out.status, "publisher_accepted");

    // Over the per-request cap → rejected, and the persisted intent is failed.
    let p = signed_payload(
        &kp_sess,
        &sess_payer,
        "merchant_1",
        "zkv_over",
        "n_over",
        5_000,
        now,
    );
    assert!(settle(pool, &signer(), &mock_publisher(), &p, now)
        .await
        .is_err());
    let over = store::load_payment_intent_by_voucher(pool, "zkv_over")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        over.status,
        super::types::PaymentIntentStatus::FailedTerminal
    );

    // A merchant NOT in the signed allow-list → rejected (verify() still
    // needs an active merchant row; the delegation check is what bites).
    active_merchant(pool, "merchant_2").await;
    let p = signed_payload(
        &kp_sess,
        &sess_payer,
        "merchant_2",
        "zkv_wm",
        "n_wm",
        500,
        now,
    );
    assert!(settle(pool, &signer(), &mock_publisher(), &p, now)
        .await
        .is_err());

    // Revoked session key → rejected.
    assert!(revoke_session_key(pool, &sess_pub, now).await.unwrap());
    let p = signed_payload(
        &kp_sess,
        &sess_payer,
        "merchant_1",
        "zkv_rev",
        "n_rev",
        500,
        now,
    );
    assert!(settle(pool, &signer(), &mock_publisher(), &p, now)
        .await
        .is_err());
}

#[tokio::test]
async fn settle_rejects_session_key_outside_window() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;

    let (kp_id, agent_id) = kp(33);
    let (kp_sess, sess_payer) = kp(34);
    let sess_pub = sess_payer.strip_prefix("zkpayer_").unwrap().to_owned();
    let t0 = 1_779_900_000;
    // Delegation expires at t0+5; created at t0 (still in the future then).
    delegate(
        pool,
        &kp_id,
        &agent_id,
        &sess_pub,
        vec!["merchant_1".to_owned()],
        1_000,
        t0 - 10,
        t0 + 5,
        t0,
    )
    .await;

    // Settle after the delegation window — the voucher itself is still valid
    // at `now`, so it is the delegation window (not verify()) that rejects.
    let now = t0 + 10;
    let p = signed_payload(
        &kp_sess,
        &sess_payer,
        "merchant_1",
        "zkv_exp",
        "n_exp",
        500,
        now,
    );
    assert!(settle(pool, &signer(), &mock_publisher(), &p, now)
        .await
        .is_err());

    // An ordinary (non-delegated) payer is untouched by the session-key gate.
    let (kp_plain, plain_payer) = test_keypair();
    let p = signed_payload(
        &kp_plain,
        &plain_payer,
        "merchant_1",
        "zkv_plain",
        "n_plain",
        9_999,
        now,
    );
    let out = settle(pool, &signer(), &mock_publisher(), &p, now)
        .await
        .unwrap();
    assert_eq!(out.status, "publisher_accepted");
}
