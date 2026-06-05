//! Step-4 tests: non-custodial authorization sessions + concurrency.
//!
//! Acceptance: create/read/revoke; voucher accepted only within signed
//! caps; overspend, expiry, revocation, foreign-merchant and
//! over-per-request-cap all fail with structured codes; and — the
//! load-bearing one — 100 PARALLEL vouchers cannot exceed the signed
//! total cap.

use std::sync::Arc;

use bitcoin::secp256k1::Keypair;
use chrono::{Duration, Utc};
use shared::SECP256K1;

use crate::test_db::setup_pool;

use super::authorization::{create_authorization, revoke_authorization, NewAuthorizationRequest};
use super::canonical::voucher_signing_digest;
use super::error::Zk402Error;
use super::facilitator::{settle, MockPublisherAccept, PublisherAcceptance};
use super::payload::ParsedPayment;
use super::receipt::ReceiptSigner;
use super::store;
use super::types::{AuthorizationStatus, MerchantStatus, NewMerchant};

fn keypair() -> (Keypair, String) {
    let mut sk = [0u8; 32];
    sk[31] = 9;
    let kp = Keypair::from_seckey_slice(&SECP256K1, &sk).unwrap();
    let payer = format!(
        "zkpayer_{}",
        hex::encode(kp.x_only_public_key().0.serialize())
    );
    (kp, payer)
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

#[allow(clippy::too_many_arguments)]
fn auth_voucher(
    kp: &Keypair,
    payer: &str,
    merchant: &str,
    auth_id: &str,
    voucher: &str,
    nonce: &str,
    amount: i64,
    now: i64,
) -> ParsedPayment {
    let mut p = ParsedPayment {
        scheme: "zkcoins-publisher".to_owned(),
        network: "zkcoins:regtest".to_owned(),
        mode: "authorization".to_owned(),
        facilitator: "https://facilitator.test".to_owned(),
        access_threshold: "publisher_accepted".to_owned(),
        intent_id: format!("zkintent_{voucher}"),
        authorization_id: Some(auth_id.to_owned()),
        voucher_id: voucher.to_owned(),
        payer: payer.to_owned(),
        merchant: merchant.to_owned(),
        amount_sats: amount,
        fee_amount_sats: 0,
        asset: "btc-sats".to_owned(),
        resource_hash: "sha256:aa".to_owned(),
        request_hash: format!("sha256:{voucher}"),
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

fn new_auth_req(
    payer: &str,
    total: i64,
    per_request: Option<i64>,
    merchants: Vec<String>,
) -> NewAuthorizationRequest {
    let now = Utc::now();
    NewAuthorizationRequest {
        payer: payer.to_owned(),
        network: "zkcoins:regtest".to_owned(),
        authorized_amount_sats: total,
        valid_after: now - Duration::minutes(1),
        valid_before: now + Duration::hours(1),
        spend_limit_per_request_sats: per_request,
        spend_limit_total_sats: Some(total),
        allowed_merchants: merchants,
        facilitator_origin: "https://facilitator.test".to_owned(),
        session_public_key: None,
        signature: "auth-sig".to_owned(),
    }
}

#[tokio::test]
async fn create_read_revoke_roundtrip() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (_kp, payer) = keypair();

    let a = create_authorization(
        pool,
        "zkauth_1",
        &new_auth_req(&payer, 100_000, Some(1_000), vec!["merchant_1".into()]),
    )
    .await
    .unwrap();
    assert_eq!(a.status, AuthorizationStatus::Active);
    assert_eq!(a.authorized_amount_sats, 100_000);

    let loaded = store::load_authorization(pool, "zkauth_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.payer, payer);

    let revoked = revoke_authorization(pool, "zkauth_1").await.unwrap();
    assert_eq!(revoked.status, AuthorizationStatus::Revoked);
    // revoke is idempotent
    assert_eq!(
        revoke_authorization(pool, "zkauth_1").await.unwrap().status,
        AuthorizationStatus::Revoked
    );
    // unknown id
    assert_eq!(
        revoke_authorization(pool, "missing").await.unwrap_err(),
        Zk402Error::AuthorizationNotFound
    );
}

#[tokio::test]
async fn voucher_within_caps_accepted_and_tracked() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    let (kp, payer) = keypair();
    let now = Utc::now().timestamp();
    create_authorization(
        pool,
        "zkauth_1",
        &new_auth_req(&payer, 100, Some(40), vec!["merchant_1".into()]),
    )
    .await
    .unwrap();
    let signer = Arc::new(ReceiptSigner::generate("k").unwrap());
    let publisher: Arc<dyn PublisherAcceptance> = Arc::new(MockPublisherAccept);

    // Two vouchers of 30 fit under the 100 total + 40 per-request caps.
    settle(
        pool,
        &signer,
        &publisher,
        &auth_voucher(
            &kp,
            &payer,
            "merchant_1",
            "zkauth_1",
            "zkv_1",
            "n1",
            30,
            now,
        ),
        now,
    )
    .await
    .unwrap();
    settle(
        pool,
        &signer,
        &publisher,
        &auth_voucher(
            &kp,
            &payer,
            "merchant_1",
            "zkauth_1",
            "zkv_2",
            "n2",
            30,
            now,
        ),
        now,
    )
    .await
    .unwrap();

    let auth = store::load_authorization(pool, "zkauth_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth.accepted_amount_sats, 60);
}

#[tokio::test]
async fn overspend_per_request_revocation_and_expiry_fail() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    active_merchant(pool, "merchant_1").await;
    active_merchant(pool, "merchant_2").await;
    let (kp, payer) = keypair();
    let now = Utc::now().timestamp();
    let signer = Arc::new(ReceiptSigner::generate("k").unwrap());
    let publisher: Arc<dyn PublisherAcceptance> = Arc::new(MockPublisherAccept);

    create_authorization(
        pool,
        "zkauth_1",
        &new_auth_req(&payer, 50, Some(40), vec!["merchant_1".into()]),
    )
    .await
    .unwrap();

    // amount over the per-request cap (45 > 40)
    let e = settle(
        pool,
        &signer,
        &publisher,
        &auth_voucher(
            &kp,
            &payer,
            "merchant_1",
            "zkauth_1",
            "zkv_1",
            "n1",
            45,
            now,
        ),
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(e, Zk402Error::AuthorizationLimitExceeded);

    // merchant not in the allow-list
    let e = settle(
        pool,
        &signer,
        &publisher,
        &auth_voucher(
            &kp,
            &payer,
            "merchant_2",
            "zkauth_1",
            "zkv_2",
            "n2",
            10,
            now,
        ),
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(e, Zk402Error::AuthorizationLimitExceeded);

    // total-cap overspend: 40 ok, then 40 more exceeds 50
    settle(
        pool,
        &signer,
        &publisher,
        &auth_voucher(
            &kp,
            &payer,
            "merchant_1",
            "zkauth_1",
            "zkv_3",
            "n3",
            40,
            now,
        ),
        now,
    )
    .await
    .unwrap();
    let e = settle(
        pool,
        &signer,
        &publisher,
        &auth_voucher(
            &kp,
            &payer,
            "merchant_1",
            "zkauth_1",
            "zkv_4",
            "n4",
            40,
            now,
        ),
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(e, Zk402Error::AuthorizationLimitExceeded);

    // revocation blocks future vouchers
    revoke_authorization(pool, "zkauth_1").await.unwrap();
    let e = settle(
        pool,
        &signer,
        &publisher,
        &auth_voucher(&kp, &payer, "merchant_1", "zkauth_1", "zkv_5", "n5", 5, now),
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(e, Zk402Error::AuthorizationRevoked);

    // expiry: a voucher presented after valid_before fails
    create_authorization(pool, "zkauth_2", &{
        let mut r = new_auth_req(&payer, 100, Some(100), vec!["merchant_1".into()]);
        r.valid_before = Utc::now() - Duration::seconds(1); // already expired
        r
    })
    .await
    .unwrap();
    let e = settle(
        pool,
        &signer,
        &publisher,
        &auth_voucher(&kp, &payer, "merchant_1", "zkauth_2", "zkv_6", "n6", 5, now),
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(e, Zk402Error::ExpiredPayment);
}

/// The headline guarantee: 100 concurrent vouchers of 10 against a
/// signed total cap of 250 — at most 25 may be accepted, and the
/// authorization's accepted total can never exceed the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hundred_parallel_vouchers_cannot_exceed_cap() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    active_merchant(&pool, "merchant_1").await;
    let (kp, payer) = keypair();
    let now = Utc::now().timestamp();
    create_authorization(
        &pool,
        "zkauth_1",
        &new_auth_req(&payer, 250, Some(10), vec!["merchant_1".into()]),
    )
    .await
    .unwrap();
    let signer = Arc::new(ReceiptSigner::generate("k").unwrap());
    let publisher: Arc<dyn PublisherAcceptance> = Arc::new(MockPublisherAccept);

    let mut handles = Vec::new();
    for i in 0..100 {
        let pool = pool.clone();
        let signer = signer.clone();
        let publisher = publisher.clone();
        let voucher = auth_voucher(
            &kp,
            &payer,
            "merchant_1",
            "zkauth_1",
            &format!("zkv_{i}"),
            &format!("n_{i}"),
            10,
            now,
        );
        handles.push(tokio::spawn(async move {
            settle(&pool, &signer, &publisher, &voucher, now)
                .await
                .is_ok()
        }));
    }
    let mut accepted = 0;
    for h in handles {
        if h.await.unwrap() {
            accepted += 1;
        }
    }

    // Exactly 25 vouchers of 10 fit under the cap of 250.
    assert_eq!(accepted, 25, "expected exactly 25 accepted, got {accepted}");
    let auth = store::load_authorization(&pool, "zkauth_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(auth.accepted_amount_sats, 250);
    assert!(
        auth.accepted_amount_sats <= auth.authorized_amount_sats,
        "overspend: {} > {}",
        auth.accepted_amount_sats,
        auth.authorized_amount_sats
    );
}
