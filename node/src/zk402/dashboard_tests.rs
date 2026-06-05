//! Step-9 tests: dashboard & operations.
//!
//! Acceptance: API-key auth required; a merchant sees only its own data;
//! settlement states are reported separately (not collapsed into a
//! balance); exports reconcile with the ledger; and there is NO
//! withdraw/payout route.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use tower::ServiceExt;

use crate::test_db::{setup_pool, SchemaScope};

use super::dashboard::{
    authenticate, fee_analytics, issue_api_key, onboard_merchant, reconciles, revoke_api_key,
    settlement_summary,
};
use super::facilitator::MockPublisherAccept;
use super::receipt::ReceiptSigner;
use super::routes::{create_zk402_router, Zk402State};
use super::store;
use super::types::{
    MerchantStatus, NewMerchant, NewMerchantSettlement, NewPaymentIntent, PaymentIntentStatus,
    SettlementKind, SettlementStatus,
};

async fn merchant(pool: &sqlx::PgPool, id: &str) {
    store::insert_merchant(
        pool,
        &NewMerchant {
            id: id.to_owned(),
            display_name: format!("M-{id}"),
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

async fn intent(pool: &sqlx::PgPool, id: &str, merchant_id: &str, amount: i64, fee: i64) {
    let now = Utc::now();
    store::insert_payment_intent(
        pool,
        &NewPaymentIntent {
            id: id.to_owned(),
            voucher_id: format!("v_{id}"),
            authorization_id: None,
            payer: "zkpayer_x".to_owned(),
            merchant_id: merchant_id.to_owned(),
            network: "zkcoins:regtest".to_owned(),
            asset: "btc-sats".to_owned(),
            amount_sats: amount,
            fee_amount_sats: fee,
            resource_hash: "sha256:aa".to_owned(),
            request_hash: format!("sha256:{id}"),
            nonce: format!("n_{id}"),
            valid_after: now - chrono::Duration::hours(1),
            valid_before: now + chrono::Duration::hours(1),
            canonical_message: "m".to_owned(),
            signature_scheme: "bip340-schnorr".to_owned(),
            signature: "sig".to_owned(),
            status: PaymentIntentStatus::Received,
            access_threshold: super::types::AccessThreshold::PublisherAccepted,
        },
    )
    .await
    .unwrap();
}

async fn settlement(
    pool: &sqlx::PgPool,
    id: &str,
    merchant_id: &str,
    kind: SettlementKind,
    amount: i64,
) {
    store::insert_merchant_settlement(
        pool,
        &NewMerchantSettlement {
            id: id.to_owned(),
            merchant_id: merchant_id.to_owned(),
            payment_intent_id: None,
            batch_id: None,
            kind,
            amount_sats: amount,
            status: SettlementStatus::Posted,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn onboarding_issues_a_working_api_key_that_can_be_revoked() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let o = onboard_merchant(pool, "m1", "Merchant One", "zk1qaddr", "zk402_sk_secret1")
        .await
        .unwrap();
    assert_eq!(o.merchant_id, "m1");
    assert_eq!(o.api_key, "zk402_sk_secret1");

    // The key authenticates to its merchant; an unknown key does not.
    assert_eq!(
        authenticate(pool, "zk402_sk_secret1")
            .await
            .unwrap()
            .as_deref(),
        Some("m1")
    );
    assert_eq!(authenticate(pool, "wrong").await.unwrap(), None);

    // Onboarding a duplicate merchant id is rejected.
    assert!(onboard_merchant(pool, "m1", "dup", "addr", "k")
        .await
        .is_err());

    // Issue + revoke a second key.
    let kid = issue_api_key(pool, "m1", "ci", "zk402_sk_secret2")
        .await
        .unwrap();
    assert_eq!(
        authenticate(pool, "zk402_sk_secret2")
            .await
            .unwrap()
            .as_deref(),
        Some("m1")
    );
    assert!(revoke_api_key(pool, &kid).await.unwrap());
    assert_eq!(authenticate(pool, "zk402_sk_secret2").await.unwrap(), None);
    // first key still works
    assert_eq!(
        authenticate(pool, "zk402_sk_secret1")
            .await
            .unwrap()
            .as_deref(),
        Some("m1")
    );
}

#[tokio::test]
async fn merchant_sees_only_its_own_data() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    merchant(pool, "m1").await;
    merchant(pool, "m2").await;
    intent(pool, "pi1", "m1", 100, 1).await;
    intent(pool, "pi2", "m1", 200, 2).await;
    intent(pool, "pi3", "m2", 999, 9).await;

    let a1 = fee_analytics(pool, "m1").await.unwrap();
    assert_eq!(a1.intent_count, 2);
    assert_eq!(a1.gross_sats, 300);
    assert_eq!(a1.fee_sats, 3);
    assert_eq!(a1.net_sats, 297);

    let a2 = fee_analytics(pool, "m2").await.unwrap();
    assert_eq!(a2.intent_count, 1);
    assert_eq!(a2.gross_sats, 999);
}

#[tokio::test]
async fn settlement_states_are_reported_separately() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    merchant(pool, "m1").await;
    settlement(pool, "s1", "m1", SettlementKind::Accepted, 100).await;
    settlement(pool, "s2", "m1", SettlementKind::Published, 100).await;
    settlement(pool, "s3", "m1", SettlementKind::Confirmed, 100).await;
    settlement(pool, "s4", "m1", SettlementKind::Final, 100).await;
    settlement(pool, "s5", "m1", SettlementKind::Fee, 5).await;

    let s = settlement_summary(pool, "m1").await.unwrap();
    assert_eq!(s.accepted_sats, 100);
    assert_eq!(s.published_sats, 100);
    assert_eq!(s.confirmed_sats, 100);
    assert_eq!(s.final_sats, 100);
    assert_eq!(s.fee_sats, 5);
    // Reported separately — never summed into a single custodial balance.
}

#[tokio::test]
async fn exports_reconcile_with_the_ledger() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    merchant(pool, "m1").await;
    // A final batch with net 297 and matching final ledger entries.
    sqlx::query(
        "INSERT INTO zk402_batches (id, network, merchant_id, status, net_amount_sats) \
         VALUES ('b1', 'zkcoins:regtest', 'm1', 'final', 297)",
    )
    .execute(pool)
    .await
    .unwrap();
    settlement(pool, "f1", "m1", SettlementKind::Final, 99).await;
    settlement(pool, "f2", "m1", SettlementKind::Final, 198).await;
    assert!(reconciles(pool, "m1").await.unwrap());

    // Break the ledger → no longer reconciles.
    settlement(pool, "f3", "m1", SettlementKind::Final, 1).await;
    assert!(!reconciles(pool, "m1").await.unwrap());
}

// ---- route-level: auth required + no payout route ---------------------------

async fn router_with_merchant() -> (axum::Router, SchemaScope) {
    let scope = setup_pool().await;
    onboard_merchant(&scope.pool, "m1", "M", "addr", "zk402_sk_routekey")
        .await
        .unwrap();
    intent(&scope.pool, "pi1", "m1", 100, 1).await;
    let state = Zk402State {
        pool: Arc::new(scope.pool.clone()),
        signer: Arc::new(ReceiptSigner::generate("k").unwrap()),
        publisher: Arc::new(MockPublisherAccept),
    };
    (create_zk402_router(state), scope)
}

#[tokio::test]
async fn dashboard_requires_api_key() {
    let (app, _scope) = router_with_merchant().await;

    // No key → 401.
    let res = app
        .clone()
        .oneshot(
            Request::get("/api/zk402/dashboard/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // Valid key → 200.
    let res = app
        .clone()
        .oneshot(
            Request::get("/api/zk402/dashboard/summary")
                .header("x-api-key", "zk402_sk_routekey")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Wrong key → 401.
    let res = app
        .oneshot(
            Request::get("/api/zk402/dashboard/summary")
                .header("authorization", "Bearer nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn there_is_no_withdraw_or_payout_route() {
    let (app, _scope) = router_with_merchant().await;
    for path in [
        "/api/zk402/withdraw",
        "/api/zk402/payout",
        "/api/zk402/merchants/m1/withdraw",
    ] {
        let res = app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("x-api-key", "zk402_sk_routekey")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path} must not exist");
    }
}
