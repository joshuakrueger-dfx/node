//! Agent-Economy Layer-4 (v1) acceptance tests: seller reputation as a
//! recomputable read model (proposals/AGENT_ECONOMY_design.md, Phase 0b).
//!
//! * the scoring function is the documented, deterministic curve
//!   (neutral 50 with no history, saturates with clean volume, drops on
//!   failures);
//! * aggregates are derived from `zk402_payment_intents` keyed by
//!   `resource_hash` — no stored score, no snapshot table;
//! * the public route returns the derived snapshot;
//! * discovery search is ranked by score (the agent's "score > N" lever).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::test_db::{setup_pool, SchemaScope};

use super::dashboard::onboard_merchant;
use super::facilitator::MockPublisherAccept;
use super::receipt::ReceiptSigner;
use super::reputation::{self, ReputationSignals};
use super::routes::{create_zk402_router, Zk402State};
use super::store;
use super::types::{
    AccessThreshold, NewPaymentIntent, PaymentIntentStatus, PaymentIntentStatus as S,
};

// ---- pure scoring (no DB) ---------------------------------------------------

#[tokio::test]
async fn score_is_neutral_without_history() {
    let (score, rate) = reputation::score(&ReputationSignals::default());
    assert_eq!(score, 50, "no history → neutral 50");
    assert_eq!(rate, 1.0);
}

#[tokio::test]
async fn score_rewards_clean_volume_and_punishes_failures() {
    let clean_small = reputation::score(&ReputationSignals {
        settled_count: 5,
        ..Default::default()
    })
    .0;
    let clean_big = reputation::score(&ReputationSignals {
        settled_count: 50,
        ..Default::default()
    })
    .0;
    // More clean volume ⇒ higher confidence ⇒ higher score, toward 100.
    assert!(clean_big > clean_small, "{clean_big} !> {clean_small}");
    assert!(clean_big >= 99, "50 clean settles saturates: {clean_big}");
    assert!(
        clean_small > 50,
        "any clean history beats neutral: {clean_small}"
    );

    // Failures pull the rate down hard.
    let with_failures = reputation::score(&ReputationSignals {
        settled_count: 50,
        failed_count: 50,
        ..Default::default()
    });
    assert!(
        (with_failures.1 - 0.5).abs() < 1e-9,
        "50/50 success rate: {}",
        with_failures.1
    );
    assert!(with_failures.0 < clean_big);

    // Reversals count against the rate the same way.
    let with_reversal = reputation::score(&ReputationSignals {
        settled_count: 9,
        reversed_count: 1,
        ..Default::default()
    });
    assert!((with_reversal.1 - 0.9).abs() < 1e-9);
}

// ---- DB-derived aggregates --------------------------------------------------

fn intent(id: &str, rhash: &str, amount: i64, status: PaymentIntentStatus) -> NewPaymentIntent {
    let now = Utc::now();
    NewPaymentIntent {
        id: id.to_owned(),
        voucher_id: format!("v_{id}"),
        authorization_id: None,
        payer: "zkpayer_aa".to_owned(),
        merchant_id: "merchant_1".to_owned(),
        network: "zkcoins:regtest".to_owned(),
        asset: "btc-sats".to_owned(),
        amount_sats: amount,
        fee_amount_sats: 0,
        resource_hash: rhash.to_owned(),
        request_hash: "sha256:bb".to_owned(),
        nonce: format!("n_{id}"),
        valid_after: now,
        valid_before: now + Duration::minutes(10),
        canonical_message: "ZK402-V1\n…".to_owned(),
        signature_scheme: "bip340-schnorr".to_owned(),
        signature: "sig".to_owned(),
        status,
        access_threshold: AccessThreshold::PublisherAccepted,
    }
}

async fn seed(pool: &sqlx::PgPool, rhash: &str) {
    onboard_merchant(pool, "merchant_1", "M", "addr", "zk402_sk_one")
        .await
        .ok();
    // 3 settled (publisher_accepted / published / final), 1 failed, 1 reversed,
    // plus 1 still-verified (not yet a settle → excluded).
    store::insert_payment_intent(pool, &intent("i1", rhash, 100, S::PublisherAccepted))
        .await
        .unwrap();
    store::insert_payment_intent(pool, &intent("i2", rhash, 200, S::Published))
        .await
        .unwrap();
    store::insert_payment_intent(pool, &intent("i3", rhash, 300, S::Final))
        .await
        .unwrap();
    store::insert_payment_intent(pool, &intent("i4", rhash, 999, S::FailedTerminal))
        .await
        .unwrap();
    store::insert_payment_intent(pool, &intent("i5", rhash, 999, S::Reversed))
        .await
        .unwrap();
    store::insert_payment_intent(pool, &intent("i6", rhash, 999, S::Verified))
        .await
        .unwrap();
    // Stamp a publisher_accepted milestone so latency is computable.
    store::update_payment_intent_status(pool, "i1", S::PublisherAccepted, Utc::now())
        .await
        .unwrap();
}

#[tokio::test]
async fn aggregates_derive_from_payment_history() {
    let scope = setup_pool().await;
    let rhash = "sha256:service_aaa";
    seed(&scope.pool, rhash).await;

    let rep = reputation::for_resource(&scope.pool, rhash).await.unwrap();
    assert_eq!(rep.signals.settled_count, 3, "accepted+published+final");
    assert_eq!(rep.signals.failed_count, 1);
    assert_eq!(rep.signals.reversed_count, 1);
    assert_eq!(rep.signals.volume_sats, 600, "100+200+300, settled only");
    assert_eq!(rep.signals.volume_30d_sats, 600);
    // success_rate = 3 / (3+1+1) = 0.6
    assert!(
        (rep.success_rate - 0.6).abs() < 1e-9,
        "{}",
        rep.success_rate
    );
    assert!(rep.signals.first_settled_at.is_some());
    // Latency must never be negative (clock-granularity clamp): the
    // handler stamps publisher_accepted_at at second precision while
    // created_at is the DB's microsecond now().
    if let Some(ms) = rep.signals.median_settle_latency_ms {
        assert!(ms >= 0.0, "negative latency leaked: {ms}");
    }
}

#[tokio::test]
async fn unknown_resource_is_neutral() {
    let scope = setup_pool().await;
    let rep = reputation::for_resource(&scope.pool, "sha256:never_paid")
        .await
        .unwrap();
    assert_eq!(rep.signals.settled_count, 0);
    assert_eq!(rep.score, 50);
}

// ---- HTTP surface -----------------------------------------------------------

async fn router() -> (axum::Router, SchemaScope) {
    let scope = setup_pool().await;
    let state = Zk402State {
        pool: Arc::new(scope.pool.clone()),
        signer: Arc::new(ReceiptSigner::generate("k").unwrap()),
        publisher: Arc::new(MockPublisherAccept),
    };
    (create_zk402_router(state), scope)
}

async fn get_json(app: &axum::Router, path: &str, key: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().method("GET").uri(path);
    if let Some(k) = key {
        req = req.header("x-api-key", k);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn register(app: &axum::Router, capability: &str, sats: i64) -> String {
    let body = json!({
        "capability": capability,
        "displayName": format!("{capability} svc"),
        "endpoint": format!("https://{capability}.test/v1"),
        "network": "zkcoins:regtest",
        "facilitator": "https://facilitator.test",
        "pricePolicy": { "kind": "per_request", "amountSats": sats },
    });
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/zk402/services")
                .header("content-type", "application/json")
                .header("x-api-key", "zk402_sk_one")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["serviceId"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn reputation_route_returns_derived_snapshot() {
    let (app, scope) = router().await;
    onboard_merchant(&scope.pool, "merchant_1", "M", "addr", "zk402_sk_one")
        .await
        .unwrap();
    let svc_id = register(&app, "ocr", 3).await;
    let svc = store::load_service(&scope.pool, &svc_id)
        .await
        .unwrap()
        .unwrap();
    // One settled payment against this service's resource hash.
    store::insert_payment_intent(
        &scope.pool,
        &intent("p1", &svc.resource_hash, 100, S::Final),
    )
    .await
    .unwrap();

    let (status, body) = get_json(
        &app,
        &format!("/api/zk402/services/{svc_id}/reputation"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["serviceId"], svc_id);
    assert_eq!(body["reputation"]["settledCount"], 1);
    assert_eq!(body["reputation"]["successRate"], 1.0);
    assert!(body["reputation"]["score"].as_i64().unwrap() > 50);
    assert_eq!(body["reputation"]["volumeSats"], "100");

    let (status, _) = get_json(&app, "/api/zk402/services/svc_nope/reputation", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn discovery_search_ranks_by_reputation() {
    let (app, scope) = router().await;
    onboard_merchant(&scope.pool, "merchant_1", "M", "addr", "zk402_sk_one")
        .await
        .unwrap();
    // Two OCR services: "good" with a clean record, "bad" with failures.
    let good = register(&app, "ocr-good", 3).await;
    let bad = register(&app, "ocr-bad", 2).await;
    let good_h = store::load_service(&scope.pool, &good)
        .await
        .unwrap()
        .unwrap()
        .resource_hash;
    let bad_h = store::load_service(&scope.pool, &bad)
        .await
        .unwrap()
        .unwrap()
        .resource_hash;
    for i in 0..10 {
        store::insert_payment_intent(
            &scope.pool,
            &intent(&format!("g{i}"), &good_h, 10, S::Final),
        )
        .await
        .unwrap();
    }
    for i in 0..10 {
        // bad: half fail
        let st = if i % 2 == 0 {
            S::Final
        } else {
            S::FailedTerminal
        };
        store::insert_payment_intent(&scope.pool, &intent(&format!("b{i}"), &bad_h, 10, st))
            .await
            .unwrap();
    }

    let (status, body) = get_json(&app, "/v2/x402/discovery/search?query=ocr", None).await;
    assert_eq!(status, StatusCode::OK);
    let resources = body["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 2);
    // Higher-reputation service ranks first despite being more expensive.
    assert_eq!(resources[0]["metadata"]["serviceId"], good);
    assert_eq!(resources[1]["metadata"]["serviceId"], bad);
    let good_score = resources[0]["metadata"]["reputation"]["score"]
        .as_i64()
        .unwrap();
    let bad_score = resources[1]["metadata"]["reputation"]["score"]
        .as_i64()
        .unwrap();
    assert!(good_score > bad_score, "{good_score} !> {bad_score}");
}

#[tokio::test]
async fn settled_statuses_are_subset_of_intent_statuses() {
    // Lock-step: every status the read model counts as "settled" must be
    // a real PaymentIntentStatus variant (catch drift if the enum changes).
    for s in reputation::SETTLED_STATUSES {
        assert!(
            PaymentIntentStatus::ALL.iter().any(|v| v.as_str() == *s),
            "unknown settled status: {s}"
        );
    }
}
