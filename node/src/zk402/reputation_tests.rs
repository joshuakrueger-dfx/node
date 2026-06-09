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
async fn score_rewards_payer_diversity_and_punishes_failures() {
    // Confidence is driven by DISTINCT PAYERS, not raw settle volume.
    let small = reputation::score(&ReputationSignals {
        settled_count: 5,
        distinct_payers: 5,
        ..Default::default()
    })
    .0;
    let big = reputation::score(&ReputationSignals {
        settled_count: 50,
        distinct_payers: 50,
        ..Default::default()
    })
    .0;
    assert!(big > small, "{big} !> {small}");
    assert!(big >= 99, "20+ distinct payers saturates confidence: {big}");
    assert!(
        small > 50,
        "any clean diverse history beats neutral: {small}"
    );

    // THE ANTI-WASH PROPERTY: 50 clean settles from ONE payer cannot buy a
    // high score — one distinct counterparty caps confidence, so the score
    // tops out at ~61 regardless of self-payment volume, well under the
    // "score > 90" bar agents filter on.
    let wash = reputation::score(&ReputationSignals {
        settled_count: 50,
        distinct_payers: 1,
        ..Default::default()
    })
    .0;
    assert!(wash < 65, "single-payer wash farm must stay low: {wash}");
    assert!(
        wash < 90,
        "wash farm must not clear the score>90 filter: {wash}"
    );
    assert!(wash < big, "wash {wash} must not reach diverse {big}");

    // Failures pull the rate down hard.
    let with_failures = reputation::score(&ReputationSignals {
        settled_count: 50,
        distinct_payers: 50,
        failed_count: 50,
        ..Default::default()
    });
    assert!(
        (with_failures.1 - 0.5).abs() < 1e-9,
        "50/50 success rate: {}",
        with_failures.1
    );
    assert!(with_failures.0 < big);

    // Reversals count against the rate the same way.
    let with_reversal = reputation::score(&ReputationSignals {
        settled_count: 9,
        distinct_payers: 9,
        reversed_count: 1,
        ..Default::default()
    });
    assert!((with_reversal.1 - 0.9).abs() < 1e-9);
}

#[tokio::test]
async fn bad_disputes_apply_multiplicative_factor() {
    let clean = ReputationSignals {
        settled_count: 10,
        distinct_payers: 10,
        ..Default::default()
    };
    let base = reputation::score(&clean).0;
    // One bad dispute on 10 settles → factor 10/(10+2)=0.833.
    let one_bad = reputation::score(&ReputationSignals {
        bad_dispute_count: 1,
        ..clean.clone()
    });
    assert!(one_bad.0 < base, "{} !< {}", one_bad.0, base);
    // success_rate (acceptance) is untouched by disputes.
    assert!((one_bad.1 - 1.0).abs() < 1e-9);
    // More bad disputes → strictly lower.
    let three_bad = reputation::score(&ReputationSignals {
        bad_dispute_count: 3,
        ..clean.clone()
    })
    .0;
    assert!(three_bad < one_bad.0, "{three_bad} !< {}", one_bad.0);
    // No bad disputes → exactly the clean score (purely subtractive term).
    let only_ok = reputation::score(&ReputationSignals {
        dispute_count: 4,
        bad_dispute_count: 0,
        ..clean.clone()
    })
    .0;
    assert_eq!(only_ok, base, "ok-only disputes never move the score");
}

// ---- DB-derived aggregates --------------------------------------------------

fn intent(id: &str, rhash: &str, amount: i64, status: PaymentIntentStatus) -> NewPaymentIntent {
    intent_p(id, rhash, amount, status, "zkpayer_aa")
}

fn intent_p(
    id: &str,
    rhash: &str,
    amount: i64,
    status: PaymentIntentStatus,
    payer: &str,
) -> NewPaymentIntent {
    let now = Utc::now();
    NewPaymentIntent {
        id: id.to_owned(),
        voucher_id: format!("v_{id}"),
        authorization_id: None,
        payer: payer.to_owned(),
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
    // finalized_count = published + final (2), distinct from accepted (3).
    assert_eq!(rep.signals.finalized_count, 2, "published + final");
    // All seeded settles share one payer → 1 distinct payer.
    assert_eq!(rep.signals.distinct_payers, 1);
    // Latency must never be negative (clock-granularity clamp): the
    // handler stamps publisher_accepted_at at second precision while
    // created_at is the DB's microsecond now().
    if let Some(ms) = rep.signals.median_settle_latency_ms {
        assert!(ms >= 0.0, "negative latency leaked: {ms}");
    }
}

#[tokio::test]
async fn distinct_payer_confidence_resists_wash_farming() {
    let scope = setup_pool().await;
    onboard_merchant(&scope.pool, "merchant_1", "M", "addr", "zk402_sk_one")
        .await
        .unwrap();
    // WASH service: 30 clean settles, all from ONE payer.
    let wash = "sha256:wash_service";
    for i in 0..30 {
        store::insert_payment_intent(
            &scope.pool,
            &intent_p(&format!("w{i}"), wash, 10, S::Final, "zkpayer_solo"),
        )
        .await
        .unwrap();
    }
    // DIVERSE service: 25 clean settles, each from a DISTINCT payer.
    let diverse = "sha256:diverse_service";
    for i in 0..25 {
        store::insert_payment_intent(
            &scope.pool,
            &intent_p(
                &format!("d{i}"),
                diverse,
                10,
                S::Final,
                &format!("zkpayer_{i:03}"),
            ),
        )
        .await
        .unwrap();
    }

    let wash_rep = reputation::for_resource(&scope.pool, wash).await.unwrap();
    let diverse_rep = reputation::for_resource(&scope.pool, diverse)
        .await
        .unwrap();
    assert_eq!(wash_rep.signals.distinct_payers, 1);
    assert_eq!(diverse_rep.signals.distinct_payers, 25);
    // Both have a perfect (1.0) success rate and similar volume, yet the
    // wash farm scores far lower — diversity is the moat, not volume.
    assert!(
        wash_rep.score < 65,
        "30 self-payments must not buy a high score: {}",
        wash_rep.score
    );
    assert!(
        wash_rep.score < 90,
        "wash farm must not clear the score>90 filter: {}",
        wash_rep.score
    );
    assert!(
        diverse_rep.score >= 95,
        "25 distinct payers earns near-full confidence: {}",
        diverse_rep.score
    );
    assert!(diverse_rep.score > wash_rep.score + 30);
}

#[tokio::test]
async fn bad_disputes_lower_score_clean_ratings_do_not() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    onboard_merchant(pool, "merchant_1", "M", "addr", "zk402_sk_one")
        .await
        .ok();
    let rhash = "sha256:disputed_service";
    // 5 clean, diverse settles → a solid baseline.
    for i in 0..5 {
        store::insert_payment_intent(
            pool,
            &intent_p(
                &format!("p{i}"),
                rhash,
                100,
                S::Final,
                &format!("zkpayer_{i:03}"),
            ),
        )
        .await
        .unwrap();
    }
    let baseline = reputation::for_resource(pool, rhash).await.unwrap();
    assert_eq!(baseline.signals.dispute_count, 0);
    assert_eq!(baseline.signals.bad_dispute_count, 0);

    // A receipt for one settle + a BAD dispute against it.
    store::insert_receipt(pool, "zkr_p0", "p0", "final", &json!({"r":1}), "fsig")
        .await
        .unwrap();
    let insert_dispute =
        |id: &'static str, rid: &'static str, who: &'static str, verdict: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO zk402_disputes (id, receipt_id, complainant, verdict, \
                 reason_hash, attestation_signature, signed_timestamp) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
                )
                .bind(id)
                .bind(rid)
                .bind(who)
                .bind(verdict)
                .bind("sha256:reason")
                .bind("sig")
                .bind(0i64)
                .execute(&pool)
                .await
                .unwrap();
            }
        };
    insert_dispute("dsp_1", "zkr_p0", "zkpayer_000", "bad").await;

    let after_bad = reputation::for_resource(pool, rhash).await.unwrap();
    assert_eq!(after_bad.signals.dispute_count, 1);
    assert_eq!(after_bad.signals.bad_dispute_count, 1);
    // Acceptance rate is unchanged — only the dispute factor moves the score.
    assert!((after_bad.success_rate - baseline.success_rate).abs() < 1e-9);
    assert!(
        after_bad.score < baseline.score,
        "a bad dispute must lower the score: {} !< {}",
        after_bad.score,
        baseline.score
    );

    // An 'ok' verdict is recorded but is NOT a bad dispute → score unchanged.
    store::insert_receipt(pool, "zkr_p1", "p1", "final", &json!({"r":1}), "fsig")
        .await
        .unwrap();
    insert_dispute("dsp_2", "zkr_p1", "zkpayer_001", "ok").await;

    let after_ok = reputation::for_resource(pool, rhash).await.unwrap();
    assert_eq!(
        after_ok.signals.dispute_count, 2,
        "ok rating counts in total"
    );
    assert_eq!(
        after_ok.signals.bad_dispute_count, 1,
        "ok rating is not a bad dispute"
    );
    assert_eq!(
        after_ok.score, after_bad.score,
        "an ok rating does not move the score"
    );
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
async fn search_ranks_globally_not_within_recency_window() {
    // Register more services than the search return limit (20); the FIRST
    // (oldest) gets a high reputation. A recency-windowed ranker would cut
    // it before ranking; the global ranker must still surface it #1.
    let (app, scope) = router().await;
    onboard_merchant(&scope.pool, "merchant_1", "M", "addr", "zk402_sk_one")
        .await
        .unwrap();
    let oldest = register(&app, "rankcap", 5).await;
    let oldest_h = store::load_service(&scope.pool, &oldest)
        .await
        .unwrap()
        .unwrap()
        .resource_hash;
    // 24 newer, history-less services (all score 50).
    for _ in 0..24 {
        register(&app, "rankcap", 5).await;
    }
    // Give the oldest a strong, diverse record → near-100 score.
    for i in 0..22 {
        store::insert_payment_intent(
            &scope.pool,
            &intent_p(
                &format!("o{i}"),
                &oldest_h,
                10,
                S::Final,
                &format!("zkpayer_{i:03}"),
            ),
        )
        .await
        .unwrap();
    }

    let (status, body) = get_json(
        &app,
        "/v2/x402/discovery/search?query=rankcap&limit=20",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resources = body["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 20, "trimmed to limit");
    // The oldest service — beyond a 20-row recency window — ranks #1.
    assert_eq!(resources[0]["metadata"]["serviceId"], oldest);
    assert!(
        resources[0]["metadata"]["reputation"]["score"]
            .as_i64()
            .unwrap()
            >= 95
    );
    // More matches than returned → partialResults true.
    assert_eq!(body["partialResults"], true);
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
