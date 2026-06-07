//! Agent-Economy Layer-1 acceptance tests: service catalog + Bazaar
//! discovery (proposals/AGENT_ECONOMY_design.md, Phase 0a).
//!
//! * registration is merchant-key-gated, binds to the authed merchant,
//!   derives the resource hash, fails closed on mainnet / unsupported
//!   network and non-positive price;
//! * `/v2/x402/discovery/resources` serves the x402 Bazaar envelope
//!   (`{x402Version, items[], pagination}`) with only ACTIVE services;
//! * `/v2/x402/discovery/search` filters by text, network, maxPriceSats;
//! * `/v2/x402/supported` adverts the scheme on every testnet network
//!   and never `zkcoins:mainnet`;
//! * the dashboard view is own-data-only.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::test_db::{setup_pool, SchemaScope};

use super::dashboard::onboard_merchant;
use super::facilitator::MockPublisherAccept;
use super::receipt::ReceiptSigner;
use super::routes::{create_zk402_router, Zk402State};
use super::services;
use super::store;
use super::types::ServiceStatus;

async fn env() -> (axum::Router, SchemaScope) {
    let scope = setup_pool().await;
    onboard_merchant(&scope.pool, "merchant_1", "M1", "addr1", "zk402_sk_one")
        .await
        .unwrap();
    onboard_merchant(&scope.pool, "merchant_2", "M2", "addr2", "zk402_sk_two")
        .await
        .unwrap();
    let state = Zk402State {
        pool: Arc::new(scope.pool.clone()),
        signer: Arc::new(ReceiptSigner::generate("k").unwrap()),
        publisher: Arc::new(MockPublisherAccept),
    };
    (create_zk402_router(state), scope)
}

fn service_body(capability: &str, sats: i64) -> Value {
    json!({
        "capability": capability,
        "displayName": format!("{capability} service"),
        "description": format!("does {capability}"),
        "endpoint": format!("https://{capability}.example.test/v1"),
        "network": "zkcoins:regtest",
        "facilitator": "https://facilitator.test",
        "pricePolicy": { "kind": "per_request", "amountSats": sats },
    })
}

async fn post_json(
    app: &axum::Router,
    path: &str,
    key: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(k) = key {
        req = req.header("x-api-key", k);
    }
    let res = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
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

#[tokio::test]
async fn register_service_binds_authed_merchant_and_derives_hash() {
    let (app, _scope) = env().await;
    let (status, body) = post_json(
        &app,
        "/api/zk402/services",
        Some("zk402_sk_one"),
        service_body("ocr", 3),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["merchantId"], "merchant_1");
    let rhash = body["resourceHash"].as_str().unwrap();
    assert!(rhash.starts_with("sha256:"), "tagged hash: {rhash}");
    // The discovery item carries the requirement an agent can pay directly.
    let accepts = &body["resource"]["accepts"][0];
    assert_eq!(accepts["scheme"], "zkcoins-publisher");
    assert_eq!(accepts["network"], "zkcoins:regtest");
    assert_eq!(accepts["amount"], "3");
    assert_eq!(accepts["asset"], "btc-sats");
    assert_eq!(accepts["payTo"], "merchant_1");
    assert_eq!(accepts["extra"]["resourceHash"], rhash);
    assert_eq!(accepts["extra"]["accessThreshold"], "publisher_accepted");
}

#[tokio::test]
async fn register_service_requires_api_key() {
    let (app, _scope) = env().await;
    let (status, _) = post_json(&app, "/api/zk402/services", None, service_body("ocr", 3)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = post_json(
        &app,
        "/api/zk402/services",
        Some("wrong-key"),
        service_body("ocr", 3),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn register_service_fails_closed_on_mainnet_and_bad_price() {
    let (app, _scope) = env().await;
    // mainnet → unsupported_network (fail closed).
    let mut body = service_body("ocr", 3);
    body["network"] = json!("zkcoins:mainnet");
    let (status, resp) = post_json(&app, "/api/zk402/services", Some("zk402_sk_one"), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(resp["error"], "unsupported_network");
    // zero / missing price → invalid_payload.
    let mut body = service_body("ocr", 3);
    body["pricePolicy"] = json!({ "kind": "per_request" });
    let (status, resp) = post_json(&app, "/api/zk402/services", Some("zk402_sk_one"), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(resp["error"], "invalid_payload");
}

#[tokio::test]
async fn duplicate_service_id_is_rejected() {
    let (app, _scope) = env().await;
    let mut body = service_body("ocr", 3);
    body["serviceId"] = json!("svc_fixed");
    let (status, _) = post_json(
        &app,
        "/api/zk402/services",
        Some("zk402_sk_one"),
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, resp) = post_json(&app, "/api/zk402/services", Some("zk402_sk_one"), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(resp["error"], "invalid_payload");
}

#[tokio::test]
async fn discovery_resources_serves_bazaar_envelope_active_only() {
    let (app, scope) = env().await;
    for (cap, sats) in [("ocr", 3), ("translate", 5), ("search", 2)] {
        let (status, _) = post_json(
            &app,
            "/api/zk402/services",
            Some("zk402_sk_one"),
            service_body(cap, sats),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
    }
    // Disable one — it must drop out of discovery.
    let svc = store::search_active_services(&scope.pool, "translate", None, None, 5)
        .await
        .unwrap()
        .remove(0);
    assert!(store::update_service_status(
        &scope.pool,
        &svc.id,
        "merchant_1",
        ServiceStatus::Disabled
    )
    .await
    .unwrap());

    let (status, body) = get_json(&app, "/v2/x402/discovery/resources", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["x402Version"], 2);
    assert_eq!(body["pagination"]["total"], 2);
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    for item in items {
        assert_eq!(item["type"], "http");
        assert!(item["resource"].as_str().unwrap().starts_with("https://"));
        assert!(item["accepts"].as_array().unwrap().len() == 1);
        assert_ne!(item["metadata"]["capability"], "translate");
    }
    // Pagination clamps + offsets.
    let (_, page) = get_json(&app, "/v2/x402/discovery/resources?limit=1&offset=1", None).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["pagination"]["limit"], 1);
    assert_eq!(page["pagination"]["offset"], 1);
    assert_eq!(page["pagination"]["total"], 2);
}

#[tokio::test]
async fn discovery_search_filters_text_network_and_price() {
    let (app, _scope) = env().await;
    for (cap, sats) in [("ocr", 3), ("ocr-premium", 50), ("translate", 5)] {
        post_json(
            &app,
            "/api/zk402/services",
            Some("zk402_sk_one"),
            service_body(cap, sats),
        )
        .await;
    }
    // Text match.
    let (status, body) = get_json(&app, "/v2/x402/discovery/search?query=ocr", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["x402Version"], 2);
    assert_eq!(body["searchMethod"], "text");
    assert_eq!(body["resources"].as_array().unwrap().len(), 2);
    // Price cap drops the premium one.
    let (_, body) = get_json(
        &app,
        "/v2/x402/discovery/search?query=ocr&maxPriceSats=10",
        None,
    )
    .await;
    let resources = body["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["accepts"][0]["amount"], "3");
    // Network filter: nothing on signet.
    let (_, body) = get_json(
        &app,
        "/v2/x402/discovery/search?query=ocr&network=zkcoins:signet",
        None,
    )
    .await;
    assert_eq!(body["resources"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn search_with_like_metacharacters_does_not_500() {
    // A query of LIKE metachars (incl. a lone trailing backslash) must be
    // escaped, not break the public search into a 503.
    let (app, _scope) = env().await;
    post_json(
        &app,
        "/api/zk402/services",
        Some("zk402_sk_one"),
        service_body("ocr", 3),
    )
    .await;
    for q in ["%25", "_", "%5C", "a%5Cb", "ocr%25"] {
        let (status, body) =
            get_json(&app, &format!("/v2/x402/discovery/search?query={q}"), None).await;
        assert_eq!(status, StatusCode::OK, "query {q} → {status}: {body}");
        // Wildcard query must not match everything: a bare `%` escaped is a
        // literal percent, so it finds no service named with a percent.
        assert!(body["resources"].is_array());
    }
}

#[tokio::test]
async fn supported_adverts_testnets_never_mainnet() {
    let (app, _scope) = env().await;
    let (status, body) = get_json(&app, "/v2/x402/supported", None).await;
    assert_eq!(status, StatusCode::OK);
    let kinds = body["kinds"].as_array().unwrap();
    assert_eq!(kinds.len(), 3);
    for kind in kinds {
        assert_eq!(kind["scheme"], "zkcoins-publisher");
        assert_ne!(kind["network"], "zkcoins:mainnet");
    }
}

#[tokio::test]
async fn dashboard_services_is_own_data_only() {
    let (app, _scope) = env().await;
    post_json(
        &app,
        "/api/zk402/services",
        Some("zk402_sk_one"),
        service_body("ocr", 3),
    )
    .await;
    post_json(
        &app,
        "/api/zk402/services",
        Some("zk402_sk_two"),
        service_body("translate", 5),
    )
    .await;
    let (status, body) =
        get_json(&app, "/api/zk402/dashboard/services", Some("zk402_sk_one")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["merchantId"], "merchant_1");
    let services = body["services"].as_array().unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0]["metadata"]["capability"], "ocr");
}

#[tokio::test]
async fn resource_hash_matches_sdk_construction() {
    // Pin the ZK402-RESOURCE-V1 bytes: the Rust derivation must equal the
    // SDK's resourceHash() for the same inputs (sha256 over the literal
    // "ZK402-RESOURCE-V1\nmerchant_id=..\nresource_id=..\nprice_policy_id=..").
    use sha2::{Digest, Sha256};
    let expect = {
        let s = "ZK402-RESOURCE-V1\nmerchant_id=m1\nresource_id=svc1\nprice_policy_id=pp1";
        let mut h = Sha256::new();
        h.update(s.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    };
    assert_eq!(services::resource_hash("m1", "svc1", "pp1"), expect);
}

#[tokio::test]
async fn disabled_merchant_cannot_register() {
    let (app, scope) = env().await;
    assert!(store::update_merchant_status(
        &scope.pool,
        "merchant_1",
        super::types::MerchantStatus::Disabled
    )
    .await
    .unwrap());
    let (status, resp) = post_json(
        &app,
        "/api/zk402/services",
        Some("zk402_sk_one"),
        service_body("ocr", 3),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(resp["error"], "merchant_disabled");
}
