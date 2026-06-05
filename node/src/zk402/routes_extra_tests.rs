//! Tests for the test-environment / frontend routes: POST
//! /v2/x402/stream/meter and the dashboard read endpoints
//! (payments/channels/usage) — auth-gated and merchant-scoped.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bitcoin::secp256k1::Keypair;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shared::SECP256K1;
use tower::ServiceExt;

use crate::test_db::{setup_pool, SchemaScope};

use super::authorization::{create_authorization, NewAuthorizationRequest};
use super::canonical::{stream_signing_digest, StreamVoucherFields};
use super::dashboard::onboard_merchant;
use super::facilitator::MockPublisherAccept;
use super::receipt::ReceiptSigner;
use super::routes::{create_zk402_router, Zk402State};

fn keypair() -> (Keypair, String) {
    let mut sk = [0u8; 32];
    sk[31] = 21;
    let kp = Keypair::from_seckey_slice(&SECP256K1, &sk).unwrap();
    let payer = format!(
        "zkpayer_{}",
        hex::encode(kp.x_only_public_key().0.serialize())
    );
    (kp, payer)
}

async fn env() -> (axum::Router, String, SchemaScope) {
    let scope = setup_pool().await;
    // merchant + API key
    onboard_merchant(&scope.pool, "merchant_1", "M", "addr", "zk402_sk_key")
        .await
        .unwrap();
    let state = Zk402State {
        pool: Arc::new(scope.pool.clone()),
        signer: Arc::new(ReceiptSigner::generate("k").unwrap()),
        publisher: Arc::new(MockPublisherAccept),
    };
    (create_zk402_router(state), "zk402_sk_key".to_owned(), scope)
}

async fn channel(pool: &sqlx::PgPool, payer: &str, cap: i64) {
    let now = Utc::now();
    create_authorization(
        pool,
        "chan_1",
        &NewAuthorizationRequest {
            payer: payer.to_owned(),
            network: "zkcoins:regtest".to_owned(),
            authorized_amount_sats: cap,
            valid_after: now - Duration::minutes(1),
            valid_before: now + Duration::hours(1),
            spend_limit_per_request_sats: None,
            spend_limit_total_sats: Some(cap),
            allowed_merchants: vec!["merchant_1".to_owned()],
            facilitator_origin: "https://facilitator.test".to_owned(),
            session_public_key: None,
            signature: "auth-sig".to_owned(),
        },
    )
    .await
    .unwrap();
}

fn stream_body(kp: &Keypair, payer: &str, seq: i64, max: i64, cumulative: i64, now: i64) -> Value {
    let f = StreamVoucherFields {
        network: "zkcoins:regtest".to_owned(),
        channel_id: "chan_1".to_owned(),
        voucher_seq: seq,
        payer: payer.to_owned(),
        merchant: "merchant_1".to_owned(),
        max_amount_sats: max,
        cumulative_authorized_sats: cumulative,
        resource_hash: "sha256:aa".to_owned(),
        request_hash: format!("sha256:r{seq}"),
        valid_after: now - 10,
        valid_before: now + 60,
        facilitator: "https://facilitator.test".to_owned(),
        access_threshold: "metered".to_owned(),
    };
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&stream_signing_digest(&f)).unwrap();
    let sig = hex::encode(SECP256K1.sign_schnorr_no_aux_rand(&msg, kp).serialize());
    json!({
        "streamVoucher": {
            "network": f.network, "channelId": f.channel_id, "voucherSeq": f.voucher_seq,
            "payer": f.payer, "merchant": f.merchant, "maxAmount": f.max_amount_sats,
            "cumulativeAuthorized": f.cumulative_authorized_sats, "resourceHash": f.resource_hash,
            "requestHash": f.request_hash, "validAfter": f.valid_after, "validBefore": f.valid_before,
            "facilitator": f.facilitator, "accessThreshold": f.access_threshold,
        },
        "signature": sig,
        "usage": [{ "unit": "output_tokens", "quantity": 1_000_000, "unitPriceMicrosats": 15, "model": "claude-sonnet-4-6" }],
    })
}

async fn post(app: &axum::Router, path: &str, body: &Value) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn get_auth(app: &axum::Router, path: &str, key: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::get(path);
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
async fn stream_meter_route_charges_and_enforces_signature() {
    let (app, _key, scope) = env().await;
    let (kp, payer) = keypair();
    channel(&scope.pool, &payer, 1_000).await;
    let now = Utc::now().timestamp();

    // Happy path: 1M output tokens @15 microsats = 15 sats, under the 100 max.
    let (status, body) = post(
        &app,
        "/v2/x402/stream/meter",
        &stream_body(&kp, &payer, 1, 100, 100, now),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["actualCostSats"], "15");
    assert_eq!(body["meteredTotalSats"], "15");

    // Tampered signature → invalid_signature.
    let mut bad = stream_body(&kp, &payer, 2, 100, 200, now);
    bad["streamVoucher"]["maxAmount"] = json!(9999);
    let (_s, body) = post(&app, "/v2/x402/stream/meter", &bad).await;
    assert_eq!(body["success"], false);
    assert_eq!(body["errorReason"], "invalid_signature");

    // Replay (cumulative not advanced) → authorization_limit_exceeded.
    let (_s, body) = post(
        &app,
        "/v2/x402/stream/meter",
        &stream_body(&kp, &payer, 1, 100, 100, now),
    )
    .await;
    assert_eq!(body["errorReason"], "authorization_limit_exceeded");
}

#[tokio::test]
async fn dashboard_reads_require_key_and_scope_to_merchant() {
    let (app, key, scope) = env().await;
    let (kp, payer) = keypair();
    channel(&scope.pool, &payer, 1_000).await;
    let now = Utc::now().timestamp();
    // produce a usage event + (via the channel) a meter
    post(
        &app,
        "/v2/x402/stream/meter",
        &stream_body(&kp, &payer, 1, 100, 100, now),
    )
    .await;

    // No key → 401 on every dashboard read.
    for path in [
        "/api/zk402/dashboard/payments",
        "/api/zk402/dashboard/channels",
        "/api/zk402/dashboard/usage?channel=chan_1",
    ] {
        let (status, _b) = get_auth(&app, path, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }

    // With key: channels shows the metering channel with its meter.
    let (status, body) = get_auth(&app, "/api/zk402/dashboard/channels", Some(&key)).await;
    assert_eq!(status, StatusCode::OK);
    let channels = body["channels"].as_array().unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0]["meteredSats"], "15");
    assert_eq!(channels[0]["capSats"], "1000");

    // Usage events for the channel.
    let (_s, body) = get_auth(
        &app,
        "/api/zk402/dashboard/usage?channel=chan_1",
        Some(&key),
    )
    .await;
    let usage = body["usage"].as_array().unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0]["unit"], "output_tokens");
    assert_eq!(usage[0]["costSats"], "15");
    assert_eq!(usage[0]["model"], "claude-sonnet-4-6");

    // Payments list is empty here (no exact-intent settled) but authorized.
    let (status, body) = get_auth(&app, "/api/zk402/dashboard/payments", Some(&key)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["payments"].as_array().unwrap().len(), 0);
}
