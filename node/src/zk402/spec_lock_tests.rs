//! Step-11 tests: spec & fixture lock.
//!
//! The final gate. Locks the wire fixtures and binds the end-to-end HTTP
//! contract:
//! * every wire fixture (`PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` /
//!   `PAYMENT-RESPONSE` incl. `extensions.zk402`) keeps its expected
//!   x402-v2 shape;
//! * `POST /v2/x402/verify` returns `isValid` and `POST /v2/x402/settle`
//!   returns `success` per x402 v2, exercised through the real router;
//! * an automated schema guard rejects any production column named
//!   `deposit_amount` / `treasury` / `payout_balance` (no-custody lock).
//!
//! Canonical-request-hash, BIP-340 and receipt-signature fixtures are
//! locked in `sig_tests` / `facilitator_tests`; this file locks the
//! remaining wire shapes and the HTTP surface.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use bitcoin::secp256k1::Keypair;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use shared::SECP256K1;
use tower::ServiceExt;

use crate::test_db::{setup_pool, SchemaScope};

use super::canonical::{
    allowed_merchants_hash, canonical_agent_message, canonical_authorization_message,
    canonical_dispute_message, capabilities_hash, voucher_signing_digest, AgentFields,
    AuthorizationFields, DisputeFields,
};
use super::facilitator::MockPublisherAccept;
use super::payload::ParsedPayment;
use super::receipt::ReceiptSigner;
use super::routes::{create_zk402_router, Zk402State};
use super::store;
use super::types::{MerchantStatus, NewMerchant};

const PAYMENT_REQUIRED: &str = include_str!("test_fixtures/payment-required.zk402.json");
const PAYMENT_SIGNATURE: &str = include_str!("test_fixtures/payment-signature.zk402.json");
const RESP_SUCCESS: &str = include_str!("test_fixtures/payment-response-success.zk402.json");
const RESP_FAILURE: &str = include_str!("test_fixtures/payment-response-failure.zk402.json");

fn fx(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

// ---- wire fixture shape lock ------------------------------------------------

#[test]
fn payment_required_fixture_has_x402v2_shape() {
    let d = fx(PAYMENT_REQUIRED);
    let d = &d["decoded"];
    assert_eq!(d["x402Version"], 2);
    let accept = &d["accepts"][0];
    assert_eq!(accept["scheme"], "zkcoins-publisher");
    assert_eq!(accept["asset"], "btc-sats");
    assert!(accept["extra"]["resourceHash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(accept["extra"]["accessThreshold"], "publisher_accepted");
}

#[test]
fn payment_signature_fixture_parses_and_binds_request() {
    let d = fx(PAYMENT_SIGNATURE);
    let p = ParsedPayment::from_decoded(&d["decoded"]).unwrap();
    assert_eq!(p.scheme, "zkcoins-publisher");
    assert_eq!(p.signature_scheme, "bip340-schnorr");
    // requestHash is the canonical-request binding pinned in sig_tests.
    assert_eq!(
        p.request_hash,
        "sha256:761b8d5a72948c73c0e2b703309d7603045f436c8317139f743de0fd6623e282"
    );
}

#[test]
fn payment_response_fixtures_carry_extensions_zk402() {
    let ok = fx(RESP_SUCCESS);
    let ok = ok.get("decoded").unwrap_or(&ok);
    assert_eq!(ok["success"], true);
    assert!(ok["extensions"]["zk402"]["receiptId"].is_string());
    assert_eq!(ok["extensions"]["zk402"]["settlementState"], "queued");

    let fail = fx(RESP_FAILURE);
    let fail = fail.get("decoded").unwrap_or(&fail);
    assert_eq!(fail["success"], false);
    assert!(fail["errorReason"].is_string());
    assert!(fail["extensions"]["zk402"]["invalidMessage"].is_string());
}

// ---- end-to-end HTTP contract ----------------------------------------------

async fn router() -> (axum::Router, SchemaScope) {
    let scope = setup_pool().await;
    store::insert_merchant(
        &scope.pool,
        &NewMerchant {
            id: "merchant_1".to_owned(),
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
    let state = Zk402State {
        pool: Arc::new(scope.pool.clone()),
        signer: Arc::new(ReceiptSigner::generate("receipt-key-001").unwrap()),
        publisher: Arc::new(MockPublisherAccept),
    };
    (create_zk402_router(state), scope)
}

/// A signed PAYMENT-SIGNATURE envelope valid for `now`, wrapped in the
/// x402 v2 verify/settle request shape.
fn signed_envelope(now: i64) -> Value {
    let mut sk = [0u8; 32];
    sk[31] = 11;
    let kp = Keypair::from_seckey_slice(&SECP256K1, &sk).unwrap();
    let payer = format!(
        "zkpayer_{}",
        hex::encode(kp.x_only_public_key().0.serialize())
    );

    let mut p = ParsedPayment {
        scheme: "zkcoins-publisher".to_owned(),
        network: "zkcoins:regtest".to_owned(),
        mode: "exact-payment-intent".to_owned(),
        facilitator: "https://facilitator.test".to_owned(),
        access_threshold: "publisher_accepted".to_owned(),
        intent_id: "zkintent_lock".to_owned(),
        authorization_id: None,
        voucher_id: "zkv_lock".to_owned(),
        payer: payer.clone(),
        merchant: "merchant_1".to_owned(),
        amount_sats: 25,
        fee_amount_sats: 1,
        asset: "btc-sats".to_owned(),
        resource_hash: "sha256:aa".to_owned(),
        request_hash: "sha256:bb".to_owned(),
        valid_after: now - 10,
        valid_before: now + 30,
        nonce: "lock-nonce".to_owned(),
        signature_scheme: "bip340-schnorr".to_owned(),
        signature: String::new(),
    };
    let digest = voucher_signing_digest(&p.voucher_fields());
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&digest).unwrap();
    p.signature = hex::encode(SECP256K1.sign_schnorr_no_aux_rand(&msg, &kp).serialize());

    let payment_payload = json!({
        "x402Version": 2,
        "resource": { "url": "https://api.example.com/v1/weather" },
        "accepted": {
            "scheme": p.scheme, "network": p.network, "amount": p.amount_sats.to_string(),
            "asset": "btc-sats", "payTo": p.merchant, "maxTimeoutSeconds": 30,
            "extra": {
                "mode": p.mode, "facilitator": p.facilitator,
                "resourceId": "weather", "resourceHash": p.resource_hash,
                "accessThreshold": p.access_threshold,
            }
        },
        "payload": {
            "intentId": p.intent_id, "authorizationId": null, "voucherId": p.voucher_id,
            "payer": p.payer, "merchant": p.merchant, "amount": p.amount_sats.to_string(),
            "feeAmount": p.fee_amount_sats.to_string(), "asset": "btc-sats",
            "resourceHash": p.resource_hash, "requestHash": p.request_hash,
            "validAfter": p.valid_after.to_string(), "validBefore": p.valid_before.to_string(),
            "nonce": p.nonce, "signatureScheme": p.signature_scheme, "signature": p.signature,
        },
        "extensions": {}
    });
    json!({ "x402Version": 2, "paymentPayload": payment_payload, "paymentRequirements": payment_payload["accepted"] })
}

async fn post_json(app: &axum::Router, path: &str, body: &Value) -> (StatusCode, Value) {
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

#[tokio::test]
async fn verify_returns_isvalid_and_settle_returns_success_per_x402v2() {
    let (app, _scope) = router().await;
    let now = chrono::Utc::now().timestamp();
    let envelope = signed_envelope(now);

    // verify → { isValid: true, ... }
    let (status, body) = post_json(&app, "/v2/x402/verify", &envelope).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["isValid"], true, "verify body: {body}");
    assert!(body["payer"].as_str().unwrap().starts_with("zkpayer_"));
    assert_eq!(body["extra"]["zk402"]["voucherId"], "zkv_lock");

    // settle → { success: true, extensions.zk402.* }
    let (status, body) = post_json(&app, "/v2/x402/settle", &envelope).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], true, "settle body: {body}");
    assert_eq!(body["amount"], "25");
    assert_eq!(body["extensions"]["zk402"]["status"], "publisher_accepted");
    assert_eq!(body["extensions"]["zk402"]["settlementState"], "queued");
    assert!(body["extensions"]["zk402"]["receiptId"]
        .as_str()
        .unwrap()
        .starts_with("zkr_"));

    // settle is idempotent at the HTTP layer too.
    let (_s, body2) = post_json(&app, "/v2/x402/settle", &envelope).await;
    assert_eq!(
        body2["extensions"]["zk402"]["receiptId"],
        body["extensions"]["zk402"]["receiptId"]
    );
}

#[tokio::test]
async fn verify_rejects_bad_signature_with_structured_reason() {
    let (app, _scope) = router().await;
    let now = chrono::Utc::now().timestamp();
    let mut envelope = signed_envelope(now);
    // Tamper the signed amount so the signature no longer matches.
    envelope["paymentPayload"]["payload"]["amount"] = json!("999");
    let (status, body) = post_json(&app, "/v2/x402/verify", &envelope).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["isValid"], false);
    assert_eq!(body["invalidReason"], "invalid_signature");
}

// ---- no-custody schema guard (automated lock) -------------------------------

#[tokio::test]
async fn production_schema_has_no_custodial_fields() {
    let scope = setup_pool().await;
    let pool = &scope.pool;

    let offending: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema = $1 \
           AND lower(column_name) IN ('deposit_amount', 'treasury', 'payout_balance')",
    )
    .bind(scope.schema())
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        offending.is_empty(),
        "custodial columns found: {offending:?}"
    );

    // Also assert at least the zk402 surface exists (guard is meaningful).
    let zk402_tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = $1 AND table_name LIKE 'zk402_%'",
    )
    .bind(scope.schema())
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        zk402_tables.len() >= 9,
        "expected the full zk402 surface, got {}",
        zk402_tables.len()
    );
}

// ---- Agent Economy Layer 3/4 canonical goldens (cross-language pin) ----------
// The EXACT same strings are asserted in the `@zk402/sdk` test
// (`test/core.test.ts`), so the Rust and TS encoders for AGENT/AUTHORIZATION/
// DISPUTE-V1 are byte-for-byte identical. A divergence silently breaks every
// cross-language agent registration / delegation / dispute signature.

const AGENT_GOLDEN: &str = "ZK402-AGENT-V1\nscheme=zkcoins-publisher\nagent_id=zkpayer_aa\nhandle=research-bot\ncapabilities_hash=sha256:2a95c57618561f09ecde2762140e55e0023c4b93a6c237b9381fc598880d6295\ntimestamp=1779900000";
const DISPUTE_GOLDEN: &str = "ZK402-DISPUTE-V1\nscheme=zkcoins-publisher\nreceipt_id=zkr_1\ncomplainant=zkpayer_aa\nverdict=bad\nreason_hash=sha256:dd\ntimestamp=1779900000";
// `session_pubkey` is a 64-hex (32-byte) x-only key — spliced from
// `"bb".repeat(32)` on BOTH sides (here and in the SDK test) so the byte-run
// is identical without hand-counting; everything around it is frozen literal.
const AUTHORIZATION_GOLDEN_TMPL: &str = "ZK402-AUTHORIZATION-V1\nscheme=zkcoins-publisher\nnetwork=zkcoins:regtest\nidentity_payer=zkpayer_aa\nsession_pubkey={SP}\nauthorized_amount=10000\nspend_limit_per_request=1000\nspend_limit_total=10000\nallowed_merchants_hash=sha256:24492c8500aeda60ef07a717b25e0b3a368ffa595bd8fcc0db16f942f2fda831\nfacilitator=https://facilitator.test\nvalid_after=1779900000\nvalid_before=1779986400";

#[test]
fn agent_economy_canonical_matches_cross_language_goldens() {
    let authorization_golden = AUTHORIZATION_GOLDEN_TMPL.replace("{SP}", &"bb".repeat(32));
    // Order-independent hashes pinned to the values embedded in the goldens.
    assert_eq!(
        capabilities_hash(&["research".to_owned(), "ocr".to_owned(), "ocr".to_owned()]),
        "sha256:2a95c57618561f09ecde2762140e55e0023c4b93a6c237b9381fc598880d6295"
    );
    assert_eq!(
        allowed_merchants_hash(&["merchant_1".to_owned()]),
        "sha256:24492c8500aeda60ef07a717b25e0b3a368ffa595bd8fcc0db16f942f2fda831"
    );

    let agent = AgentFields {
        agent_id: "zkpayer_aa".to_owned(),
        handle: "research-bot".to_owned(),
        capabilities_hash: capabilities_hash(&["ocr".to_owned(), "research".to_owned()]),
        timestamp: 1_779_900_000,
    };
    assert_eq!(
        String::from_utf8(canonical_agent_message(&agent)).unwrap(),
        AGENT_GOLDEN
    );

    let auth = AuthorizationFields {
        network: "zkcoins:regtest".to_owned(),
        identity_payer: "zkpayer_aa".to_owned(),
        session_pubkey: "bb".repeat(32),
        authorized_amount_sats: 10_000,
        spend_limit_per_request_sats: 1_000,
        spend_limit_total_sats: 10_000,
        allowed_merchants_hash: allowed_merchants_hash(&["merchant_1".to_owned()]),
        facilitator: "https://facilitator.test".to_owned(),
        valid_after: 1_779_900_000,
        valid_before: 1_779_986_400,
    };
    assert_eq!(
        String::from_utf8(canonical_authorization_message(&auth)).unwrap(),
        authorization_golden
    );

    let dispute = DisputeFields {
        receipt_id: "zkr_1".to_owned(),
        complainant: "zkpayer_aa".to_owned(),
        verdict: "bad".to_owned(),
        reason_hash: "sha256:dd".to_owned(),
        timestamp: 1_779_900_000,
    };
    assert_eq!(
        String::from_utf8(canonical_dispute_message(&dispute)).unwrap(),
        DISPUTE_GOLDEN
    );
}
