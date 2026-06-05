//! Step-1 acceptance tests (BIGBROTHER_ROADMAP.md / prompts/01):
//!
//! * migrations apply cleanly (every test runs them via `setup_pool`),
//! * duplicate `voucher_id` and `nonce` are rejected,
//! * merchant create/read works,
//! * authorization create/read works,
//! * audit-event insert works,
//! * production schema contains no deposit/treasury/payout-balance
//!   table or field (non-custodial lint),
//! * enum ↔ CHECK-constraint lock-step in both directions.

use chrono::{Duration, Utc};
use serde_json::json;

use crate::test_db::setup_pool;

use super::store;
use super::types::{
    AccessThreshold, AuditEvent, AuthorizationStatus, BatchStatus, MerchantStatus,
    NewAuthorization, NewMerchant, NewPaymentIntent, PaymentIntentStatus, SettlementKind,
    SettlementStatus,
};

fn new_merchant(id: &str) -> NewMerchant {
    NewMerchant {
        id: id.to_owned(),
        display_name: "Test Merchant".to_owned(),
        settlement_address: "zk1qmerchantsettlementaddress".to_owned(),
        username: None,
        status: MerchantStatus::Active,
        fee_bps: 100,
        fixed_fee_sats: 0,
    }
}

fn new_authorization(id: &str) -> NewAuthorization {
    let now = Utc::now();
    NewAuthorization {
        id: id.to_owned(),
        payer: "zk1qpayer".to_owned(),
        network: "zkcoins:regtest".to_owned(),
        asset: "btc-sats".to_owned(),
        authorized_amount_sats: 100_000,
        status: AuthorizationStatus::Pending,
        valid_after: now,
        valid_before: now + Duration::hours(24),
        spend_limit_per_request_sats: Some(1_000),
        spend_limit_total_sats: Some(100_000),
        allowed_merchants: json!(["merchant-1"]),
        facilitator_origin: "https://facilitator.test".to_owned(),
        session_public_key: None,
        authorization_signature: "sig-placeholder".to_owned(),
    }
}

fn new_intent(id: &str, voucher: &str, nonce: &str, merchant: &str) -> NewPaymentIntent {
    let now = Utc::now();
    NewPaymentIntent {
        id: id.to_owned(),
        voucher_id: voucher.to_owned(),
        authorization_id: None,
        payer: "zk1qpayer".to_owned(),
        merchant_id: merchant.to_owned(),
        network: "zkcoins:regtest".to_owned(),
        asset: "btc-sats".to_owned(),
        amount_sats: 500,
        fee_amount_sats: 5,
        resource_hash: "sha256:aa".to_owned(),
        request_hash: "sha256:bb".to_owned(),
        nonce: nonce.to_owned(),
        valid_after: now,
        valid_before: now + Duration::minutes(10),
        canonical_message: "ZK402-V1\n…".to_owned(),
        signature_scheme: "bip340-schnorr".to_owned(),
        signature: "sig-placeholder".to_owned(),
        status: PaymentIntentStatus::Received,
        access_threshold: AccessThreshold::PublisherAccepted,
    }
}

/// The Postgres unique/check constraint name carried by a DB error, so
/// the negative tests can assert *which* invariant fired.
fn constraint_of(err: &sqlx::Error) -> Option<String> {
    match err {
        sqlx::Error::Database(db) => db.constraint().map(str::to_owned),
        _ => None,
    }
}

#[tokio::test]
async fn merchant_create_read_roundtrip() {
    let scope = setup_pool().await;
    let pool = &scope.pool;

    let inserted = store::insert_merchant(pool, &new_merchant("merchant-1"))
        .await
        .unwrap();
    assert!(inserted);

    let loaded = store::load_merchant(pool, "merchant-1").await.unwrap().unwrap();
    assert_eq!(loaded.id, "merchant-1");
    assert_eq!(loaded.display_name, "Test Merchant");
    assert_eq!(loaded.status, MerchantStatus::Active);
    assert_eq!(loaded.fee_bps, 100);
    assert_eq!(loaded.address_change_delay_seconds, 86400);

    // Idempotent replay of the same id is a no-op, not an error.
    let replayed = store::insert_merchant(pool, &new_merchant("merchant-1"))
        .await
        .unwrap();
    assert!(!replayed);

    // Status update round-trips.
    assert!(store::update_merchant_status(pool, "merchant-1", MerchantStatus::Disabled)
        .await
        .unwrap());
    let disabled = store::load_merchant(pool, "merchant-1").await.unwrap().unwrap();
    assert_eq!(disabled.status, MerchantStatus::Disabled);

    // Missing merchant reads as None.
    assert!(store::load_merchant(pool, "missing").await.unwrap().is_none());
}

#[tokio::test]
async fn authorization_create_read_roundtrip() {
    let scope = setup_pool().await;
    let pool = &scope.pool;

    let inserted = store::insert_authorization(pool, &new_authorization("auth-1"))
        .await
        .unwrap();
    assert!(inserted);

    let loaded = store::load_authorization(pool, "auth-1").await.unwrap().unwrap();
    assert_eq!(loaded.id, "auth-1");
    assert_eq!(loaded.status, AuthorizationStatus::Pending);
    assert_eq!(loaded.authorized_amount_sats, 100_000);
    assert_eq!(loaded.accepted_amount_sats, 0);
    assert_eq!(loaded.published_amount_sats, 0);
    assert_eq!(loaded.allowed_merchants, json!(["merchant-1"]));
    assert_eq!(loaded.spend_limit_per_request_sats, Some(1_000));

    // Idempotent replay.
    assert!(!store::insert_authorization(pool, &new_authorization("auth-1"))
        .await
        .unwrap());

    // Revocation transition round-trips.
    assert!(
        store::update_authorization_status(pool, "auth-1", AuthorizationStatus::Revoked)
            .await
            .unwrap()
    );
    let revoked = store::load_authorization(pool, "auth-1").await.unwrap().unwrap();
    assert_eq!(revoked.status, AuthorizationStatus::Revoked);
}

#[tokio::test]
async fn duplicate_voucher_id_rejected() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    store::insert_merchant(pool, &new_merchant("merchant-1")).await.unwrap();

    assert!(
        store::insert_payment_intent(pool, &new_intent("pi-1", "voucher-1", "nonce-1", "merchant-1"))
            .await
            .unwrap()
    );

    // Same id ⇒ idempotent no-op.
    assert!(
        !store::insert_payment_intent(pool, &new_intent("pi-1", "voucher-1", "nonce-1", "merchant-1"))
            .await
            .unwrap()
    );

    // Different id, same voucher_id ⇒ unique violation (replay backstop).
    let err = store::insert_payment_intent(
        pool,
        &new_intent("pi-2", "voucher-1", "nonce-2", "merchant-1"),
    )
    .await
    .unwrap_err();
    assert_eq!(
        constraint_of(&err).as_deref(),
        Some("zk402_payment_intents_voucher_id_uq"),
        "expected the voucher_id unique index to fire, got: {err}"
    );
}

#[tokio::test]
async fn duplicate_nonce_rejected() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    store::insert_merchant(pool, &new_merchant("merchant-1")).await.unwrap();

    store::insert_payment_intent(pool, &new_intent("pi-1", "voucher-1", "nonce-1", "merchant-1"))
        .await
        .unwrap();

    let err = store::insert_payment_intent(
        pool,
        &new_intent("pi-2", "voucher-2", "nonce-1", "merchant-1"),
    )
    .await
    .unwrap_err();
    assert_eq!(
        constraint_of(&err).as_deref(),
        Some("zk402_payment_intents_nonce_uq"),
        "expected the nonce unique index to fire, got: {err}"
    );
}

#[tokio::test]
async fn payment_intent_status_milestones() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    store::insert_merchant(pool, &new_merchant("merchant-1")).await.unwrap();
    store::insert_payment_intent(pool, &new_intent("pi-1", "voucher-1", "nonce-1", "merchant-1"))
        .await
        .unwrap();

    let now = Utc::now();
    assert!(
        store::update_payment_intent_status(pool, "pi-1", PaymentIntentStatus::Queued, now)
            .await
            .unwrap()
    );
    let loaded = store::load_payment_intent_by_voucher(pool, "voucher-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.status, PaymentIntentStatus::Queued);

    // The matching milestone column was stamped.
    let (queued_at,): (Option<chrono::DateTime<Utc>>,) =
        sqlx::query_as("SELECT queued_at FROM zk402_payment_intents WHERE id = 'pi-1'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(queued_at.is_some());

    // A structured failure records code + message.
    assert!(store::fail_payment_intent(
        pool,
        "pi-1",
        PaymentIntentStatus::FailedRecoverable,
        "prover_unavailable",
        "prover offline",
    )
    .await
    .unwrap());
    let failed = store::load_payment_intent_by_voucher(pool, "voucher-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failed.status, PaymentIntentStatus::FailedRecoverable);
    assert_eq!(failed.failure_code.as_deref(), Some("prover_unavailable"));
}

#[tokio::test]
async fn receipt_is_unique_per_intent() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    store::insert_merchant(pool, &new_merchant("merchant-1")).await.unwrap();
    store::insert_payment_intent(pool, &new_intent("pi-1", "voucher-1", "nonce-1", "merchant-1"))
        .await
        .unwrap();

    let receipt_body = json!({"receiptId": "r-1", "settlementState": "queued"});
    assert!(
        store::insert_receipt(pool, "r-1", "pi-1", "success", &receipt_body, "ed25519-sig")
            .await
            .unwrap()
    );

    // Idempotent replay on the same receipt id.
    assert!(
        !store::insert_receipt(pool, "r-1", "pi-1", "success", &receipt_body, "ed25519-sig")
            .await
            .unwrap()
    );

    // A *second* receipt for the same intent violates the one-receipt
    // invariant.
    let err = store::insert_receipt(pool, "r-2", "pi-1", "success", &receipt_body, "ed25519-sig")
        .await
        .unwrap_err();
    assert_eq!(
        constraint_of(&err).as_deref(),
        Some("zk402_receipts_payment_intent_id_uq"),
        "expected the one-receipt-per-intent index to fire, got: {err}"
    );

    let loaded = store::load_receipt_for_intent(pool, "pi-1").await.unwrap().unwrap();
    assert_eq!(loaded.id, "r-1");
    assert_eq!(loaded.receipt_json, receipt_body);
}

#[tokio::test]
async fn audit_event_insert_works() {
    let scope = setup_pool().await;
    let pool = &scope.pool;

    let event = AuditEvent {
        actor: "facilitator".to_owned(),
        entity_type: "payment_intent".to_owned(),
        entity_id: "pi-1".to_owned(),
        event_type: "verification_succeeded".to_owned(),
        event_json: json!({"voucherId": "voucher-1", "network": "zkcoins:regtest"}),
    };
    store::insert_audit_event(pool, &event).await.unwrap();
    store::insert_audit_event(pool, &event).await.unwrap(); // append-only: same event twice is two rows

    assert_eq!(
        store::count_audit_events(pool, "payment_intent", "pi-1").await.unwrap(),
        2
    );
    assert_eq!(
        store::count_audit_events(pool, "payment_intent", "other").await.unwrap(),
        0
    );
}

/// Non-custodial schema lint (hard rule from prompts/00-master-context.md):
/// the production schema must contain no deposit / treasury /
/// payout-balance table or column. Scoped to this test's isolated
/// schema so it sees exactly what the migrations created.
#[tokio::test]
async fn no_custody_schema() {
    let scope = setup_pool().await;
    let pool = &scope.pool;

    let offending_columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema = $1 \
           AND (column_name ~* 'deposit' OR column_name ~* 'treasury' \
                OR column_name ~* 'payout')",
    )
    .bind(scope.schema())
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        offending_columns.is_empty(),
        "custodial column names found: {offending_columns:?}"
    );

    let offending_tables: Vec<(String,)> = sqlx::query_as(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = $1 \
           AND (table_name ~* 'deposit' OR table_name ~* 'treasury' \
                OR table_name ~* 'payout')",
    )
    .bind(scope.schema())
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        offending_tables.is_empty(),
        "custodial table names found: {offending_tables:?}"
    );
}

/// Enum ↔ string round-trip (pure, no DB): every variant survives
/// `as_str` → `FromStr`, and an unknown value fails with context.
#[test]
fn enum_string_roundtrips() {
    for v in MerchantStatus::ALL {
        assert_eq!(v.as_str().parse::<MerchantStatus>().unwrap(), *v);
    }
    for v in AuthorizationStatus::ALL {
        assert_eq!(v.as_str().parse::<AuthorizationStatus>().unwrap(), *v);
    }
    for v in PaymentIntentStatus::ALL {
        assert_eq!(v.as_str().parse::<PaymentIntentStatus>().unwrap(), *v);
    }
    for v in AccessThreshold::ALL {
        assert_eq!(v.as_str().parse::<AccessThreshold>().unwrap(), *v);
    }
    for v in BatchStatus::ALL {
        assert_eq!(v.as_str().parse::<BatchStatus>().unwrap(), *v);
    }
    for v in SettlementKind::ALL {
        assert_eq!(v.as_str().parse::<SettlementKind>().unwrap(), *v);
    }
    for v in SettlementStatus::ALL {
        assert_eq!(v.as_str().parse::<SettlementStatus>().unwrap(), *v);
    }

    let err = "definitely_not_a_status".parse::<PaymentIntentStatus>().unwrap_err();
    assert_eq!(err.kind, "PaymentIntentStatus");
    assert_eq!(err.value, "definitely_not_a_status");
    assert!(err.to_string().contains("PaymentIntentStatus"));
}

/// Enum ↔ CHECK lock-step, DB direction: every `PaymentIntentStatus`
/// variant is accepted by the migration's CHECK constraint, and a value
/// outside the enum is rejected by it. Guards against the migration and
/// the Rust enum drifting apart.
#[tokio::test]
async fn payment_intent_status_check_accepts_all_variants() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    store::insert_merchant(pool, &new_merchant("merchant-1")).await.unwrap();
    store::insert_payment_intent(pool, &new_intent("pi-1", "voucher-1", "nonce-1", "merchant-1"))
        .await
        .unwrap();

    for status in PaymentIntentStatus::ALL {
        assert!(
            store::update_payment_intent_status(pool, "pi-1", *status, Utc::now())
                .await
                .unwrap(),
            "CHECK constraint rejected enum variant {status}"
        );
    }

    let err = sqlx::query("UPDATE zk402_payment_intents SET status = 'bogus' WHERE id = 'pi-1'")
        .execute(pool)
        .await
        .unwrap_err();
    assert!(
        constraint_of(&err).is_some(),
        "expected a CHECK violation for an out-of-enum status, got: {err}"
    );
}
