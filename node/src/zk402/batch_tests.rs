//! Step-7 tests: batch worker.
//!
//! Acceptance: batches eligible intents; does not batch expired ones;
//! correct merchant grouping; settlement entries posted exactly once;
//! resumes after a crash (rolled-back cycle leaves clean queued state);
//! a failed batch can be retried without double-posting.

use chrono::Utc;

use crate::test_db::setup_pool;

use super::batch::{
    expire_stale_intents, fail_batch, retry_failed_batch, run_batch_cycle, BatchPolicy,
};
use super::store;
use super::types::{
    BatchStatus, MerchantStatus, NewMerchant, NewPaymentIntent, PaymentIntentStatus,
};

async fn merchant(pool: &sqlx::PgPool, id: &str) {
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

/// Insert a queued intent directly (bypassing settle) with a chosen
/// validity window, then advance it to `queued`.
async fn queued_intent(
    pool: &sqlx::PgPool,
    id: &str,
    merchant_id: &str,
    amount: i64,
    fee: i64,
    valid_before_unix: i64,
) {
    let now = Utc::now();
    let p = NewPaymentIntent {
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
        valid_before: chrono::TimeZone::timestamp_opt(&Utc, valid_before_unix, 0)
            .single()
            .unwrap(),
        canonical_message: "m".to_owned(),
        signature_scheme: "bip340-schnorr".to_owned(),
        signature: "sig".to_owned(),
        status: PaymentIntentStatus::Received,
        access_threshold: super::types::AccessThreshold::PublisherAccepted,
    };
    store::insert_payment_intent(pool, &p).await.unwrap();
    store::update_payment_intent_status(pool, id, PaymentIntentStatus::Queued, now)
        .await
        .unwrap();
}

#[tokio::test]
async fn batches_eligible_intents_grouped_by_merchant() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let now = Utc::now().timestamp();
    merchant(pool, "m1").await;
    merchant(pool, "m2").await;
    queued_intent(pool, "pi1", "m1", 100, 1, now + 3600).await;
    queued_intent(pool, "pi2", "m1", 200, 2, now + 3600).await;
    queued_intent(pool, "pi3", "m2", 50, 0, now + 3600).await;

    let batches = run_batch_cycle(pool, &BatchPolicy::default(), now)
        .await
        .unwrap();
    assert_eq!(batches.len(), 2, "one batch per merchant");

    // Each intent advanced to batching and has an accepted ledger entry.
    for pi in ["pi1", "pi2", "pi3"] {
        let intent = store::load_payment_intent(pool, pi).await.unwrap().unwrap();
        assert_eq!(intent.status, PaymentIntentStatus::Batching);
    }
    // m1 batch totals 300 gross / 3 fee / 297 net over 2 intents.
    let m1_ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    assert_eq!(m1_ledger.len(), 2);
    assert_eq!(
        m1_ledger.iter().map(|s| s.amount_sats).sum::<i64>(),
        99 + 198
    );

    let m2_ledger = store::list_merchant_settlements(pool, "m2").await.unwrap();
    assert_eq!(m2_ledger.len(), 1);
    assert_eq!(m2_ledger[0].amount_sats, 50);
}

#[tokio::test]
async fn does_not_batch_expired_intents() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let now = Utc::now().timestamp();
    merchant(pool, "m1").await;
    queued_intent(pool, "fresh", "m1", 100, 0, now + 3600).await;
    queued_intent(pool, "stale", "m1", 100, 0, now - 10).await; // already past validBefore

    let expired = expire_stale_intents(pool, now).await.unwrap();
    assert_eq!(expired, 1);

    let batches = run_batch_cycle(pool, &BatchPolicy::default(), now)
        .await
        .unwrap();
    assert_eq!(batches.len(), 1);

    let stale = store::load_payment_intent(pool, "stale")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stale.status, PaymentIntentStatus::Expired);
    let fresh = store::load_payment_intent(pool, "fresh")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fresh.status, PaymentIntentStatus::Batching);
}

#[tokio::test]
async fn settlement_entries_posted_exactly_once_across_reruns() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let now = Utc::now().timestamp();
    merchant(pool, "m1").await;
    queued_intent(pool, "pi1", "m1", 100, 1, now + 3600).await;

    run_batch_cycle(pool, &BatchPolicy::default(), now)
        .await
        .unwrap();
    // The intent is no longer queued, so a second cycle is a no-op...
    let again = run_batch_cycle(pool, &BatchPolicy::default(), now)
        .await
        .unwrap();
    assert!(again.is_empty());

    // ...and even forcing the intent back to queued and re-running does
    // not double-post the accepted ledger entry (deterministic id).
    store::update_payment_intent_status(pool, "pi1", PaymentIntentStatus::Queued, Utc::now())
        .await
        .unwrap();
    run_batch_cycle(pool, &BatchPolicy::default(), now)
        .await
        .unwrap();

    let ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    assert_eq!(ledger.len(), 1, "exactly one accepted entry despite re-run");
}

#[tokio::test]
async fn failed_batch_retries_without_double_posting() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let now = Utc::now().timestamp();
    merchant(pool, "m1").await;
    queued_intent(pool, "pi1", "m1", 100, 1, now + 3600).await;
    let batches = run_batch_cycle(pool, &BatchPolicy::default(), now)
        .await
        .unwrap();
    let batch_id = &batches[0];

    // Simulate a publish failure, then retry.
    assert!(fail_batch(
        pool,
        batch_id,
        BatchStatus::FailedRecoverable,
        "publisher_unfunded",
        "no utxos"
    )
    .await
    .unwrap());
    assert!(retry_failed_batch(pool, batch_id).await.unwrap());

    let batch = store::load_batch(pool, batch_id).await.unwrap().unwrap();
    assert_eq!(batch.status, BatchStatus::Locked);
    assert_eq!(batch.retry_count, 1);

    // Retry did not duplicate the ledger entry.
    let ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    assert_eq!(ledger.len(), 1);
}

#[tokio::test]
async fn empty_queue_is_a_noop() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let batches = run_batch_cycle(pool, &BatchPolicy::default(), Utc::now().timestamp())
        .await
        .unwrap();
    assert!(batches.is_empty());
}
