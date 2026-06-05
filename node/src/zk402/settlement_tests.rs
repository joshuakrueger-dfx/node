//! Step-8 tests: zkCoins settlement integration (mocked backend).
//!
//! Acceptance: mocked publisher-acceptance success path runs the full
//! state machine; prover failure / empty publisher wallet / broadcast
//! failure each map to `failed_recoverable` with the structured code;
//! retry does not double-credit; scanner confirmation advances finality;
//! interrupted batches resume.

use chrono::Utc;

use crate::test_db::setup_pool;

use super::batch::{retry_failed_batch, run_batch_cycle, BatchPolicy};
use super::error::Zk402Error;
use super::settlement::{
    confirm_batch, finalize_batch, resume_pending_batches, settle_batch, BroadcastFailing,
    MockSettlement, ProverFailing, UnfundedPublisher,
};
use super::store;
use super::types::{
    BatchStatus, MerchantStatus, NewMerchant, NewPaymentIntent, PaymentIntentStatus,
    SettlementKind, SettlementStatus,
};

async fn seed_locked_batch(pool: &sqlx::PgPool) -> String {
    store::insert_merchant(
        pool,
        &NewMerchant {
            id: "m1".to_owned(),
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
    let now = Utc::now();
    for (id, amount, fee) in [("pi1", 100i64, 1i64), ("pi2", 200, 2)] {
        let p = NewPaymentIntent {
            id: id.to_owned(),
            voucher_id: format!("v_{id}"),
            authorization_id: None,
            payer: "zkpayer_x".to_owned(),
            merchant_id: "m1".to_owned(),
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
        };
        store::insert_payment_intent(pool, &p).await.unwrap();
        store::update_payment_intent_status(pool, id, PaymentIntentStatus::Queued, now)
            .await
            .unwrap();
    }
    let mut batches = run_batch_cycle(pool, &BatchPolicy::default(), now.timestamp())
        .await
        .unwrap();
    batches.remove(0)
}

#[tokio::test]
async fn happy_path_settles_publishes_confirms_finalizes() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let batch_id = seed_locked_batch(pool).await;
    let now = Utc::now().timestamp();

    settle_batch(pool, &MockSettlement, &batch_id, now)
        .await
        .unwrap();
    let b = store::load_batch(pool, &batch_id).await.unwrap().unwrap();
    assert_eq!(b.status, BatchStatus::Published);
    assert_eq!(
        b.zkcoins_proof_id.as_deref(),
        Some(format!("proof_{batch_id}").as_str())
    );
    assert!(b.commit_txid.as_deref().unwrap().starts_with("4242c_"));
    assert!(b.reveal_txid.as_deref().unwrap().starts_with("4242r_"));

    // Scanner observes → confirmed; finality depth → final.
    assert!(confirm_batch(pool, &batch_id, now).await.unwrap());
    assert!(finalize_batch(pool, &batch_id, now).await.unwrap());

    let b = store::load_batch(pool, &batch_id).await.unwrap().unwrap();
    assert_eq!(b.status, BatchStatus::Final);
    for pi in ["pi1", "pi2"] {
        let intent = store::load_payment_intent(pool, pi).await.unwrap().unwrap();
        assert_eq!(intent.status, PaymentIntentStatus::Final);
    }

    // Ledger: accepted entries are posted, final credits exist once each.
    let ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    let finals: Vec<_> = ledger
        .iter()
        .filter(|s| s.kind == SettlementKind::Final)
        .collect();
    assert_eq!(finals.len(), 2);
    assert_eq!(finals.iter().map(|s| s.amount_sats).sum::<i64>(), 99 + 198);
    assert!(ledger
        .iter()
        .filter(|s| s.kind == SettlementKind::Accepted)
        .all(|s| s.status == SettlementStatus::Posted));
}

#[tokio::test]
async fn failure_modes_map_to_structured_codes() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let now = Utc::now().timestamp();

    // prover failure
    let b1 = seed_locked_batch(pool).await;
    let e = settle_batch(pool, &ProverFailing, &b1, now)
        .await
        .unwrap_err();
    assert_eq!(e, Zk402Error::ProverUnavailable);
    let b = store::load_batch(pool, &b1).await.unwrap().unwrap();
    assert_eq!(b.status, BatchStatus::FailedRecoverable);
    assert_eq!(b.failure_code.as_deref(), Some("prover_unavailable"));

    // empty publisher wallet — retry the SAME batch with a new backend
    assert!(retry_failed_batch(pool, &b1).await.unwrap());
    let e = settle_batch(pool, &UnfundedPublisher, &b1, now)
        .await
        .unwrap_err();
    assert_eq!(e, Zk402Error::PublisherUnfunded);
    let b = store::load_batch(pool, &b1).await.unwrap().unwrap();
    assert_eq!(b.failure_code.as_deref(), Some("publisher_unfunded"));

    // broadcast failure
    assert!(retry_failed_batch(pool, &b1).await.unwrap());
    let e = settle_batch(pool, &BroadcastFailing, &b1, now)
        .await
        .unwrap_err();
    assert_eq!(e, Zk402Error::SettlementQueueUnavailable);
    let b = store::load_batch(pool, &b1).await.unwrap().unwrap();
    assert_eq!(b.status, BatchStatus::FailedRecoverable);
    assert_eq!(b.retry_count, 2);
}

#[tokio::test]
async fn retry_after_failure_succeeds_without_double_credit() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let now = Utc::now().timestamp();
    let batch_id = seed_locked_batch(pool).await;

    // First attempt fails at publish; retry succeeds.
    let _ = settle_batch(pool, &UnfundedPublisher, &batch_id, now)
        .await
        .unwrap_err();
    assert!(retry_failed_batch(pool, &batch_id).await.unwrap());
    settle_batch(pool, &MockSettlement, &batch_id, now)
        .await
        .unwrap();
    assert!(confirm_batch(pool, &batch_id, now).await.unwrap());
    assert!(finalize_batch(pool, &batch_id, now).await.unwrap());

    // Finalize again (spurious scanner replay): must be a no-op.
    assert!(!finalize_batch(pool, &batch_id, now).await.unwrap());

    let ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    let finals: Vec<_> = ledger
        .iter()
        .filter(|s| s.kind == SettlementKind::Final)
        .collect();
    assert_eq!(
        finals.len(),
        2,
        "exactly one final credit per intent, despite retry + replay"
    );
}

#[tokio::test]
async fn confirm_requires_published_state() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let now = Utc::now().timestamp();
    let batch_id = seed_locked_batch(pool).await;

    // Still locked: scanner confirmation is a no-op, not an error.
    assert!(!confirm_batch(pool, &batch_id, now).await.unwrap());
    assert!(!finalize_batch(pool, &batch_id, now).await.unwrap());
}

#[tokio::test]
async fn interrupted_batches_resume_to_locked() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let now = Utc::now().timestamp();
    let batch_id = seed_locked_batch(pool).await;

    // Simulate a crash mid-settlement: force proof_generating, then resume.
    sqlx::query("UPDATE zk402_batches SET status = 'proof_generating' WHERE id = $1")
        .bind(&batch_id)
        .execute(pool)
        .await
        .unwrap();
    let resumed = resume_pending_batches(pool).await.unwrap();
    assert_eq!(resumed, 1);
    let b = store::load_batch(pool, &batch_id).await.unwrap().unwrap();
    assert_eq!(b.status, BatchStatus::Locked);

    // And the resumed batch settles cleanly end-to-end.
    settle_batch(pool, &MockSettlement, &batch_id, now)
        .await
        .unwrap();
    let b = store::load_batch(pool, &batch_id).await.unwrap().unwrap();
    assert_eq!(b.status, BatchStatus::Published);
}
