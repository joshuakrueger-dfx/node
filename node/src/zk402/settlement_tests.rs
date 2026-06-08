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
    advance_intent_settlement, confirm_batch, confirmations, finalize_batch,
    record_receive_observation, resume_pending_batches, reverse_intent, revert_reorged_intents,
    settle_batch, settlement_state_for, BroadcastFailing, MockSettlement, ProverFailing,
    UnfundedPublisher, FINALITY_CONFIRMATIONS,
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

// --- Receive-driven finality (migration 0019) --------------------------------

#[test]
fn confirmations_and_state_thresholds() {
    // Inclusion block counts as the first confirmation; forward anchors clamp.
    assert_eq!(confirmations(100, 100), 1);
    assert_eq!(confirmations(104, 100), 5);
    assert_eq!(confirmations(105, 100), 6);
    assert_eq!(confirmations(99, 100), 0);
    // 0 = mempool → published; 1..5 → confirmed; >=6 → final (PDF §3.9/§3.10).
    assert_eq!(settlement_state_for(0), PaymentIntentStatus::Published);
    assert_eq!(settlement_state_for(1), PaymentIntentStatus::Confirmed);
    assert_eq!(settlement_state_for(5), PaymentIntentStatus::Confirmed);
    assert_eq!(
        settlement_state_for(FINALITY_CONFIRMATIONS),
        PaymentIntentStatus::Final
    );
}

async fn seed_merchant_and_intent(pool: &sqlx::PgPool, mid: &str, iid: &str, amount: i64) {
    let _ = store::insert_merchant(
        pool,
        &NewMerchant {
            id: mid.to_owned(),
            display_name: "M".to_owned(),
            settlement_address: "zk1qm".to_owned(),
            username: None,
            status: MerchantStatus::Active,
            fee_bps: 0,
            fixed_fee_sats: 0,
        },
    )
    .await;
    let now = Utc::now();
    let p = NewPaymentIntent {
        id: iid.to_owned(),
        voucher_id: format!("v_{iid}"),
        authorization_id: None,
        payer: "zkpayer_x".to_owned(),
        merchant_id: mid.to_owned(),
        network: "zkcoins:regtest".to_owned(),
        asset: "btc-sats".to_owned(),
        amount_sats: amount,
        fee_amount_sats: 0,
        resource_hash: "sha256:aa".to_owned(),
        request_hash: format!("sha256:{iid}"),
        nonce: format!("n_{iid}"),
        valid_after: now - chrono::Duration::hours(1),
        valid_before: now + chrono::Duration::hours(1),
        canonical_message: "m".to_owned(),
        signature_scheme: "bip340-schnorr".to_owned(),
        signature: "sig".to_owned(),
        status: PaymentIntentStatus::Received,
        access_threshold: super::types::AccessThreshold::PublisherAccepted,
    };
    store::insert_payment_intent(pool, &p).await.unwrap();
}

#[tokio::test]
async fn advance_drives_published_confirmed_final_from_observations() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_merchant_and_intent(pool, "m1", "pi1", 100).await;
    sqlx::query("UPDATE zk402_payment_intents SET receiving_address = 'addr_pi1' WHERE id = 'pi1'")
        .execute(pool)
        .await
        .unwrap();
    let now = Utc::now().timestamp();

    // (a) mempool observation (no block) → published.
    record_receive_observation(pool, Some("pi1"), "addr_pi1", 100, None, now)
        .await
        .unwrap();
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 0, now)
            .await
            .unwrap(),
        Some(PaymentIntentStatus::Published)
    );

    // (b) mined at block 100, tip 100 → 1 conf → confirmed.
    record_receive_observation(pool, Some("pi1"), "addr_pi1", 100, Some(100), now)
        .await
        .unwrap();
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 100, now)
            .await
            .unwrap(),
        Some(PaymentIntentStatus::Confirmed)
    );

    // (c) tip 105 → 6 conf → final + single ledger credit.
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 105, now)
            .await
            .unwrap(),
        Some(PaymentIntentStatus::Final)
    );
    let intent = store::load_payment_intent(pool, "pi1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(intent.status, PaymentIntentStatus::Final);
    let ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    let finals: Vec<_> = ledger
        .iter()
        .filter(|s| s.kind == SettlementKind::Final)
        .collect();
    assert_eq!(finals.len(), 1);
    assert_eq!(finals[0].amount_sats, 100);

    // (d) idempotent: re-advancing a final intent is a no-op (no double credit).
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 110, now)
            .await
            .unwrap(),
        None
    );
    let ledger2 = store::list_merchant_settlements(pool, "m1").await.unwrap();
    assert_eq!(
        ledger2
            .iter()
            .filter(|s| s.kind == SettlementKind::Final)
            .count(),
        1
    );
}

#[tokio::test]
async fn advance_is_fail_closed_without_address_observation_or_amount() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_merchant_and_intent(pool, "m1", "pi1", 100).await;
    let now = Utc::now().timestamp();

    // No receiving address → unchanged.
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 200, now)
            .await
            .unwrap(),
        None
    );

    // Address set but no observation → unchanged.
    sqlx::query("UPDATE zk402_payment_intents SET receiving_address = 'addr_x' WHERE id = 'pi1'")
        .execute(pool)
        .await
        .unwrap();
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 200, now)
            .await
            .unwrap(),
        None
    );

    // Underpaid observation (50 < 100) → unchanged, no credit.
    record_receive_observation(pool, Some("pi1"), "addr_x", 50, Some(100), now)
        .await
        .unwrap();
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 200, now)
            .await
            .unwrap(),
        None
    );
    let intent = store::load_payment_intent(pool, "pi1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(intent.status, PaymentIntentStatus::Received);
}

#[tokio::test]
async fn watch_advances_only_address_bound_intents() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_merchant_and_intent(pool, "m1", "pi1", 100).await;
    seed_merchant_and_intent(pool, "m1", "pi2", 100).await; // no address bound
    store::set_receiving_address(pool, "pi1", "addr_pi1")
        .await
        .unwrap();
    let now = Utc::now().timestamp();
    record_receive_observation(pool, Some("pi1"), "addr_pi1", 100, Some(100), now)
        .await
        .unwrap();

    // tip 105 → 6 conf → pi1 finalizes; pi2 (no address) is untouched.
    let moved = super::settlement_watch::advance_due_intents(pool, 105, now)
        .await
        .unwrap();
    assert_eq!(moved, 1);
    assert_eq!(
        store::load_payment_intent(pool, "pi1")
            .await
            .unwrap()
            .unwrap()
            .status,
        PaymentIntentStatus::Final
    );
    assert_eq!(
        store::load_payment_intent(pool, "pi2")
            .await
            .unwrap()
            .unwrap()
            .status,
        PaymentIntentStatus::Received
    );
}

// --- Reversal / refund (Phase 1) ---------------------------------------------

async fn seed_final_intent(pool: &sqlx::PgPool, mid: &str, iid: &str, amount: i64) {
    seed_merchant_and_intent(pool, mid, iid, amount).await;
    let addr = format!("addr_{iid}");
    sqlx::query("UPDATE zk402_payment_intents SET receiving_address = $2 WHERE id = $1")
        .bind(iid)
        .bind(&addr)
        .execute(pool)
        .await
        .unwrap();
    let now = Utc::now().timestamp();
    record_receive_observation(pool, Some(iid), &addr, amount, Some(100), now)
        .await
        .unwrap();
    assert_eq!(
        advance_intent_settlement(pool, iid, 105, now)
            .await
            .unwrap(),
        Some(PaymentIntentStatus::Final)
    );
}

#[tokio::test]
async fn reverse_intent_posts_single_reversal_and_is_idempotent() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_final_intent(pool, "m1", "pi1", 100).await;
    let now = Utc::now().timestamp();

    assert!(reverse_intent(pool, "pi1", now).await.unwrap());
    assert_eq!(
        store::load_payment_intent(pool, "pi1")
            .await
            .unwrap()
            .unwrap()
            .status,
        PaymentIntentStatus::Reversed
    );
    let ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    let reversals: Vec<_> = ledger
        .iter()
        .filter(|s| s.kind == SettlementKind::Reversal)
        .collect();
    assert_eq!(reversals.len(), 1);
    assert_eq!(reversals[0].amount_sats, 100);
    // The original final credit is still present (append-only ledger).
    assert_eq!(
        ledger
            .iter()
            .filter(|s| s.kind == SettlementKind::Final)
            .count(),
        1
    );

    // Idempotent: re-reversing an already-reversed intent is a no-op.
    assert!(!reverse_intent(pool, "pi1", now).await.unwrap());
    let ledger2 = store::list_merchant_settlements(pool, "m1").await.unwrap();
    assert_eq!(
        ledger2
            .iter()
            .filter(|s| s.kind == SettlementKind::Reversal)
            .count(),
        1
    );
}

#[tokio::test]
async fn reverse_intent_rejects_uncredited_and_unknown() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_merchant_and_intent(pool, "m1", "pi1", 100).await; // status Received, never credited
    let now = Utc::now().timestamp();
    assert!(!reverse_intent(pool, "pi1", now).await.unwrap());
    assert!(!reverse_intent(pool, "nope", now).await.unwrap());
    let ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    assert!(ledger.iter().all(|s| s.kind != SettlementKind::Reversal));
}

// --- Reorg revert (Phase 1, Spec §3.7) ---------------------------------------

#[tokio::test]
async fn reorg_reverts_confirmed_intent_then_re_applies_under_new_chain() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_merchant_and_intent(pool, "m1", "pi1", 100).await;
    sqlx::query("UPDATE zk402_payment_intents SET receiving_address = 'addr_pi1' WHERE id = 'pi1'")
        .execute(pool)
        .await
        .unwrap();
    let now = Utc::now().timestamp();

    // Anchored at block 102, tip 104 → 3 confs → confirmed.
    record_receive_observation(pool, Some("pi1"), "addr_pi1", 100, Some(102), now)
        .await
        .unwrap();
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 104, now)
            .await
            .unwrap(),
        Some(PaymentIntentStatus::Confirmed)
    );

    // Reorg orphans every block >= 101 (including the inclusion block 102).
    assert_eq!(revert_reorged_intents(pool, 101, now).await.unwrap(), 1);
    assert_eq!(
        store::load_payment_intent(pool, "pi1")
            .await
            .unwrap()
            .unwrap()
            .status,
        PaymentIntentStatus::Reorged
    );
    // Orphaned observation dropped → advance is fail-closed until re-observed.
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 200, now)
            .await
            .unwrap(),
        None
    );

    // The new canonical chain re-includes the transfer at block 150.
    record_receive_observation(pool, Some("pi1"), "addr_pi1", 100, Some(150), now)
        .await
        .unwrap();
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 156, now)
            .await
            .unwrap(),
        Some(PaymentIntentStatus::Final)
    );
    let ledger = store::list_merchant_settlements(pool, "m1").await.unwrap();
    assert_eq!(
        ledger
            .iter()
            .filter(|s| s.kind == SettlementKind::Final)
            .count(),
        1
    );
}

#[tokio::test]
async fn reorg_below_inclusion_height_leaves_intent_untouched() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_merchant_and_intent(pool, "m1", "pi1", 100).await;
    sqlx::query("UPDATE zk402_payment_intents SET receiving_address = 'addr_pi1' WHERE id = 'pi1'")
        .execute(pool)
        .await
        .unwrap();
    let now = Utc::now().timestamp();
    record_receive_observation(pool, Some("pi1"), "addr_pi1", 100, Some(100), now)
        .await
        .unwrap();
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 102, now)
            .await
            .unwrap(),
        Some(PaymentIntentStatus::Confirmed)
    );
    // Reorg only orphans blocks >= 150 — the inclusion block 100 is untouched.
    assert_eq!(revert_reorged_intents(pool, 150, now).await.unwrap(), 0);
    assert_eq!(
        store::load_payment_intent(pool, "pi1")
            .await
            .unwrap()
            .unwrap()
            .status,
        PaymentIntentStatus::Confirmed
    );
}

#[tokio::test]
async fn advance_is_a_noop_when_not_strictly_forward() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_merchant_and_intent(pool, "m1", "pi1", 100).await;
    sqlx::query("UPDATE zk402_payment_intents SET receiving_address = 'addr_pi1' WHERE id = 'pi1'")
        .execute(pool)
        .await
        .unwrap();
    let now = Utc::now().timestamp();
    record_receive_observation(pool, Some("pi1"), "addr_pi1", 100, Some(100), now)
        .await
        .unwrap();
    // tip 100 → 1 conf → confirmed.
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 100, now)
            .await
            .unwrap(),
        Some(PaymentIntentStatus::Confirmed)
    );
    // Same tip again: target (confirmed) is not strictly past current → no-op.
    assert_eq!(
        advance_intent_settlement(pool, "pi1", 100, now)
            .await
            .unwrap(),
        None
    );
}
