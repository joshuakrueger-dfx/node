//! Agent Economy Phase 1 tests — identity (ZK402-AGENT-V1), delegated session
//! keys (ZK402-AUTHORIZATION-V1 + use-time enforcement), and signed disputes
//! (ZK402-DISPUTE-V1, bound to the receipt's payer).

use bitcoin::secp256k1::{Keypair, Message};
use chrono::Utc;
use serde_json::json;
use shared::SECP256K1;

use crate::test_db::setup_pool;

use super::agents::{
    add_session_key, file_dispute, register_agent, revoke_session_key, validate_session_delegation,
    AddSessionKey, FileDispute, RegisterAgent,
};
use super::canonical::{
    agent_signing_digest, allowed_merchants_hash, authorization_signing_digest, capabilities_hash,
    dispute_signing_digest, AgentFields, AuthorizationFields, DisputeFields,
};
use super::error::Zk402Error;
use super::signature::{
    verify_agent_signature, verify_authorization_signature, verify_dispute_signature,
};
use super::store;
use super::types::{MerchantStatus, NewMerchant, NewPaymentIntent, PaymentIntentStatus};

fn kp_payer(seed: u8) -> (Keypair, String) {
    let mut sk = [0u8; 32];
    sk[31] = seed;
    let kp = Keypair::from_seckey_slice(&SECP256K1, &sk).unwrap();
    let payer = format!(
        "zkpayer_{}",
        hex::encode(kp.x_only_public_key().0.serialize())
    );
    (kp, payer)
}
fn sign(digest: &[u8; 32], kp: &Keypair) -> String {
    let msg = Message::from_digest_slice(digest).unwrap();
    hex::encode(SECP256K1.sign_schnorr_no_aux_rand(&msg, kp).serialize())
}
fn now() -> i64 {
    Utc::now().timestamp()
}

#[test]
fn agent_authorization_dispute_messages_sign_verify_and_tamper_fails() {
    let (kp, payer) = kp_payer(7);

    let af = AgentFields {
        agent_id: payer.clone(),
        handle: "bot@dev".to_owned(),
        capabilities_hash: capabilities_hash(&["ocr".to_owned()]),
        timestamp: 100,
    };
    let sig = sign(&agent_signing_digest(&af), &kp);
    assert!(verify_agent_signature(&af, &sig).is_ok());
    let tampered = AgentFields {
        timestamp: 101,
        ..af
    };
    assert!(matches!(
        verify_agent_signature(&tampered, &sig),
        Err(Zk402Error::InvalidSignature)
    ));

    let auth = AuthorizationFields {
        network: "zkcoins:regtest".to_owned(),
        identity_payer: payer.clone(),
        session_pubkey: "aa".repeat(32),
        authorized_amount_sats: 10_000,
        spend_limit_per_request_sats: 1_000,
        spend_limit_total_sats: 10_000,
        allowed_merchants_hash: allowed_merchants_hash(&["m1".to_owned()]),
        facilitator: "https://f.test".to_owned(),
        valid_after: 1,
        valid_before: 9_999_999_999,
    };
    let asig = sign(&authorization_signing_digest(&auth), &kp);
    assert!(verify_authorization_signature(&auth, &asig).is_ok());
    let bad = AuthorizationFields {
        spend_limit_total_sats: 999_999,
        ..auth
    };
    assert!(verify_authorization_signature(&bad, &asig).is_err());

    let d = DisputeFields {
        receipt_id: "zkr_x".to_owned(),
        complainant: payer.clone(),
        verdict: "bad".to_owned(),
        reason_hash: "sha256:dd".to_owned(),
        timestamp: 5,
    };
    let dsig = sign(&dispute_signing_digest(&d), &kp);
    assert!(verify_dispute_signature(&d, &dsig).is_ok());
    let dbad = DisputeFields {
        verdict: "ok".to_owned(),
        ..d
    };
    assert!(verify_dispute_signature(&dbad, &dsig).is_err());
}

/// Register an agent with a fresh, correctly-signed ZK402-AGENT-V1.
async fn register(pool: &sqlx::PgPool, kp: &Keypair, agent_id: &str) {
    let t = now();
    let caps = vec!["research".to_owned(), "ocr".to_owned()];
    let af = AgentFields {
        agent_id: agent_id.to_owned(),
        handle: format!("bot-{agent_id}@dev"),
        capabilities_hash: capabilities_hash(&caps),
        timestamp: t,
    };
    register_agent(
        pool,
        &RegisterAgent {
            agent_id: agent_id.to_owned(),
            handle: Some(format!("bot-{agent_id}@dev")),
            capabilities: caps,
            timestamp: t,
            signature: sign(&agent_signing_digest(&af), kp),
        },
        t,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn register_rejects_stale_message_and_bad_signature() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (kp, agent_id) = kp_payer(9);
    // Stale timestamp (older than the freshness window) → replay-rejected.
    let stale = now() - 200_000;
    let af = AgentFields {
        agent_id: agent_id.clone(),
        handle: String::new(),
        capabilities_hash: capabilities_hash(&[]),
        timestamp: stale,
    };
    assert!(matches!(
        register_agent(
            pool,
            &RegisterAgent {
                agent_id: agent_id.clone(),
                handle: None,
                capabilities: vec![],
                timestamp: stale,
                signature: sign(&agent_signing_digest(&af), &kp),
            },
            now(),
        )
        .await,
        Err(Zk402Error::InvalidPayload)
    ));
    // Bad signature (fresh) → rejected.
    assert!(register_agent(
        pool,
        &RegisterAgent {
            agent_id,
            handle: None,
            capabilities: vec![],
            timestamp: now(),
            signature: "00".repeat(32),
        },
        now(),
    )
    .await
    .is_err());
}

#[tokio::test]
async fn delegate_session_key_then_enforce_caps_window_and_revocation() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (kp, agent_id) = kp_payer(15);
    register(pool, &kp, &agent_id).await;

    let t = now();
    let va = t - 10;
    let vb = t + 86_400;
    let merchants = vec!["merchant_demo".to_owned()];
    let spub = "bb".repeat(32);
    let auth = AuthorizationFields {
        network: "zkcoins:regtest".to_owned(),
        identity_payer: agent_id.clone(),
        session_pubkey: spub.clone(),
        authorized_amount_sats: 10_000,
        spend_limit_per_request_sats: 1_000,
        spend_limit_total_sats: 10_000,
        allowed_merchants_hash: allowed_merchants_hash(&merchants),
        facilitator: "https://f.test".to_owned(),
        valid_after: va,
        valid_before: vb,
    };
    add_session_key(
        pool,
        &AddSessionKey {
            agent_id: agent_id.clone(),
            session_pubkey: spub.clone(),
            network: "zkcoins:regtest".to_owned(),
            authorized_amount_sats: 10_000,
            spend_limit_per_request_sats: 1_000,
            spend_limit_total_sats: 10_000,
            allowed_merchants: merchants,
            facilitator: "https://f.test".to_owned(),
            valid_after: va,
            valid_before: vb,
            scope_json: "{}".to_owned(),
            delegation_signature: sign(&authorization_signing_digest(&auth), &kp),
        },
        t,
    )
    .await
    .unwrap();

    // Enforcement: within caps/window/merchant → ok.
    assert!(
        validate_session_delegation(pool, &spub, 500, "merchant_demo", t)
            .await
            .is_ok()
    );
    // Over per-request cap → rejected.
    assert!(
        validate_session_delegation(pool, &spub, 5_000, "merchant_demo", t)
            .await
            .is_err()
    );
    // Wrong merchant → rejected.
    assert!(
        validate_session_delegation(pool, &spub, 500, "merchant_evil", t)
            .await
            .is_err()
    );
    // Outside window → rejected.
    assert!(
        validate_session_delegation(pool, &spub, 500, "merchant_demo", vb + 1)
            .await
            .is_err()
    );
    // Revoke → afterwards rejected.
    assert!(revoke_session_key(pool, &spub, t).await.unwrap());
    assert!(
        validate_session_delegation(pool, &spub, 500, "merchant_demo", t)
            .await
            .is_err()
    );

    // Already-expired window at creation is rejected.
    assert!(matches!(
        add_session_key(
            pool,
            &AddSessionKey {
                agent_id: agent_id.clone(),
                session_pubkey: "cc".repeat(32),
                network: "zkcoins:regtest".to_owned(),
                authorized_amount_sats: 1,
                spend_limit_per_request_sats: 1,
                spend_limit_total_sats: 1,
                allowed_merchants: vec![],
                facilitator: "https://f.test".to_owned(),
                valid_after: t - 100,
                valid_before: t - 50,
                scope_json: "{}".to_owned(),
                delegation_signature: "00".repeat(32),
            },
            t,
        )
        .await,
        Err(Zk402Error::InvalidPayload)
    ));

    // Unknown agent → rejected.
    let (kp2, agent2) = kp_payer(17);
    let auth2 = AuthorizationFields {
        network: "zkcoins:regtest".to_owned(),
        identity_payer: agent2.clone(),
        session_pubkey: "dd".repeat(32),
        authorized_amount_sats: 1,
        spend_limit_per_request_sats: 1,
        spend_limit_total_sats: 1,
        allowed_merchants_hash: allowed_merchants_hash(&[]),
        facilitator: "https://f.test".to_owned(),
        valid_after: va,
        valid_before: vb,
    };
    assert!(matches!(
        add_session_key(
            pool,
            &AddSessionKey {
                agent_id: agent2,
                session_pubkey: "dd".repeat(32),
                network: "zkcoins:regtest".to_owned(),
                authorized_amount_sats: 1,
                spend_limit_per_request_sats: 1,
                spend_limit_total_sats: 1,
                allowed_merchants: vec![],
                facilitator: "https://f.test".to_owned(),
                valid_after: va,
                valid_before: vb,
                scope_json: "{}".to_owned(),
                delegation_signature: sign(&authorization_signing_digest(&auth2), &kp2),
            },
            t,
        )
        .await,
        Err(Zk402Error::InvalidPayload)
    ));
}

/// Seed a merchant + intent + receipt whose payer is `payer`.
async fn seed_receipt(pool: &sqlx::PgPool, rid: &str, payer: &str) {
    let _ = store::insert_merchant(
        pool,
        &NewMerchant {
            id: "m1".to_owned(),
            display_name: "M".to_owned(),
            settlement_address: "zk1qm".to_owned(),
            username: None,
            status: MerchantStatus::Active,
            fee_bps: 0,
            fixed_fee_sats: 0,
        },
    )
    .await;
    let n = Utc::now();
    store::insert_payment_intent(
        pool,
        &NewPaymentIntent {
            id: format!("pi_{rid}"),
            voucher_id: format!("v_{rid}"),
            authorization_id: None,
            payer: payer.to_owned(),
            merchant_id: "m1".to_owned(),
            network: "zkcoins:regtest".to_owned(),
            asset: "btc-sats".to_owned(),
            amount_sats: 10,
            fee_amount_sats: 0,
            resource_hash: "sha256:aa".to_owned(),
            request_hash: format!("sha256:{rid}"),
            nonce: format!("n_{rid}"),
            valid_after: n - chrono::Duration::hours(1),
            valid_before: n + chrono::Duration::hours(1),
            canonical_message: "m".to_owned(),
            signature_scheme: "bip340-schnorr".to_owned(),
            signature: "sig".to_owned(),
            status: PaymentIntentStatus::Final,
            access_threshold: super::types::AccessThreshold::PublisherAccepted,
        },
    )
    .await
    .unwrap();
    store::insert_receipt(
        pool,
        rid,
        &format!("pi_{rid}"),
        "final",
        &json!({"r": 1}),
        "fsig",
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn dispute_must_come_from_the_receipt_payer_and_is_idempotent() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (kp, payer) = kp_payer(21);
    seed_receipt(pool, "zkr_d1", &payer).await;

    let t = now();
    let mk = |kp: &Keypair, complainant: &str| {
        let d = DisputeFields {
            receipt_id: "zkr_d1".to_owned(),
            complainant: complainant.to_owned(),
            verdict: "bad".to_owned(),
            reason_hash: "sha256:dd".to_owned(),
            timestamp: t,
        };
        FileDispute {
            receipt_id: "zkr_d1".to_owned(),
            complainant: complainant.to_owned(),
            verdict: "bad".to_owned(),
            reason_hash: "sha256:dd".to_owned(),
            timestamp: t,
            signature: sign(&dispute_signing_digest(&d), kp),
        }
    };

    // The receipt's payer can dispute it.
    let id = file_dispute(pool, &mk(&kp, &payer), t).await.unwrap();
    // Idempotent.
    assert_eq!(file_dispute(pool, &mk(&kp, &payer), t).await.unwrap(), id);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM zk402_disputes WHERE receipt_id = 'zkr_d1'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(count, 1);

    // A DIFFERENT key (not the payer) signs validly but is REJECTED — no
    // third-party reputation poisoning.
    let (kp2, other) = kp_payer(22);
    assert!(matches!(
        file_dispute(pool, &mk(&kp2, &other), t).await,
        Err(Zk402Error::InvalidPayload)
    ));

    // Unknown receipt → rejected.
    let d = DisputeFields {
        receipt_id: "zkr_nope".to_owned(),
        complainant: payer.clone(),
        verdict: "bad".to_owned(),
        reason_hash: "sha256:dd".to_owned(),
        timestamp: t,
    };
    assert!(matches!(
        file_dispute(
            pool,
            &FileDispute {
                receipt_id: "zkr_nope".to_owned(),
                complainant: payer,
                verdict: "bad".to_owned(),
                reason_hash: "sha256:dd".to_owned(),
                timestamp: t,
                signature: sign(&dispute_signing_digest(&d), &kp),
            },
            t,
        )
        .await,
        Err(Zk402Error::InvalidPayload)
    ));
}
