//! Agent Economy Phase 1 tests — identity (ZK402-AGENT-V1), delegated session
//! keys (ZK402-AUTHORIZATION-V1, closing the authorization seam), and signed
//! disputes (ZK402-DISPUTE-V1).

use bitcoin::secp256k1::{Keypair, Message};
use chrono::Utc;
use serde_json::json;
use shared::SECP256K1;

use crate::test_db::setup_pool;

use super::agents::{
    add_session_key, file_dispute, register_agent, AddSessionKey, FileDispute, RegisterAgent,
};
use super::canonical::{
    agent_signing_digest, authorization_signing_digest, capabilities_hash, dispute_signing_digest,
    AgentFields, AuthorizationFields, DisputeFields,
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

#[test]
fn agent_authorization_dispute_messages_sign_verify_and_tamper_fails() {
    let (kp, payer) = kp_payer(7);

    // ZK402-AGENT-V1
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

    // ZK402-AUTHORIZATION-V1 (identity key signs the delegation)
    let auth = AuthorizationFields {
        network: "zkcoins:regtest".to_owned(),
        identity_payer: payer.clone(),
        session_pubkey: "aa".repeat(32),
        authorized_amount_sats: 10_000,
        spend_limit_per_request_sats: 1_000,
        spend_limit_total_sats: 10_000,
        allowed_merchants_hash: super::canonical::allowed_merchants_hash(&["m1".to_owned()]),
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

    // ZK402-DISPUTE-V1 (complainant signs)
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

#[tokio::test]
async fn register_agent_and_delegate_session_key_with_real_signatures() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (kp, agent_id) = kp_payer(9);

    // Register the agent (ZK402-AGENT-V1 signed by the identity key).
    let caps = vec!["research".to_owned(), "ocr".to_owned()];
    let af = AgentFields {
        agent_id: agent_id.clone(),
        handle: "research-bot@dev".to_owned(),
        capabilities_hash: capabilities_hash(&caps),
        timestamp: 100,
    };
    let req = RegisterAgent {
        agent_id: agent_id.clone(),
        handle: Some("research-bot@dev".to_owned()),
        capabilities: caps,
        timestamp: 100,
        signature: sign(&agent_signing_digest(&af), &kp),
    };
    register_agent(pool, &req).await.unwrap();

    // Bad signature is rejected.
    let bad = RegisterAgent {
        signature: "00".repeat(32),
        ..RegisterAgent {
            agent_id: agent_id.clone(),
            handle: None,
            capabilities: vec![],
            timestamp: 1,
            signature: String::new(),
        }
    };
    assert!(register_agent(pool, &bad).await.is_err());

    // Delegate a session key (ZK402-AUTHORIZATION-V1 signed by the identity key).
    let auth = AuthorizationFields {
        network: "zkcoins:regtest".to_owned(),
        identity_payer: agent_id.clone(),
        session_pubkey: "bb".repeat(32),
        authorized_amount_sats: 10_000,
        spend_limit_per_request_sats: 1_000,
        spend_limit_total_sats: 10_000,
        allowed_merchants_hash: super::canonical::allowed_merchants_hash(&[
            "merchant_demo".to_owned()
        ]),
        facilitator: "https://f.test".to_owned(),
        valid_after: 1,
        valid_before: 9_999_999_999,
    };
    let sk_req = AddSessionKey {
        agent_id: agent_id.clone(),
        session_pubkey: "bb".repeat(32),
        network: "zkcoins:regtest".to_owned(),
        authorized_amount_sats: 10_000,
        spend_limit_per_request_sats: 1_000,
        spend_limit_total_sats: 10_000,
        allowed_merchants: vec!["merchant_demo".to_owned()],
        facilitator: "https://f.test".to_owned(),
        valid_after: 1,
        valid_before: 9_999_999_999,
        scope_json: "{}".to_owned(),
        delegation_signature: sign(&authorization_signing_digest(&auth), &kp),
    };
    let sk_id = add_session_key(pool, &sk_req).await.unwrap();
    assert!(sk_id.starts_with("sk_"));

    // Unknown agent → rejected.
    let (kp2, agent2) = kp_payer(11);
    let auth2 = AuthorizationFields {
        identity_payer: agent2.clone(),
        ..AuthorizationFields {
            network: "zkcoins:regtest".to_owned(),
            identity_payer: agent2.clone(),
            session_pubkey: "cc".repeat(32),
            authorized_amount_sats: 1,
            spend_limit_per_request_sats: 1,
            spend_limit_total_sats: 1,
            allowed_merchants_hash: super::canonical::allowed_merchants_hash(&[]),
            facilitator: "https://f.test".to_owned(),
            valid_after: 1,
            valid_before: 2,
        }
    };
    let sk2 = AddSessionKey {
        agent_id: agent2,
        session_pubkey: "cc".repeat(32),
        network: "zkcoins:regtest".to_owned(),
        authorized_amount_sats: 1,
        spend_limit_per_request_sats: 1,
        spend_limit_total_sats: 1,
        allowed_merchants: vec![],
        facilitator: "https://f.test".to_owned(),
        valid_after: 1,
        valid_before: 2,
        scope_json: "{}".to_owned(),
        delegation_signature: sign(&authorization_signing_digest(&auth2), &kp2),
    };
    assert!(matches!(
        add_session_key(pool, &sk2).await,
        Err(Zk402Error::InvalidPayload)
    ));
}

async fn seed_receipt(pool: &sqlx::PgPool, rid: &str) {
    store::insert_merchant(
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
    .await
    .unwrap();
    let now = Utc::now();
    store::insert_payment_intent(
        pool,
        &NewPaymentIntent {
            id: "pi_d".to_owned(),
            voucher_id: "v_d".to_owned(),
            authorization_id: None,
            payer: "zkpayer_x".to_owned(),
            merchant_id: "m1".to_owned(),
            network: "zkcoins:regtest".to_owned(),
            asset: "btc-sats".to_owned(),
            amount_sats: 10,
            fee_amount_sats: 0,
            resource_hash: "sha256:aa".to_owned(),
            request_hash: "sha256:bb".to_owned(),
            nonce: "n_d".to_owned(),
            valid_after: now - chrono::Duration::hours(1),
            valid_before: now + chrono::Duration::hours(1),
            canonical_message: "m".to_owned(),
            signature_scheme: "bip340-schnorr".to_owned(),
            signature: "sig".to_owned(),
            status: PaymentIntentStatus::Final,
            access_threshold: super::types::AccessThreshold::PublisherAccepted,
        },
    )
    .await
    .unwrap();
    store::insert_receipt(pool, rid, "pi_d", "final", &json!({"r": 1}), "fsig")
        .await
        .unwrap();
}

#[tokio::test]
async fn file_dispute_verifies_signature_persists_and_is_idempotent() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    seed_receipt(pool, "zkr_d1").await;
    let (kp, complainant) = kp_payer(13);

    let d = DisputeFields {
        receipt_id: "zkr_d1".to_owned(),
        complainant: complainant.clone(),
        verdict: "bad".to_owned(),
        reason_hash: "sha256:dd".to_owned(),
        timestamp: 5,
    };
    let req = FileDispute {
        receipt_id: "zkr_d1".to_owned(),
        complainant: complainant.clone(),
        verdict: "bad".to_owned(),
        reason_hash: "sha256:dd".to_owned(),
        timestamp: 5,
        signature: sign(&dispute_signing_digest(&d), &kp),
        counter_signature: None,
    };
    let id = file_dispute(pool, &req).await.unwrap();
    // Idempotent: same (receipt, complainant) → same id, no duplicate row.
    let id2 = file_dispute(pool, &req).await.unwrap();
    assert_eq!(id, id2);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM zk402_disputes WHERE receipt_id = 'zkr_d1'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(count, 1);

    // Unknown receipt → rejected.
    let dn = DisputeFields {
        receipt_id: "zkr_nope".to_owned(),
        ..d
    };
    let req_n = FileDispute {
        receipt_id: "zkr_nope".to_owned(),
        complainant,
        verdict: "bad".to_owned(),
        reason_hash: "sha256:dd".to_owned(),
        timestamp: 5,
        signature: sign(&dispute_signing_digest(&dn), &kp),
        counter_signature: None,
    };
    assert!(matches!(
        file_dispute(pool, &req_n).await,
        Err(Zk402Error::InvalidPayload)
    ));
}
