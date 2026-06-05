//! ZK402-Stream (Flow-D) tests — the Claude-token billing path.
//!
//! Pins: byte-stable STREAM-V1; signature covers max + cumulative +
//! request binding; strictly-monotone cumulative (replay rejected);
//! actual ≤ max; the metered total can NEVER exceed the signed cap under
//! 100 parallel meterings; usage ledger sums to the metered cursor; and
//! the end-to-end Claude pricing math (tokens → micro-sats → sats).

use bitcoin::secp256k1::Keypair;
use chrono::{Duration, Utc};
use shared::SECP256K1;

use crate::test_db::setup_pool;

use super::authorization::{create_authorization, NewAuthorizationRequest};
use super::canonical::{canonical_stream_message, stream_signing_digest, StreamVoucherFields};
use super::error::Zk402Error;
use super::streaming::{channel_meter, cost_sats, meter, usage_total, Usage};

fn keypair() -> (Keypair, String) {
    let mut sk = [0u8; 32];
    sk[31] = 13;
    let kp = Keypair::from_seckey_slice(&SECP256K1, &sk).unwrap();
    let payer = format!(
        "zkpayer_{}",
        hex::encode(kp.x_only_public_key().0.serialize())
    );
    (kp, payer)
}

async fn metering_channel(pool: &sqlx::PgPool, payer: &str, cap: i64) -> String {
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
            allowed_merchants: vec![],
            facilitator_origin: "https://facilitator.test".to_owned(),
            session_public_key: None,
            signature: "auth-sig".to_owned(),
        },
    )
    .await
    .unwrap();
    "chan_1".to_owned()
}

fn fields(payer: &str, seq: i64, max: i64, cumulative: i64, now: i64) -> StreamVoucherFields {
    StreamVoucherFields {
        network: "zkcoins:regtest".to_owned(),
        channel_id: "chan_1".to_owned(),
        voucher_seq: seq,
        payer: payer.to_owned(),
        merchant: "merchant_1".to_owned(),
        max_amount_sats: max,
        cumulative_authorized_sats: cumulative,
        resource_hash: "sha256:aa".to_owned(),
        request_hash: format!("sha256:req{seq}"),
        valid_after: now - 10,
        valid_before: now + 60,
        facilitator: "https://facilitator.test".to_owned(),
        access_threshold: "metered".to_owned(),
    }
}

fn sign(f: &StreamVoucherFields, kp: &Keypair) -> String {
    let msg = bitcoin::secp256k1::Message::from_digest_slice(&stream_signing_digest(f)).unwrap();
    hex::encode(SECP256K1.sign_schnorr_no_aux_rand(&msg, kp).serialize())
}

fn tokens(input: i64, output: i64) -> Vec<Usage> {
    // Sonnet-4.6-shaped pricing: $3/M input, $15/M output. At a demo
    // rate of 1000 sats/$ that is 3000 sats/M = 3 microsats/token input
    // and 15 microsats/token output.
    vec![
        Usage {
            unit: "input_tokens".into(),
            quantity: input,
            unit_price_microsats: 3,
            model: Some("claude-sonnet-4-6".into()),
        },
        Usage {
            unit: "output_tokens".into(),
            quantity: output,
            unit_price_microsats: 15,
            model: Some("claude-sonnet-4-6".into()),
        },
    ]
}

#[test]
fn stream_canonical_is_byte_stable_with_fixed_layout() {
    let (_kp, payer) = keypair();
    let f = fields(&payer, 1, 100, 100, 1_779_900_000);
    let a = canonical_stream_message(&f);
    assert_eq!(a, canonical_stream_message(&f.clone()));
    let s = String::from_utf8(a).unwrap();
    assert!(s.starts_with("ZK402-STREAM-V1\nscheme=zkcoins-publisher\n"));
    assert!(s.contains("\nmax_amount=100\ncumulative_authorized=100\n"));
    assert!(s.ends_with("\naccess_threshold=metered"));
}

#[test]
fn cost_math_rounds_up_and_matches_claude_pricing() {
    // 10k input + 2k output @ Sonnet pricing (3 / 15 microsats per token)
    // = 30_000 + 30_000 microsats = 0.03 + 0.03 sats → ceil = 1 sat each.
    assert_eq!(cost_sats(10_000, 3), 1);
    assert_eq!(cost_sats(2_000, 15), 1);
    // A million output tokens = 15_000_000 micro = exactly 15 sats.
    assert_eq!(cost_sats(1_000_000, 15), 15);
    // Rounding is always UP, never undercharging.
    assert_eq!(cost_sats(1, 1), 1);
    assert_eq!(cost_sats(0, 15), 0);
}

#[tokio::test]
async fn meter_charges_actual_and_tracks_cursors() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (kp, payer) = keypair();
    metering_channel(pool, &payer, 1_000).await;
    let now = Utc::now().timestamp();

    // Voucher 1: up to 100, actual usage = 1M output tokens = 15 sats.
    let f1 = fields(&payer, 1, 100, 100, now);
    let out = meter(
        pool,
        &f1,
        &sign(&f1, &kp),
        &[Usage {
            unit: "output_tokens".into(),
            quantity: 1_000_000,
            unit_price_microsats: 15,
            model: None,
        }],
        now,
    )
    .await
    .unwrap();
    assert_eq!(out.actual_cost_sats, 15);
    assert_eq!(out.unspent_sats, 85);
    assert_eq!(out.metered_total_sats, 15);
    assert_eq!(out.cumulative_authorized_sats, 100);

    // Voucher 2: cumulative advances to 250, actual 20.
    let f2 = fields(&payer, 2, 150, 250, now);
    let out = meter(
        pool,
        &f2,
        &sign(&f2, &kp),
        &[Usage {
            unit: "input_tokens".into(),
            quantity: 20_000_000,
            unit_price_microsats: 1,
            model: None,
        }],
        now,
    )
    .await
    .unwrap();
    assert_eq!(out.actual_cost_sats, 20);
    assert_eq!(out.metered_total_sats, 35);

    // Ledger consistency: usage events sum to the metered cursor.
    assert_eq!(usage_total(pool, "chan_1").await.unwrap(), 35);
    let (metered, cumulative, cap) = channel_meter(pool, "chan_1").await.unwrap();
    assert_eq!((metered, cumulative, cap), (35, 250, 1_000));
}

#[tokio::test]
async fn replayed_or_decreased_cumulative_is_rejected() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (kp, payer) = keypair();
    metering_channel(pool, &payer, 1_000).await;
    let now = Utc::now().timestamp();

    let f1 = fields(&payer, 1, 100, 100, now);
    meter(pool, &f1, &sign(&f1, &kp), &tokens(10_000, 2_000), now)
        .await
        .unwrap();

    // Exact replay of the same voucher → cumulative not greater → rejected.
    let e = meter(pool, &f1, &sign(&f1, &kp), &tokens(10_000, 2_000), now)
        .await
        .unwrap_err();
    assert_eq!(e, Zk402Error::AuthorizationLimitExceeded);

    // A decreased cumulative (rollback attempt) → rejected.
    let f_back = fields(&payer, 2, 50, 50, now);
    let e = meter(pool, &f_back, &sign(&f_back, &kp), &tokens(1_000, 0), now)
        .await
        .unwrap_err();
    assert_eq!(e, Zk402Error::AuthorizationLimitExceeded);
}

#[tokio::test]
async fn actual_above_voucher_max_and_tampered_signature_fail() {
    let scope = setup_pool().await;
    let pool = &scope.pool;
    let (kp, payer) = keypair();
    metering_channel(pool, &payer, 1_000).await;
    let now = Utc::now().timestamp();

    // Actual (15 sats) above the voucher max (10) → amount_mismatch.
    let f = fields(&payer, 1, 10, 10, now);
    let e = meter(
        pool,
        &f,
        &sign(&f, &kp),
        &[Usage {
            unit: "output_tokens".into(),
            quantity: 1_000_000,
            unit_price_microsats: 15,
            model: None,
        }],
        now,
    )
    .await
    .unwrap_err();
    assert_eq!(e, Zk402Error::AmountMismatch);

    // Tampered max (signature no longer matches) → invalid_signature.
    let f_ok = fields(&payer, 2, 100, 100, now);
    let sig = sign(&f_ok, &kp);
    let mut f_tampered = f_ok.clone();
    f_tampered.max_amount_sats = 1_000;
    let e = meter(pool, &f_tampered, &sig, &tokens(1_000, 100), now)
        .await
        .unwrap_err();
    assert_eq!(e, Zk402Error::InvalidSignature);

    // Expired voucher window.
    let mut f_exp = fields(&payer, 3, 100, 200, now);
    f_exp.valid_before = now - 1;
    let e = meter(pool, &f_exp, &sign(&f_exp, &kp), &tokens(1_000, 100), now)
        .await
        .unwrap_err();
    assert_eq!(e, Zk402Error::ExpiredPayment);
}

/// The safety headline: 100 PARALLEL meterings against a cap of 250 —
/// whatever the race outcome, the metered total never exceeds the cap
/// and the usage ledger stays consistent with the cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn hundred_parallel_meterings_never_exceed_cap() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let (kp, payer) = keypair();
    metering_channel(&pool, &payer, 250).await;
    let now = Utc::now().timestamp();

    let mut handles = Vec::new();
    for i in 1..=100i64 {
        let pool = pool.clone();
        let f = fields(&payer, i, 10, i * 10, now);
        let sig = sign(&f, &kp);
        handles.push(tokio::spawn(async move {
            meter(
                &pool,
                &f,
                &sig,
                &[Usage {
                    unit: "request".into(),
                    quantity: 1,
                    unit_price_microsats: 10_000_000,
                    model: None,
                }],
                now,
            )
            .await
            .is_ok()
        }));
    }
    let mut ok = 0;
    for h in handles {
        if h.await.unwrap() {
            ok += 1;
        }
    }

    let (metered, cumulative, cap) = channel_meter(&pool, "chan_1").await.unwrap();
    assert!(metered <= cap, "OVERSPEND: metered {metered} > cap {cap}");
    assert!(cumulative <= cap, "ceiling breached: {cumulative} > {cap}");
    assert_eq!(
        usage_total(&pool, "chan_1").await.unwrap(),
        metered,
        "usage ledger must sum to the metered cursor"
    );
    assert!(
        ok >= 1 && ok <= 25,
        "at most cap/amount meterings can succeed, got {ok}"
    );
}

/// The exact STREAM-V1 bytes for a fixed input. The identical string is
/// asserted in the `@zk402/sdk` test, guaranteeing the Rust and TS
/// encoders are byte-for-byte equal (there is no shared fixture for
/// STREAM-V1, so this golden IS the cross-language pin).
const STREAM_GOLDEN: &str = "ZK402-STREAM-V1\nscheme=zkcoins-publisher\nnetwork=zkcoins:regtest\nchannel_id=chan_1\nvoucher_seq=1\npayer=zkpayer_aa\nmerchant=merchant_1\nasset=btc-sats\nmax_amount=100\ncumulative_authorized=100\nresource_hash=sha256:aa\nrequest_hash=sha256:bb\nvalid_after=1779900000\nvalid_before=1779900060\nfacilitator=https://facilitator.test\naccess_threshold=metered";

#[test]
fn stream_canonical_matches_cross_language_golden() {
    let f = StreamVoucherFields {
        network: "zkcoins:regtest".to_owned(),
        channel_id: "chan_1".to_owned(),
        voucher_seq: 1,
        payer: "zkpayer_aa".to_owned(),
        merchant: "merchant_1".to_owned(),
        max_amount_sats: 100,
        cumulative_authorized_sats: 100,
        resource_hash: "sha256:aa".to_owned(),
        request_hash: "sha256:bb".to_owned(),
        valid_after: 1_779_900_000,
        valid_before: 1_779_900_060,
        facilitator: "https://facilitator.test".to_owned(),
        access_threshold: "metered".to_owned(),
    };
    assert_eq!(
        String::from_utf8(canonical_stream_message(&f)).unwrap(),
        STREAM_GOLDEN
    );
}
