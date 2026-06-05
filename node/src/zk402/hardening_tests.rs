//! Step-10 tests: hardening primitives.
//!
//! Acceptance (the testable, deterministic slices of the drill set):
//! rate limits on invalid signatures are enforced; the receipt key can
//! be rotated in a way that keeps prior-`kid` receipts verifiable.

use super::hardening::{InvalidSigLimiter, KeyRegistry};

#[test]
fn invalid_signature_rate_limit_trips_at_threshold_and_resets_next_window() {
    let limiter = InvalidSigLimiter::new(3, 60);
    let key = "zkpayer_abuser";
    let now = 1_000_000; // window = now/60

    // First 3 attempts allowed; each failure recorded.
    for _ in 0..3 {
        assert!(limiter.allowed(key, now));
        limiter.record_failure(key, now);
    }
    // 4th in the same window is blocked.
    assert!(!limiter.allowed(key, now));

    // A different key is unaffected.
    assert!(limiter.allowed("zkpayer_innocent", now));

    // The next window resets the counter.
    assert!(limiter.allowed(key, now + 60));
}

#[test]
fn default_policy_is_thirty_per_minute() {
    let limiter = InvalidSigLimiter::default_policy();
    let now = 500_000;
    for _ in 0..30 {
        assert!(limiter.allowed("k", now));
        limiter.record_failure("k", now);
    }
    assert!(!limiter.allowed("k", now));
}

#[test]
fn receipt_key_rotation_keeps_old_keys_verifiable() {
    let old_pub = [1u8; 32];
    let new_pub = [2u8; 32];
    let registry = KeyRegistry::new("receipt-key-001", &old_pub);

    // Before rotation: only the first key, and it is active.
    assert_eq!(
        registry.get("receipt-key-001").unwrap().public_key,
        old_pub.to_vec()
    );
    assert!(registry.get("receipt-key-001").unwrap().active);
    assert!(registry.get("receipt-key-002").is_none());

    registry.rotate("receipt-key-002", &new_pub);

    // After rotation: the new key is active, the OLD key is still
    // present and verifiable (so receipts signed under it still check).
    let old = registry.get("receipt-key-001").unwrap();
    let new = registry.get("receipt-key-002").unwrap();
    assert!(!old.active, "rotated-out key is inactive");
    assert_eq!(old.public_key, old_pub.to_vec(), "old key still resolvable");
    assert!(new.active);
    assert_eq!(new.public_key, new_pub.to_vec());

    // The registry JSON advertises both keys with the right active flags.
    let json = registry.to_json();
    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys.iter().filter(|k| k["active"] == true).count(), 1);
}
