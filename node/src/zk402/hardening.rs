//! Production hardening primitives (Step 10).
//!
//! * [`InvalidSigLimiter`] — fixed-window rate limit on invalid-signature
//!   attempts (`docs/ABUSE_CONTROLS.md`: 30/min). Signature verification
//!   is CPU-priced, so the limiter is consulted BEFORE the expensive
//!   check and recorded after a failure: an attacker spraying garbage
//!   signatures gets cut off at the window threshold with HTTP 429.
//! * [`KeyRegistry`] — the receipt-key set behind
//!   `GET /api/zk402/receipt-keys`. Rotation appends the new key and
//!   keeps prior keys verifiable, so receipts signed under an old `kid`
//!   stay checkable after a rotation (the rotation drill in
//!   `hardening_tests.rs` pins exactly that).

use std::collections::HashMap;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

/// Fixed-window counter keyed by an attacker-attributable string
/// (payer id; the audit middleware already records client IPs).
pub struct InvalidSigLimiter {
    max_per_window: u32,
    window_seconds: i64,
    state: Mutex<HashMap<String, (i64, u32)>>,
}

impl InvalidSigLimiter {
    pub fn new(max_per_window: u32, window_seconds: i64) -> Self {
        Self {
            max_per_window,
            window_seconds,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// ABUSE_CONTROLS default: 30 invalid attempts per minute.
    pub fn default_policy() -> Self {
        Self::new(30, 60)
    }

    fn window(&self, now_unix: i64) -> i64 {
        now_unix / self.window_seconds
    }

    /// Is this key currently allowed to attempt verification?
    pub fn allowed(&self, key: &str, now_unix: i64) -> bool {
        let state = self.state.lock().expect("limiter poisoned");
        match state.get(key) {
            Some((win, count)) if *win == self.window(now_unix) => *count < self.max_per_window,
            _ => true,
        }
    }

    /// Record one invalid-signature failure for this key.
    pub fn record_failure(&self, key: &str, now_unix: i64) {
        let mut state = self.state.lock().expect("limiter poisoned");
        let win = self.window(now_unix);
        let entry = state.entry(key.to_owned()).or_insert((win, 0));
        if entry.0 != win {
            *entry = (win, 0);
        }
        entry.1 += 1;
    }
}

/// One advertised receipt key.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryKey {
    pub kid: String,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
    /// Keys stay verifiable after rotation; `active` marks the signer.
    pub active: bool,
}

/// The receipt-key registry (`GET /api/zk402/receipt-keys`).
pub struct KeyRegistry {
    keys: Mutex<Vec<RegistryKey>>,
}

impl KeyRegistry {
    /// Start with one active key.
    pub fn new(kid: &str, public_key: &[u8]) -> Self {
        Self {
            keys: Mutex::new(vec![RegistryKey {
                kid: kid.to_owned(),
                public_key: public_key.to_vec(),
                active: true,
            }]),
        }
    }

    /// Rotate: the new key becomes active; every prior key remains in
    /// the registry (still verifiable) but inactive.
    pub fn rotate(&self, kid: &str, public_key: &[u8]) {
        let mut keys = self.keys.lock().expect("registry poisoned");
        for k in keys.iter_mut() {
            k.active = false;
        }
        keys.push(RegistryKey {
            kid: kid.to_owned(),
            public_key: public_key.to_vec(),
            active: true,
        });
    }

    /// Look up a key by `kid` (active or rotated-out).
    pub fn get(&self, kid: &str) -> Option<RegistryKey> {
        self.keys
            .lock()
            .expect("registry poisoned")
            .iter()
            .find(|k| k.kid == kid)
            .cloned()
    }

    /// Wire form for the registry endpoint.
    pub fn to_json(&self) -> serde_json::Value {
        let keys = self.keys.lock().expect("registry poisoned");
        serde_json::json!({
            "keys": keys
                .iter()
                .map(|k| serde_json::json!({
                    "kid": k.kid,
                    "algorithm": "Ed25519",
                    "publicKeyBase64url": URL_SAFE_NO_PAD.encode(&k.public_key),
                    "active": k.active,
                }))
                .collect::<Vec<_>>(),
        })
    }
}
