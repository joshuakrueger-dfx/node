//! Canonical byte encodings for ZK402 (Step 2).
//!
//! Two distinct canonical forms live here:
//!
//! 1. **`ZK402-REQUEST-V1`** — the canonical *HTTP request* string whose
//!    SHA-256 becomes `request_hash` (`specs/canonical-request-hash.md`).
//!    It binds a voucher to exactly one HTTP request.
//! 2. **`ZK402-V1`** — the canonical *voucher message* the wallet signs
//!    (`specs/x402-zkcoins-publisher-scheme.md`, "Canonical Signed
//!    Message"). Field order is fixed, ASCII only, LF endings, no
//!    trailing newline. Byte-stability is load-bearing: the Rust and TS
//!    encoders must agree byte-for-byte (mirrors the discipline of the
//!    zk-coins SDK `buildSendMessage`).
//!
//! Both are pinned against `fixtures/canonical-request-vector.json` in
//! `sig_tests.rs`.

use sha2::{Digest, Sha256};

use super::error::Zk402Error;

/// `sha256:<lowercase-hex>` over raw bytes — the spec's hash string form.
pub fn sha256_tagged(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// ---- ZK402-REQUEST-V1 -------------------------------------------------------

/// The selected headers that enter the request hash
/// (`specs/canonical-request-hash.md`, "Selected Headers").
const SELECTED_HEADERS: &[&str] = &["content-type", "x-zk402-resource-id", "x-zk402-merchant-id"];

/// Decoded view of the request fields that feed the canonical string.
/// The caller supplies the raw pieces; URL splitting is intentionally
/// minimal (http/https only — the only schemes the spec admits).
#[derive(Debug, Clone)]
pub struct CanonicalRequestParts {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    /// Raw (unsorted) query string without the leading `?`; empty if none.
    pub query: String,
    /// All request headers as (name, value); selection + canonicalization
    /// happens here.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// `sha256:`-tagged resource hash, defined by the resource server.
    pub resource_hash: String,
}

/// Split an absolute `http(s)://` URL into (scheme, host, path, query).
/// Deliberately small: ZK402 production traffic is plain https URLs; a
/// URL this fails to parse is an invalid payload, not a soft fallback.
pub fn split_http_url(url: &str) -> Result<(String, String, String, String), Zk402Error> {
    let (scheme, rest) = url.split_once("://").ok_or(Zk402Error::InvalidPayload)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return Err(Zk402Error::InvalidPayload);
    }
    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(Zk402Error::InvalidPayload);
    }
    // Lowercase host; strip the scheme's default port (spec: "include
    // port only when non-default").
    let mut host = authority.to_ascii_lowercase();
    let default_port = if scheme == "https" { ":443" } else { ":80" };
    if let Some(stripped) = host.strip_suffix(default_port) {
        host = stripped.to_owned();
    }
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (path_and_query.to_owned(), String::new()),
    };
    Ok((scheme, host, path, query))
}

/// RFC 3986 unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~".
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Percent-decode ONLY unreserved characters (the spec's rule); every
/// other escape is preserved verbatim so reserved characters cannot
/// change the parse after canonicalization.
fn percent_decode_unreserved(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                let decoded = (hi * 16 + lo) as u8;
                if is_unreserved(decoded) {
                    out.push(decoded as char);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Normalize the path per spec: absolute, resolve `.`/`..`, preserve
/// trailing slash, empty becomes `/`, percent-decode unreserved only.
pub fn normalize_path(path: &str) -> String {
    let decoded = percent_decode_unreserved(path);
    if decoded.is_empty() {
        return "/".to_owned();
    }
    let trailing_slash = decoded.len() > 1 && decoded.ends_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segments.join("/"));
    if trailing_slash && out.len() > 1 {
        out.push('/');
    }
    out
}

/// Canonicalize the query per spec: split pairs, percent-decode
/// unreserved, sort by key bytes then value bytes (duplicates kept),
/// rejoin as `key=value&...`. Empty query stays empty.
pub fn canonical_query(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (percent_decode_unreserved(k), percent_decode_unreserved(v)),
            None => (percent_decode_unreserved(p), String::new()),
        })
        .collect();
    pairs.sort_by(|a, b| {
        a.0.as_bytes()
            .cmp(b.0.as_bytes())
            .then(a.1.as_bytes().cmp(b.1.as_bytes()))
    });
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonical selected-headers string (`name:value\n` per selected
/// header, names lowercased, values whitespace-collapsed, sorted by
/// name) — the pre-image of the `headers=` hash.
pub fn canonical_selected_headers(headers: &[(String, String)]) -> String {
    let mut selected: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(name, value)| {
            let lname = name.trim().to_ascii_lowercase();
            if SELECTED_HEADERS.contains(&lname.as_str()) {
                let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
                Some((lname, collapsed))
            } else {
                None
            }
        })
        .collect();
    selected.sort_by(|a, b| a.0.cmp(&b.0));
    selected
        .into_iter()
        .map(|(n, v)| format!("{n}:{v}\n"))
        .collect()
}

/// Build the full `ZK402-REQUEST-V1` canonical string. LF endings, no
/// trailing newline (pinned by the fixture vector).
pub fn canonical_request_string(parts: &CanonicalRequestParts) -> String {
    let headers_hash = sha256_tagged(canonical_selected_headers(&parts.headers).as_bytes());
    let body_hash = sha256_tagged(&parts.body);
    format!(
        "ZK402-REQUEST-V1\n\
         method={}\n\
         scheme={}\n\
         host={}\n\
         path={}\n\
         query={}\n\
         headers={}\n\
         body={}\n\
         resource_hash={}",
        parts.method.to_ascii_uppercase(),
        parts.scheme.to_ascii_lowercase(),
        parts.host.to_ascii_lowercase(),
        normalize_path(&parts.path),
        canonical_query(&parts.query),
        headers_hash,
        body_hash,
        parts.resource_hash,
    )
}

/// `request_hash = "sha256:" + hex(SHA256(canonical_request))`.
pub fn request_hash(parts: &CanonicalRequestParts) -> String {
    sha256_tagged(canonical_request_string(parts).as_bytes())
}

// ---- ZK402-V1 (canonical signed voucher message) ----------------------------

/// The eighteen fields of the canonical signed message, in spec order.
/// Amounts/timestamps are integers here so the encoder — not the caller —
/// owns their ASCII rendering (no accidental `+`, padding, or locale).
#[derive(Debug, Clone, PartialEq)]
pub struct VoucherFields {
    pub network: String,
    pub mode: String,
    pub intent_id: String,
    /// `None` renders as the empty string (spec: "authorization_id or empty").
    pub authorization_id: Option<String>,
    pub voucher_id: String,
    pub payer: String,
    pub merchant: String,
    pub amount_sats: i64,
    pub fee_amount_sats: i64,
    pub resource_hash: String,
    pub request_hash: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub nonce: String,
    pub facilitator: String,
    pub access_threshold: String,
}

/// Build the canonical `ZK402-V1` message bytes. ASCII, LF endings,
/// fields exactly in spec order, no trailing newline. `scheme` and
/// `asset` are fixed by the spec and emitted as literals.
pub fn canonical_voucher_message(f: &VoucherFields) -> Vec<u8> {
    let msg = format!(
        "ZK402-V1\n\
         scheme=zkcoins-publisher\n\
         network={}\n\
         mode={}\n\
         intent_id={}\n\
         authorization_id={}\n\
         voucher_id={}\n\
         payer={}\n\
         merchant={}\n\
         amount={}\n\
         fee_amount={}\n\
         asset=btc-sats\n\
         resource_hash={}\n\
         request_hash={}\n\
         valid_after={}\n\
         valid_before={}\n\
         nonce={}\n\
         facilitator={}\n\
         access_threshold={}",
        f.network,
        f.mode,
        f.intent_id,
        f.authorization_id.as_deref().unwrap_or(""),
        f.voucher_id,
        f.payer,
        f.merchant,
        f.amount_sats,
        f.fee_amount_sats,
        f.resource_hash,
        f.request_hash,
        f.valid_after,
        f.valid_before,
        f.nonce,
        f.facilitator,
        f.access_threshold,
    );
    msg.into_bytes()
}

/// The 32-byte BIP-340 signing digest for a voucher: SHA-256 over the
/// canonical message bytes — the same hash-then-sign discipline the
/// zkCoins SDK applies to `buildSendMessage` output.
pub fn voucher_signing_digest(f: &VoucherFields) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_voucher_message(f));
    hasher.finalize().into()
}

// ---- ZK402-STREAM-V1 (Flow-D streaming "up-to" voucher) ---------------------

/// The fields of a streaming voucher's canonical signed message. The
/// buyer signs ONE of these per inference: `max_amount_sats` is the
/// ceiling for THIS request, `cumulative_authorized_sats` is the
/// monotone running total across the channel (the replay guard).
#[derive(Debug, Clone, PartialEq)]
pub struct StreamVoucherFields {
    pub network: String,
    pub channel_id: String,
    pub voucher_seq: i64,
    pub payer: String,
    pub merchant: String,
    pub max_amount_sats: i64,
    pub cumulative_authorized_sats: i64,
    pub resource_hash: String,
    pub request_hash: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub facilitator: String,
    pub access_threshold: String,
}

/// Canonical `ZK402-STREAM-V1` bytes — same byte discipline as
/// `ZK402-V1` (ASCII, LF, fixed order, no trailing newline). Must stay
/// byte-identical to the TS encoder in `@zk402/sdk`.
pub fn canonical_stream_message(f: &StreamVoucherFields) -> Vec<u8> {
    format!(
        "ZK402-STREAM-V1\n\
         scheme=zkcoins-publisher\n\
         network={}\n\
         channel_id={}\n\
         voucher_seq={}\n\
         payer={}\n\
         merchant={}\n\
         asset=btc-sats\n\
         max_amount={}\n\
         cumulative_authorized={}\n\
         resource_hash={}\n\
         request_hash={}\n\
         valid_after={}\n\
         valid_before={}\n\
         facilitator={}\n\
         access_threshold={}",
        f.network,
        f.channel_id,
        f.voucher_seq,
        f.payer,
        f.merchant,
        f.max_amount_sats,
        f.cumulative_authorized_sats,
        f.resource_hash,
        f.request_hash,
        f.valid_after,
        f.valid_before,
        f.facilitator,
        f.access_threshold,
    )
    .into_bytes()
}

/// The 32-byte BIP-340 signing digest for a streaming voucher.
pub fn stream_signing_digest(f: &StreamVoucherFields) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_stream_message(f));
    hasher.finalize().into()
}

// ---- ZK402-AUTHORIZATION-V1 (Layer 3 delegation message) --------------------
//
// The missing canonical message the `session_public_key` is delegated under
// (closes the authorization.rs seam). The agent's IDENTITY key signs this to
// authorize a short-lived, capped SESSION key; the session key then signs
// vouchers within the caps. Same byte discipline as ZK402-V1.

/// Hash of the allowed-merchants set, so the signed delegation stays compact
/// and order-independent. Empty set → hash of the empty string.
pub fn allowed_merchants_hash(merchants: &[String]) -> String {
    let mut sorted: Vec<&str> = merchants.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut hasher = Sha256::new();
    hasher.update(sorted.join(",").as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Order-independent hash of an agent's capability set (for `ZK402-AGENT-V1`).
pub fn capabilities_hash(capabilities: &[String]) -> String {
    let mut sorted: Vec<&str> = capabilities.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut hasher = Sha256::new();
    hasher.update(sorted.join(",").as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Fields of the `ZK402-AUTHORIZATION-V1` delegation message.
pub struct AuthorizationFields {
    pub network: String,
    pub identity_payer: String,
    pub session_pubkey: String,
    pub authorized_amount_sats: i64,
    pub spend_limit_per_request_sats: i64,
    pub spend_limit_total_sats: i64,
    pub allowed_merchants_hash: String,
    pub facilitator: String,
    pub valid_after: i64,
    pub valid_before: i64,
}

/// Build the canonical `ZK402-AUTHORIZATION-V1` bytes (ASCII, LF, fixed order,
/// no trailing newline). BIP-340-signed by the identity key.
pub fn canonical_authorization_message(f: &AuthorizationFields) -> Vec<u8> {
    format!(
        "ZK402-AUTHORIZATION-V1\n\
         scheme=zkcoins-publisher\n\
         network={}\n\
         identity_payer={}\n\
         session_pubkey={}\n\
         authorized_amount={}\n\
         spend_limit_per_request={}\n\
         spend_limit_total={}\n\
         allowed_merchants_hash={}\n\
         facilitator={}\n\
         valid_after={}\n\
         valid_before={}",
        f.network,
        f.identity_payer,
        f.session_pubkey,
        f.authorized_amount_sats,
        f.spend_limit_per_request_sats,
        f.spend_limit_total_sats,
        f.allowed_merchants_hash,
        f.facilitator,
        f.valid_after,
        f.valid_before,
    )
    .into_bytes()
}

/// The 32-byte BIP-340 signing digest for an authorization delegation.
pub fn authorization_signing_digest(f: &AuthorizationFields) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_authorization_message(f));
    hasher.finalize().into()
}

// ---- ZK402-AGENT-V1 (Layer 3 identity registration) -------------------------
//
// Proves control of the identity key when registering an agent / claiming a
// handle. Signed by the identity key (`agent_id`).

/// Fields of the `ZK402-AGENT-V1` registration message.
pub struct AgentFields {
    pub agent_id: String,
    pub handle: String,
    pub capabilities_hash: String,
    pub timestamp: i64,
}

/// Build the canonical `ZK402-AGENT-V1` bytes (ASCII, LF, fixed order, no
/// trailing newline). BIP-340-signed by the identity key.
pub fn canonical_agent_message(f: &AgentFields) -> Vec<u8> {
    format!(
        "ZK402-AGENT-V1\n\
         scheme=zkcoins-publisher\n\
         agent_id={}\n\
         handle={}\n\
         capabilities_hash={}\n\
         timestamp={}",
        f.agent_id, f.handle, f.capabilities_hash, f.timestamp,
    )
    .into_bytes()
}

/// The 32-byte BIP-340 signing digest for an agent registration.
pub fn agent_signing_digest(f: &AgentFields) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_agent_message(f));
    hasher.finalize().into()
}

// ---- ZK402-DISPUTE-V1 (Layer 4 signed rating) -------------------------------
//
// A rating bound to a settled receipt. BIP-340-signed by the complainant
// (payer) key; an optional merchant counter-signature uses the same message.

/// Fields of the `ZK402-DISPUTE-V1` rating message.
pub struct DisputeFields {
    pub receipt_id: String,
    pub complainant: String,
    pub verdict: String,
    pub reason_hash: String,
    pub timestamp: i64,
}

/// Build the canonical `ZK402-DISPUTE-V1` bytes (ASCII, LF, fixed order, no
/// trailing newline). BIP-340-signed by the complainant key.
pub fn canonical_dispute_message(f: &DisputeFields) -> Vec<u8> {
    format!(
        "ZK402-DISPUTE-V1\n\
         scheme=zkcoins-publisher\n\
         receipt_id={}\n\
         complainant={}\n\
         verdict={}\n\
         reason_hash={}\n\
         timestamp={}",
        f.receipt_id, f.complainant, f.verdict, f.reason_hash, f.timestamp,
    )
    .into_bytes()
}

/// The 32-byte BIP-340 signing digest for a dispute attestation.
pub fn dispute_signing_digest(f: &DisputeFields) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(canonical_dispute_message(f));
    hasher.finalize().into()
}
