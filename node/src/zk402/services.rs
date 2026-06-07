//! ZK402 Agent Economy — Layer 1: the service catalog + Bazaar discovery.
//!
//! A merchant registers a *service* (what it sells, at what price, with
//! what schema); autonomous agents discover it through the x402 v2
//! discovery endpoints (`/v2/x402/discovery/{resources,search}`) and the
//! capability advert (`/v2/x402/supported`). We speak the x402 Bazaar
//! wire format verbatim so any x402 agent can find us; the differentiation
//! is private settlement over zkCoins, not a bespoke registry
//! (proposals/AGENT_ECONOMY_design.md §2, Layer 1).
//!
//! Hard rules enforced here:
//!
//! * **Non-custodial** — a service is owned by a merchant and inherits its
//!   `settlement_address`; nothing here stores a balance. The price policy
//!   is a quote the buyer signs against.
//! * **Testnet-only / fail-closed** — registration rejects any network
//!   outside the supported set ([`payload::SUPPORTED_NETWORKS`], which has
//!   no `zkcoins:mainnet`) and any non-positive headline price.
//! * **Own data only** — registration binds the service to the
//!   API-key-authenticated merchant; status changes are merchant-scoped.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use super::error::Zk402Error;
use super::payload::{ASSET, SCHEME, SUPPORTED_NETWORKS};
use super::store;
use super::types::{AccessThreshold, NewService, Service, ServiceStatus};

/// Tagged SHA-256 in the `sha256:<hex>` form the SDK and canonical layer
/// use, so a service's `resource_hash` is byte-identical to the value a
/// buyer's voucher binds (`@zk402/sdk` `resourceHash`, `canonical.rs`).
fn sha256_tagged(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// Deterministic id for a price policy (binds the policy into the
/// resource hash so a changed price yields a new resource identity).
///
/// NODE-INTERNAL derivation: buyers never recompute this — discovery
/// serves the finished `resource_hash` and the voucher binds it verbatim,
/// so cross-language interop does not depend on this canonicalization.
/// If an SDK ever needs to derive the same id independently, pin a shared
/// fixture first (the key ordering / number formatting here is Rust
/// `serde_json`, not RFC 8785).
fn price_policy_id(policy: &Value) -> String {
    // Compact, key-sorted JSON for stability.
    let canonical = canonical_json(policy);
    sha256_tagged(canonical.as_bytes())
}

/// Minimal deterministic JSON: object keys sorted, no insignificant
/// whitespace. Sufficient for hashing a small price-policy object.
fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", json!(k), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// The `ZK402-RESOURCE-V1` resource hash for a service. The outer string
/// construction is byte-identical to the SDK's
/// `resourceHash(merchantId, resourceId, pricePolicyId)` (pinned by
/// `resource_hash_matches_sdk_construction`); the `price_policy_id`
/// input itself is node-derived — see [`price_policy_id`].
pub fn resource_hash(merchant_id: &str, resource_id: &str, price_policy_id: &str) -> String {
    let s = format!(
        "ZK402-RESOURCE-V1\nmerchant_id={merchant_id}\nresource_id={resource_id}\nprice_policy_id={price_policy_id}"
    );
    sha256_tagged(s.as_bytes())
}

/// Validated input for registering a service. The `merchant_id` is the
/// API-key-authenticated merchant (never client-supplied), the
/// `resource_hash` is derived, not trusted.
pub struct NewServiceInput {
    pub service_id: String,
    pub merchant_id: String,
    pub capability: String,
    pub display_name: String,
    pub description: Option<String>,
    pub endpoint: String,
    pub input_schema: Option<String>,
    pub output_schema: Option<String>,
    pub network: String,
    pub price_policy: Value,
    pub headline_amount_sats: i64,
    pub access_threshold: AccessThreshold,
    pub facilitator: String,
    pub privacy_level: String,
}

/// Register a service for a merchant. Fails closed on an unsupported
/// (incl. mainnet) network, a non-positive price, or an unknown merchant.
pub async fn register_service(
    pool: &PgPool,
    input: NewServiceInput,
) -> Result<Service, Zk402Error> {
    if !SUPPORTED_NETWORKS.contains(&input.network.as_str()) {
        return Err(Zk402Error::UnsupportedNetwork);
    }
    if input.headline_amount_sats <= 0 {
        return Err(Zk402Error::InvalidPayload);
    }
    if input.privacy_level != "private" && input.privacy_level != "public" {
        return Err(Zk402Error::InvalidPayload);
    }
    // Merchant must exist and be active — a disabled merchant cannot list.
    match store::load_merchant(pool, &input.merchant_id)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?
    {
        Some(m) if m.status == super::types::MerchantStatus::Active => {}
        Some(_) => return Err(Zk402Error::MerchantDisabled),
        None => return Err(Zk402Error::MerchantNotFound),
    }

    let rhash = resource_hash(
        &input.merchant_id,
        &input.service_id,
        &price_policy_id(&input.price_policy),
    );
    let new = NewService {
        id: input.service_id.clone(),
        merchant_id: input.merchant_id,
        capability: input.capability,
        display_name: input.display_name,
        description: input.description,
        endpoint: input.endpoint,
        input_schema: input.input_schema,
        output_schema: input.output_schema,
        network: input.network,
        asset: ASSET.to_owned(),
        price_policy_json: input.price_policy,
        headline_amount_sats: input.headline_amount_sats,
        access_threshold: input.access_threshold,
        resource_hash: rhash,
        facilitator: input.facilitator,
        privacy_level: input.privacy_level,
        status: ServiceStatus::Active,
    };
    let inserted = store::insert_service(pool, &new)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    if !inserted {
        return Err(Zk402Error::InvalidPayload); // service id already exists
    }
    store::load_service(pool, &new.id)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?
        .ok_or(Zk402Error::SettlementQueueUnavailable)
}

/// The x402 v2 `accepts` requirement block for a service — the same shape
/// the SDK's `buildRequirement` produces, so a discovering agent can pay
/// it directly.
pub fn requirement_block(s: &Service) -> Value {
    json!({
        "scheme": SCHEME,
        "network": s.network,
        "amount": s.headline_amount_sats.to_string(),
        "asset": s.asset,
        "payTo": s.merchant_id,
        "maxTimeoutSeconds": 30,
        "extra": {
            "mode": "exact-payment-intent",
            "facilitator": s.facilitator,
            "resourceId": s.id,
            "resourceHash": s.resource_hash,
            "accessThreshold": s.access_threshold.as_str(),
        },
    })
}

/// A single discovery `items[]` / `resources[]` entry in the x402 Bazaar
/// wire format. `metadata` carries the Bazaar input/output schema plus our
/// capability + privacy advert (and, later, the reputation snapshot).
pub fn discovery_item(s: &Service) -> Value {
    discovery_item_with_reputation(s, None)
}

/// Discovery item enriched with the (derived, read-only) seller
/// reputation snapshot in `metadata.reputation` — what a discovering
/// agent ranks on (Layer 4). `None` omits the field.
pub fn discovery_item_with_reputation(s: &Service, reputation: Option<Value>) -> Value {
    json!({
        "resource": s.endpoint,
        "type": "http",
        "x402Version": 2,
        "accepts": [requirement_block(s)],
        "lastUpdated": s.updated_at.to_rfc3339(),
        "metadata": {
            "description": s.description,
            "capability": s.capability,
            "displayName": s.display_name,
            "inputSchema": s.input_schema,
            "outputSchema": s.output_schema,
            "pricePolicy": s.price_policy_json,
            "privacyLevel": s.privacy_level,
            "serviceId": s.id,
            "reputation": reputation,
        },
    })
}
