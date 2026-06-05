//! ZK402 persistence helpers over the `zk402_*` tables (migration 0015).
//!
//! Same conventions as `node/src/db.rs`: free functions over `&PgPool`,
//! runtime-checked `sqlx::query` / `query_as` (NOT the compile-time
//! `query!` macros — see the rationale at the top of `db.rs`), and
//! `Result<_, sqlx::Error>` errors. Enum columns travel as their
//! `as_str()` form and are parsed back through `FromStr` on read; a
//! value the enum does not know (constraint drift) surfaces as
//! `sqlx::Error::Decode` with the offending value in the message.
//!
//! Idempotency: payment writes are idempotent by construction — every
//! insert helper for an id-keyed row uses `ON CONFLICT (id) DO NOTHING`
//! plus a uniqueness backstop (`voucher_id` / `nonce` unique indexes)
//! that turns a replay with a *different* id into a database error the
//! facilitator maps to `replay_detected`.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

use super::types::{
    AuditEvent, Authorization, AuthorizationStatus, Merchant, MerchantStatus, NewAuthorization,
    NewMerchant, NewPaymentIntent, PaymentIntent, PaymentIntentStatus, Receipt,
};

/// Map an enum-parse failure on a freshly-read row into a decode error
/// so constraint drift between migration and enum fails loudly.
fn decode_err(e: super::types::ParseEnumError) -> sqlx::Error {
    sqlx::Error::Decode(Box::new(e))
}

// ---- merchants ------------------------------------------------------------

/// Insert a merchant. Idempotent on `id` (`ON CONFLICT DO NOTHING`);
/// returns `true` when the row was inserted, `false` when a merchant
/// with that id already existed.
pub async fn insert_merchant(pool: &PgPool, m: &NewMerchant) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO zk402_merchants \
         (id, display_name, settlement_address, username, status, fee_bps, fixed_fee_sats) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&m.id)
    .bind(&m.display_name)
    .bind(&m.settlement_address)
    .bind(m.username.as_deref())
    .bind(m.status.as_str())
    .bind(m.fee_bps)
    .bind(m.fixed_fee_sats)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Load a merchant by id.
pub async fn load_merchant(pool: &PgPool, id: &str) -> Result<Option<Merchant>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, display_name, settlement_address, settlement_address_verified_at, \
                pending_settlement_address, pending_settlement_address_effective_at, \
                address_change_delay_seconds, username, status, fee_bps, fixed_fee_sats, \
                created_at, updated_at \
         FROM zk402_merchants WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        let status: String = r.try_get("status")?;
        Ok(Merchant {
            id: r.try_get("id")?,
            display_name: r.try_get("display_name")?,
            settlement_address: r.try_get("settlement_address")?,
            settlement_address_verified_at: r.try_get("settlement_address_verified_at")?,
            pending_settlement_address: r.try_get("pending_settlement_address")?,
            pending_settlement_address_effective_at: r
                .try_get("pending_settlement_address_effective_at")?,
            address_change_delay_seconds: r.try_get("address_change_delay_seconds")?,
            username: r.try_get("username")?,
            status: status.parse::<MerchantStatus>().map_err(decode_err)?,
            fee_bps: r.try_get("fee_bps")?,
            fixed_fee_sats: r.try_get("fixed_fee_sats")?,
            created_at: r.try_get("created_at")?,
            updated_at: r.try_get("updated_at")?,
        })
    })
    .transpose()
}

/// Update a merchant's status (e.g. `active → disabled`).
pub async fn update_merchant_status(
    pool: &PgPool,
    id: &str,
    status: MerchantStatus,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE zk402_merchants SET status = $2, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(status.as_str())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ---- authorizations -------------------------------------------------------

/// Insert an authorization. Idempotent on `id`.
pub async fn insert_authorization(
    pool: &PgPool,
    a: &NewAuthorization,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO zk402_authorizations \
         (id, payer, network, asset, authorized_amount_sats, status, \
          valid_after, valid_before, spend_limit_per_request_sats, \
          spend_limit_total_sats, allowed_merchants, facilitator_origin, \
          session_public_key, authorization_signature) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&a.id)
    .bind(&a.payer)
    .bind(&a.network)
    .bind(&a.asset)
    .bind(a.authorized_amount_sats)
    .bind(a.status.as_str())
    .bind(a.valid_after)
    .bind(a.valid_before)
    .bind(a.spend_limit_per_request_sats)
    .bind(a.spend_limit_total_sats)
    .bind(&a.allowed_merchants)
    .bind(&a.facilitator_origin)
    .bind(a.session_public_key.as_deref())
    .bind(&a.authorization_signature)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Load an authorization by id.
pub async fn load_authorization(
    pool: &PgPool,
    id: &str,
) -> Result<Option<Authorization>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, payer, network, asset, authorized_amount_sats, \
                accepted_amount_sats, published_amount_sats, status, \
                valid_after, valid_before, spend_limit_per_request_sats, \
                spend_limit_total_sats, allowed_merchants, facilitator_origin, \
                session_public_key, authorization_signature, \
                publisher_acceptance_id, created_at, updated_at \
         FROM zk402_authorizations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        let status: String = r.try_get("status")?;
        Ok(Authorization {
            id: r.try_get("id")?,
            payer: r.try_get("payer")?,
            network: r.try_get("network")?,
            asset: r.try_get("asset")?,
            authorized_amount_sats: r.try_get("authorized_amount_sats")?,
            accepted_amount_sats: r.try_get("accepted_amount_sats")?,
            published_amount_sats: r.try_get("published_amount_sats")?,
            status: status.parse::<AuthorizationStatus>().map_err(decode_err)?,
            valid_after: r.try_get("valid_after")?,
            valid_before: r.try_get("valid_before")?,
            spend_limit_per_request_sats: r.try_get("spend_limit_per_request_sats")?,
            spend_limit_total_sats: r.try_get("spend_limit_total_sats")?,
            allowed_merchants: r.try_get("allowed_merchants")?,
            facilitator_origin: r.try_get("facilitator_origin")?,
            session_public_key: r.try_get("session_public_key")?,
            authorization_signature: r.try_get("authorization_signature")?,
            publisher_acceptance_id: r.try_get("publisher_acceptance_id")?,
            created_at: r.try_get("created_at")?,
            updated_at: r.try_get("updated_at")?,
        })
    })
    .transpose()
}

/// Update an authorization's status (e.g. `pending → active`,
/// `active → revoked`).
pub async fn update_authorization_status(
    pool: &PgPool,
    id: &str,
    status: AuthorizationStatus,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE zk402_authorizations SET status = $2, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(status.as_str())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ---- payment intents ------------------------------------------------------

/// Insert a payment intent. Idempotent on `id` (a facilitator HTTP
/// retry with the same intent id is a no-op). A *different* id reusing
/// the same `voucher_id` or `nonce` violates the unique indexes and
/// surfaces as `sqlx::Error::Database` (unique violation) — the
/// facilitator's `replay_detected` backstop.
pub async fn insert_payment_intent(
    pool: &PgPool,
    p: &NewPaymentIntent,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO zk402_payment_intents \
         (id, voucher_id, authorization_id, payer, merchant_id, network, asset, \
          amount_sats, fee_amount_sats, resource_hash, request_hash, nonce, \
          valid_after, valid_before, canonical_message, signature_scheme, \
          signature, status, access_threshold) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                 $15, $16, $17, $18, $19) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&p.id)
    .bind(&p.voucher_id)
    .bind(p.authorization_id.as_deref())
    .bind(&p.payer)
    .bind(&p.merchant_id)
    .bind(&p.network)
    .bind(&p.asset)
    .bind(p.amount_sats)
    .bind(p.fee_amount_sats)
    .bind(&p.resource_hash)
    .bind(&p.request_hash)
    .bind(&p.nonce)
    .bind(p.valid_after)
    .bind(p.valid_before)
    .bind(&p.canonical_message)
    .bind(&p.signature_scheme)
    .bind(&p.signature)
    .bind(p.status.as_str())
    .bind(p.access_threshold.as_str())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Load a payment intent by `voucher_id` (the facilitator's idempotency
/// lookup: same voucher ⇒ same receipt).
pub async fn load_payment_intent_by_voucher(
    pool: &PgPool,
    voucher_id: &str,
) -> Result<Option<PaymentIntent>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, voucher_id, authorization_id, payer, merchant_id, network, \
                asset, amount_sats, fee_amount_sats, resource_hash, request_hash, \
                nonce, valid_after, valid_before, canonical_message, \
                signature_scheme, signature, status, failure_code, \
                failure_message, access_threshold, publisher_acceptance_id, \
                created_at, updated_at \
         FROM zk402_payment_intents WHERE voucher_id = $1",
    )
    .bind(voucher_id)
    .fetch_optional(pool)
    .await?;
    row.map(parse_payment_intent_row).transpose()
}

fn parse_payment_intent_row(
    r: sqlx::postgres::PgRow,
) -> Result<PaymentIntent, sqlx::Error> {
    let status: String = r.try_get("status")?;
    let access_threshold: String = r.try_get("access_threshold")?;
    Ok(PaymentIntent {
        id: r.try_get("id")?,
        voucher_id: r.try_get("voucher_id")?,
        authorization_id: r.try_get("authorization_id")?,
        payer: r.try_get("payer")?,
        merchant_id: r.try_get("merchant_id")?,
        network: r.try_get("network")?,
        asset: r.try_get("asset")?,
        amount_sats: r.try_get("amount_sats")?,
        fee_amount_sats: r.try_get("fee_amount_sats")?,
        resource_hash: r.try_get("resource_hash")?,
        request_hash: r.try_get("request_hash")?,
        nonce: r.try_get("nonce")?,
        valid_after: r.try_get("valid_after")?,
        valid_before: r.try_get("valid_before")?,
        canonical_message: r.try_get("canonical_message")?,
        signature_scheme: r.try_get("signature_scheme")?,
        signature: r.try_get("signature")?,
        status: status.parse::<PaymentIntentStatus>().map_err(decode_err)?,
        failure_code: r.try_get("failure_code")?,
        failure_message: r.try_get("failure_message")?,
        access_threshold: access_threshold
            .parse::<super::types::AccessThreshold>()
            .map_err(decode_err)?,
        publisher_acceptance_id: r.try_get("publisher_acceptance_id")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

/// Advance a payment intent's status and stamp the matching milestone
/// column. The milestone map is the write-side of the settlement state
/// machine; states without a dedicated column only bump `updated_at`.
pub async fn update_payment_intent_status(
    pool: &PgPool,
    id: &str,
    status: PaymentIntentStatus,
    at: DateTime<Utc>,
) -> Result<bool, sqlx::Error> {
    let milestone_col = match status {
        PaymentIntentStatus::Authorized => Some("authorized_at"),
        PaymentIntentStatus::PublisherAccepted => Some("publisher_accepted_at"),
        PaymentIntentStatus::Queued => Some("queued_at"),
        PaymentIntentStatus::Batching => Some("batched_at"),
        PaymentIntentStatus::Published => Some("published_at"),
        PaymentIntentStatus::Confirmed => Some("confirmed_at"),
        PaymentIntentStatus::Final => Some("final_at"),
        PaymentIntentStatus::Reorged => Some("reorged_at"),
        _ => None,
    };
    let sql = match milestone_col {
        // `milestone_col` comes from the fixed match above, never from
        // caller input, so the format! cannot inject.
        Some(col) => format!(
            "UPDATE zk402_payment_intents \
             SET status = $2, {col} = $3, updated_at = now() WHERE id = $1"
        ),
        None => "UPDATE zk402_payment_intents \
                 SET status = $2, updated_at = now() WHERE id = $1"
            .to_owned(),
    };
    let mut q = sqlx::query(&sql).bind(id).bind(status.as_str());
    if milestone_col.is_some() {
        q = q.bind(at);
    }
    let res = q.execute(pool).await?;
    Ok(res.rows_affected() == 1)
}

/// Record a structured failure on a payment intent.
pub async fn fail_payment_intent(
    pool: &PgPool,
    id: &str,
    status: PaymentIntentStatus,
    failure_code: &str,
    failure_message: &str,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE zk402_payment_intents \
         SET status = $2, failure_code = $3, failure_message = $4, updated_at = now() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(status.as_str())
    .bind(failure_code)
    .bind(failure_message)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

// ---- receipts ---------------------------------------------------------------

/// Insert a receipt. Idempotent on `id`; the unique index on
/// `payment_intent_id` enforces one receipt per intent at the database.
pub async fn insert_receipt(
    pool: &PgPool,
    id: &str,
    payment_intent_id: &str,
    status: &str,
    receipt_json: &serde_json::Value,
    facilitator_signature: &str,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO zk402_receipts \
         (id, payment_intent_id, status, receipt_json, facilitator_signature) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(payment_intent_id)
    .bind(status)
    .bind(receipt_json)
    .bind(facilitator_signature)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Load the receipt for a payment intent (the idempotent-retry read:
/// same voucher ⇒ same receipt).
pub async fn load_receipt_for_intent(
    pool: &PgPool,
    payment_intent_id: &str,
) -> Result<Option<Receipt>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, payment_intent_id, status, receipt_json, \
                facilitator_signature, created_at, updated_at \
         FROM zk402_receipts WHERE payment_intent_id = $1",
    )
    .bind(payment_intent_id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(Receipt {
            id: r.try_get("id")?,
            payment_intent_id: r.try_get("payment_intent_id")?,
            status: r.try_get("status")?,
            receipt_json: r.try_get("receipt_json")?,
            facilitator_signature: r.try_get("facilitator_signature")?,
            created_at: r.try_get("created_at")?,
            updated_at: r.try_get("updated_at")?,
        })
    })
    .transpose()
}

// ---- audit events -----------------------------------------------------------

/// Append a ZK402 domain audit event. Mirrors `db::insert_request_log`:
/// callers either await it (when the event must land before responding)
/// or `tokio::spawn` it fire-and-forget, logging-and-dropping failures
/// like `audit::persist_audit_entry` does.
pub async fn insert_audit_event(pool: &PgPool, e: &AuditEvent) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO zk402_audit_events \
         (actor, entity_type, entity_id, event_type, event_json) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&e.actor)
    .bind(&e.entity_type)
    .bind(&e.entity_id)
    .bind(&e.event_type)
    .bind(&e.event_json)
    .execute(pool)
    .await?;
    Ok(())
}

/// Count audit events for an entity — used by tests and the (later)
/// dashboard's per-entity audit view, keyed on the
/// `zk402_audit_events_entity_idx` index.
pub async fn count_audit_events(
    pool: &PgPool,
    entity_type: &str,
    entity_id: &str,
) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM zk402_audit_events \
         WHERE entity_type = $1 AND entity_id = $2",
    )
    .bind(entity_type)
    .bind(entity_id)
    .fetch_one(pool)
    .await?;
    Ok(count)
}
