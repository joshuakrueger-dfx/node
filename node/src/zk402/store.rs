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
    AuditEvent, Authorization, AuthorizationStatus, Batch, BatchItem, BatchStatus, Merchant,
    MerchantSettlement, MerchantStatus, NewAuditEvent, NewAuthorization, NewBatch, NewMerchant,
    NewMerchantSettlement, NewPaymentIntent, PaymentIntent, PaymentIntentStatus, Receipt,
    SettlementKind, SettlementStatus,
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
    let res =
        sqlx::query("UPDATE zk402_merchants SET status = $2, updated_at = now() WHERE id = $1")
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

/// Atomically reserve `amount` against an authorization's total cap.
///
/// This is the concurrency-safe heart of non-custodial spend control:
/// the guard lives entirely inside one conditional `UPDATE`, so N
/// parallel vouchers serialize on the row lock and the sum of accepted
/// amounts can NEVER exceed `authorized_amount_sats` (nor the optional
/// `spend_limit_total_sats`). Returns `true` when the reservation
/// succeeded, `false` when it would breach a cap or the authorization is
/// not `active`. The per-request cap, expiry window, and merchant
/// allow-list are checked by the caller against the loaded row; only the
/// running-total guard must be atomic, and it is.
pub async fn try_reserve_authorization(
    pool: &PgPool,
    id: &str,
    amount: i64,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE zk402_authorizations \
         SET accepted_amount_sats = accepted_amount_sats + $2, updated_at = now() \
         WHERE id = $1 \
           AND status = 'active' \
           AND accepted_amount_sats + $2 <= authorized_amount_sats \
           AND (spend_limit_total_sats IS NULL \
                OR accepted_amount_sats + $2 <= spend_limit_total_sats)",
    )
    .bind(id)
    .bind(amount)
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

/// Load a payment intent by id (the facilitator's bookkeeping key; the
/// voucher lookup above is the buyer-facing idempotency read).
pub async fn load_payment_intent(
    pool: &PgPool,
    id: &str,
) -> Result<Option<PaymentIntent>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, voucher_id, authorization_id, payer, merchant_id, network, \
                asset, amount_sats, fee_amount_sats, resource_hash, request_hash, \
                nonce, valid_after, valid_before, canonical_message, \
                signature_scheme, signature, status, failure_code, \
                failure_message, access_threshold, publisher_acceptance_id, \
                created_at, updated_at \
         FROM zk402_payment_intents WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(parse_payment_intent_row).transpose()
}

fn parse_payment_intent_row(r: sqlx::postgres::PgRow) -> Result<PaymentIntent, sqlx::Error> {
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

/// Persist the zkCoins publisher-acceptance id on an intent (settle
/// records it as soon as the publisher accepts; Step-8's real backend
/// reuses the same column).
pub async fn set_publisher_acceptance_id(
    pool: &PgPool,
    id: &str,
    acceptance_id: &str,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE zk402_payment_intents \
         SET publisher_acceptance_id = $2, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(acceptance_id)
    .execute(pool)
    .await?;
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

/// Load a receipt by its own id (the public, offline-verifiable artifact
/// served at `GET /api/zk402/receipts/:id`).
pub async fn load_receipt_json(
    pool: &PgPool,
    receipt_id: &str,
) -> Result<Option<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar("SELECT receipt_json FROM zk402_receipts WHERE id = $1")
        .bind(receipt_id)
        .fetch_optional(pool)
        .await
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

// ---- batches ----------------------------------------------------------------

/// Insert a batch. Idempotent on `id`; the amount totals, counters and
/// milestone timestamps default at the database and are advanced later
/// by the batch state machine.
pub async fn insert_batch(pool: &PgPool, b: &NewBatch) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO zk402_batches (id, network, merchant_id, status) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&b.id)
    .bind(&b.network)
    .bind(b.merchant_id.as_deref())
    .bind(b.status.as_str())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Load a batch by id.
pub async fn load_batch(pool: &PgPool, id: &str) -> Result<Option<Batch>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT id, network, merchant_id, status, gross_amount_sats, \
                fee_amount_sats, net_amount_sats, intent_count, zkcoins_proof_id, \
                commit_txid, reveal_txid, failure_code, failure_message, \
                retry_count, created_at, updated_at \
         FROM zk402_batches WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        let status: String = r.try_get("status")?;
        Ok(Batch {
            id: r.try_get("id")?,
            network: r.try_get("network")?,
            merchant_id: r.try_get("merchant_id")?,
            status: status.parse::<BatchStatus>().map_err(decode_err)?,
            gross_amount_sats: r.try_get("gross_amount_sats")?,
            fee_amount_sats: r.try_get("fee_amount_sats")?,
            net_amount_sats: r.try_get("net_amount_sats")?,
            intent_count: r.try_get("intent_count")?,
            zkcoins_proof_id: r.try_get("zkcoins_proof_id")?,
            commit_txid: r.try_get("commit_txid")?,
            reveal_txid: r.try_get("reveal_txid")?,
            failure_code: r.try_get("failure_code")?,
            failure_message: r.try_get("failure_message")?,
            retry_count: r.try_get("retry_count")?,
            created_at: r.try_get("created_at")?,
            updated_at: r.try_get("updated_at")?,
        })
    })
    .transpose()
}

/// Advance a batch's status.
pub async fn update_batch_status(
    pool: &PgPool,
    id: &str,
    status: BatchStatus,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query("UPDATE zk402_batches SET status = $2, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(status.as_str())
        .execute(pool)
        .await?;
    Ok(res.rows_affected() == 1)
}

// ---- batch items ------------------------------------------------------------

/// Add an intent to a batch. Idempotent on the `(batch_id,
/// payment_intent_id)` composite primary key — re-adding the same intent
/// to the same batch is a no-op.
pub async fn insert_batch_item(pool: &PgPool, item: &BatchItem) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO zk402_batch_items \
         (batch_id, payment_intent_id, amount_sats, fee_sats, net_sats) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (batch_id, payment_intent_id) DO NOTHING",
    )
    .bind(&item.batch_id)
    .bind(&item.payment_intent_id)
    .bind(item.amount_sats)
    .bind(item.fee_sats)
    .bind(item.net_sats)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// List the intents in a batch, ordered by intent id for a stable view.
pub async fn list_batch_items(
    pool: &PgPool,
    batch_id: &str,
) -> Result<Vec<BatchItem>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT batch_id, payment_intent_id, amount_sats, fee_sats, net_sats \
         FROM zk402_batch_items WHERE batch_id = $1 ORDER BY payment_intent_id",
    )
    .bind(batch_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(BatchItem {
                batch_id: r.try_get("batch_id")?,
                payment_intent_id: r.try_get("payment_intent_id")?,
                amount_sats: r.try_get("amount_sats")?,
                fee_sats: r.try_get("fee_sats")?,
                net_sats: r.try_get("net_sats")?,
            })
        })
        .collect()
}

// ---- merchant settlements ---------------------------------------------------

/// Append a settlement ledger entry. Idempotent on `id`; the ledger is
/// append-only, so a derived merchant balance is a sum over these
/// immutable rows — never a mutable custodial column.
pub async fn insert_merchant_settlement(
    pool: &PgPool,
    s: &NewMerchantSettlement,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO zk402_merchant_settlements \
         (id, merchant_id, payment_intent_id, batch_id, kind, amount_sats, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&s.id)
    .bind(&s.merchant_id)
    .bind(s.payment_intent_id.as_deref())
    .bind(s.batch_id.as_deref())
    .bind(s.kind.as_str())
    .bind(s.amount_sats)
    .bind(s.status.as_str())
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// List a merchant's settlement ledger, oldest first.
pub async fn list_merchant_settlements(
    pool: &PgPool,
    merchant_id: &str,
) -> Result<Vec<MerchantSettlement>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, merchant_id, payment_intent_id, batch_id, kind, amount_sats, \
                status, created_at \
         FROM zk402_merchant_settlements WHERE merchant_id = $1 ORDER BY created_at, id",
    )
    .bind(merchant_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            let kind: String = r.try_get("kind")?;
            let status: String = r.try_get("status")?;
            Ok(MerchantSettlement {
                id: r.try_get("id")?,
                merchant_id: r.try_get("merchant_id")?,
                payment_intent_id: r.try_get("payment_intent_id")?,
                batch_id: r.try_get("batch_id")?,
                kind: kind.parse::<SettlementKind>().map_err(decode_err)?,
                amount_sats: r.try_get("amount_sats")?,
                status: status.parse::<SettlementStatus>().map_err(decode_err)?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect()
}

// ---- audit events -----------------------------------------------------------

/// Build a [`NewAuditEvent`] without hand-typing the field names; the
/// database stamps `id` and `created_at`.
pub fn audit_event(
    actor: impl Into<String>,
    entity_type: impl Into<String>,
    entity_id: impl Into<String>,
    event_type: impl Into<String>,
    event_json: serde_json::Value,
) -> NewAuditEvent {
    NewAuditEvent {
        actor: actor.into(),
        entity_type: entity_type.into(),
        entity_id: entity_id.into(),
        event_type: event_type.into(),
        event_json,
    }
}

/// Append a ZK402 domain audit event, returning the new `BIGSERIAL` id.
/// Mirrors `db::insert_request_log`: callers either await it (when the
/// event must land before responding) or `tokio::spawn` it
/// fire-and-forget, logging-and-dropping failures like
/// `audit::persist_audit_entry` does.
pub async fn insert_audit_event(pool: &PgPool, e: &NewAuditEvent) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "INSERT INTO zk402_audit_events \
         (actor, entity_type, entity_id, event_type, event_json) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(&e.actor)
    .bind(&e.entity_type)
    .bind(&e.entity_id)
    .bind(&e.event_type)
    .bind(&e.event_json)
    .fetch_one(pool)
    .await?;
    row.try_get("id")
}

/// List audit events for an entity, oldest first — the (later)
/// dashboard's per-entity audit view, keyed on the
/// `zk402_audit_events_entity_idx` index.
pub async fn list_audit_events_for_entity(
    pool: &PgPool,
    entity_type: &str,
    entity_id: &str,
) -> Result<Vec<AuditEvent>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, actor, entity_type, entity_id, event_type, event_json, created_at \
         FROM zk402_audit_events \
         WHERE entity_type = $1 AND entity_id = $2 ORDER BY created_at, id",
    )
    .bind(entity_type)
    .bind(entity_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(AuditEvent {
                id: r.try_get("id")?,
                actor: r.try_get("actor")?,
                entity_type: r.try_get("entity_type")?,
                entity_id: r.try_get("entity_id")?,
                event_type: r.try_get("event_type")?,
                event_json: r.try_get("event_json")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect()
}

/// Count audit events for an entity — keyed on the
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

// ---- dashboard / streaming read helpers ------------------------------------

/// List a merchant's payment intents, newest first (dashboard view).
pub async fn list_payment_intents_for_merchant(
    pool: &PgPool,
    merchant_id: &str,
    limit: i64,
) -> Result<Vec<PaymentIntent>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, voucher_id, authorization_id, payer, merchant_id, network, \
                asset, amount_sats, fee_amount_sats, resource_hash, request_hash, \
                nonce, valid_after, valid_before, canonical_message, \
                signature_scheme, signature, status, failure_code, \
                failure_message, access_threshold, publisher_acceptance_id, \
                created_at, updated_at \
         FROM zk402_payment_intents WHERE merchant_id = $1 \
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(merchant_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(parse_payment_intent_row).collect()
}

/// One metering-channel summary row for the dashboard.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelSummary {
    pub id: String,
    pub payer: String,
    pub status: String,
    pub metered_amount_sats: i64,
    pub authorized_cumulative_sats: i64,
    pub authorized_amount_sats: i64,
    pub valid_before: DateTime<Utc>,
}

/// List metering channels visible to a merchant (allow-list contains the
/// merchant, or is empty = any). Newest first.
pub async fn list_channels_for_merchant(
    pool: &PgPool,
    merchant_id: &str,
    limit: i64,
) -> Result<Vec<ChannelSummary>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, payer, status, metered_amount_sats, \
                authorized_cumulative_sats, authorized_amount_sats, valid_before \
         FROM zk402_authorizations \
         WHERE channel_mode = 'metering' \
           AND (allowed_merchants = '[]'::jsonb OR allowed_merchants @> $1::jsonb) \
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(serde_json::json!([merchant_id]))
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(ChannelSummary {
                id: r.try_get("id")?,
                payer: r.try_get("payer")?,
                status: r.try_get("status")?,
                metered_amount_sats: r.try_get("metered_amount_sats")?,
                authorized_cumulative_sats: r.try_get("authorized_cumulative_sats")?,
                authorized_amount_sats: r.try_get("authorized_amount_sats")?,
                valid_before: r.try_get("valid_before")?,
            })
        })
        .collect()
}

/// One usage-event row for the dashboard.
#[derive(Debug, Clone, PartialEq)]
pub struct UsageEventRow {
    pub voucher_seq: i64,
    pub unit: String,
    pub quantity: i64,
    pub cost_sats: i64,
    pub model: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// List a channel's usage events, newest first.
pub async fn list_usage_events(
    pool: &PgPool,
    channel_id: &str,
    limit: i64,
) -> Result<Vec<UsageEventRow>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT voucher_seq, unit, quantity, cost_sats, model, created_at \
         FROM zk402_usage_events WHERE channel_id = $1 \
         ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(channel_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(UsageEventRow {
                voucher_seq: r.try_get("voucher_seq")?,
                unit: r.try_get("unit")?,
                quantity: r.try_get("quantity")?,
                cost_sats: r.try_get("cost_sats")?,
                model: r.try_get("model")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect()
}
