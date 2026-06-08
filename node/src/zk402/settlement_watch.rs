//! ZK402 settlement watcher — the first production ZK402 runtime loop.
//!
//! Drives receive-correlated intents to finality from the REAL chain state:
//! on each tick it fetches the chain tip and advances every eligible intent
//! via [`super::settlement::advance_intent_settlement`] (published → confirmed
//! → final at >= 6 confirmations, PDF §3.9).
//!
//! Gated behind the `ZK402_SETTLEMENT_WATCH=1` env flag (default OFF), so the
//! offline test environment and CI never run it. Live operation needs a real
//! prover/chain (DEV node, Mutinynet); the offline Esplora stub cannot mine,
//! so no intent would ever confirm there. See docs/ZK402_SPEC_ALIGNMENT.md.

use std::time::Duration;

use esplora_client::{r#async::DefaultSleeper, AsyncClient, Builder};
use sqlx::PgPool;

use super::error::Zk402Error;
use super::settlement::advance_intent_settlement;
use crate::publisher::EsploraConfig;

/// Statuses the watcher still drives forward — everything pre-`final` that a
/// receive could advance. Terminal / failed / expired intents are excluded so
/// the scan stays small and never touches a settled row.
const ELIGIBLE_STATUSES: &str = "'received','verified','authorized','publisher_accepted',\
                                 'queued','batching','published','confirmed'";

/// Advance every eligible, address-bound intent against `tip_height`. Pure
/// orchestration over the DB (no chain I/O), so it is directly testable.
/// Returns how many intents moved forward this pass.
pub async fn advance_due_intents(
    pool: &PgPool,
    tip_height: i64,
    now: i64,
) -> Result<usize, Zk402Error> {
    // `ELIGIBLE_STATUSES` is a fixed in-source constant, never caller input,
    // so the format! cannot inject.
    let sql = format!(
        "SELECT id FROM zk402_payment_intents \
         WHERE receiving_address IS NOT NULL AND status IN ({ELIGIBLE_STATUSES})"
    );
    let ids: Vec<String> = sqlx::query_scalar(&sql)
        .fetch_all(pool)
        .await
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    let mut moved = 0;
    for id in ids {
        if advance_intent_settlement(pool, &id, tip_height, now)
            .await?
            .is_some()
        {
            moved += 1;
        }
    }
    Ok(moved)
}

/// The watcher loop: build an Esplora client, then on each tick fetch the
/// chain tip and advance all due intents. Errors are logged and retried, never
/// fatal. Runs until the process exits.
pub async fn run_settlement_watch(
    pool: &PgPool,
    config: &EsploraConfig,
    interval: Duration,
) -> Result<(), Zk402Error> {
    let builder = Builder::new(&config.url);
    let client = AsyncClient::<DefaultSleeper>::from_builder(builder)
        .map_err(|_| Zk402Error::SettlementQueueUnavailable)?;
    loop {
        match client.get_height().await {
            Ok(tip) => {
                let now = chrono::Utc::now().timestamp();
                if let Err(e) = advance_due_intents(pool, i64::from(tip), now).await {
                    eprintln!("zk402 settlement watch: advance failed: {e:?}");
                }
            }
            Err(e) => eprintln!("zk402 settlement watch: tip fetch failed: {e}"),
        }
        tokio::time::sleep(interval).await;
    }
}
