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

use std::collections::HashMap;
use std::time::Duration;

use esplora_client::{r#async::DefaultSleeper, AsyncClient, Builder};
use sqlx::PgPool;

use super::error::Zk402Error;
use super::settlement::{advance_intent_settlement, detect_and_revert_reorgs, reorg_anchors};
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

/// Resolve the CURRENT canonical hash for every reorg anchor and revert any
/// intent whose anchoring block was orphaned. Chain I/O lives here (uncovered,
/// like the rest of the watcher); the decision logic is the testable
/// [`detect_and_revert_reorgs`]. Fail-closed: a height above `tip` is treated as
/// off-chain (the chain shortened past it), but a transient `get_block_hash`
/// error leaves that anchor UNRESOLVED — never a spurious revert.
async fn check_reorgs(
    pool: &PgPool,
    client: &AsyncClient<DefaultSleeper>,
    tip: i64,
    now: i64,
) -> Result<(), Zk402Error> {
    let anchors = reorg_anchors(pool).await?;
    let mut canonical: HashMap<i64, Option<String>> = HashMap::new();
    for (height, _) in &anchors {
        if canonical.contains_key(height) {
            continue;
        }
        if *height > tip {
            canonical.insert(*height, None); // chain is now shorter than this anchor
        } else if let Ok(h) = u32::try_from(*height) {
            match client.get_block_hash(h).await {
                Ok(hash) => {
                    canonical.insert(*height, Some(hash.to_string()));
                }
                Err(e) => eprintln!("zk402 settlement watch: block hash fetch failed: {e}"),
            }
        }
    }
    if let Some((from, reverted)) = detect_and_revert_reorgs(pool, &canonical, now).await? {
        eprintln!("zk402 settlement watch: reorg from height {from} reverted {reverted} intent(s)");
    }
    Ok(())
}

/// The watcher loop: build an Esplora client, then on each tick fetch the chain
/// tip, revert any reorg-orphaned intents, and advance all due intents under
/// the current tip. Errors are logged and retried, never fatal. Runs until the
/// process exits.
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
                let tip = i64::from(tip);
                // Revert orphaned anchors BEFORE advancing, so a reorged intent
                // re-applies cleanly under the new chain on the same tick onward.
                if let Err(e) = check_reorgs(pool, &client, tip, now).await {
                    eprintln!("zk402 settlement watch: reorg check failed: {e:?}");
                }
                if let Err(e) = advance_due_intents(pool, tip, now).await {
                    eprintln!("zk402 settlement watch: advance failed: {e:?}");
                }
            }
            Err(e) => eprintln!("zk402 settlement watch: tip fetch failed: {e}"),
        }
        tokio::time::sleep(interval).await;
    }
}
