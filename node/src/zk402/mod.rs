//! ZK402 Publisher — an x402-compatible payment layer native to the
//! zkCoins publisher (Step 1: database & domain).
//!
//! This module is the persistence + domain home for the ZK402 scheme
//! (context repo `joshuakrueger-dfx/ZKcoins-x402-`). Step 1 lands:
//!
//! * the `zk402_*` tables (migration `0015_zk402.sql`),
//! * Rust domain types for every entity ([`types`]),
//! * create/read/update DB helpers + an audit-event writer ([`store`]).
//!
//! Later steps add the canonical message builder + BIP-340 verification
//! (Step 2), the facilitator `verify`/`settle` API (Step 3), and the
//! non-custodial authorization enforcement (Step 4) on top of this base.
//!
//! ## Non-custodial invariant
//!
//! Nothing in this module — or its migration — stores a buyer deposit, a
//! session treasury, or an operator-controlled merchant payout balance.
//! Merchant accounting is the append-only settlement view
//! (`zk402_merchant_settlements`); a merchant's balance is a derived sum
//! over those immutable entries, never a mutable custodial column. The
//! `no_custody_schema` test in [`tests`] asserts this at the schema
//! level (no column named `deposit_amount` / `treasury` /
//! `payout_balance`).
//!
//! ## Wiring status
//!
//! `#[allow(dead_code)]` on the `lib.rs`/`main.rs` module declaration:
//! these helpers are exercised by the Step-1 test suite but are not yet
//! called from a production route (that lands in Step 3). The same
//! posture the `db` module carried during its initial PR (PR-A1).

pub mod authorization;
pub mod batch;
pub mod canonical;
pub mod dashboard;
pub mod error;
pub mod facilitator;
pub mod hardening;
pub mod payload;
pub mod receipt;
pub mod routes;
pub mod settlement;
pub mod signature;
pub mod store;
pub mod streaming;
pub mod types;

#[cfg(test)]
mod authorization_tests;
#[cfg(test)]
mod batch_tests;
#[cfg(test)]
mod dashboard_tests;
#[cfg(test)]
mod facilitator_tests;
#[cfg(test)]
mod hardening_tests;
#[cfg(test)]
mod settlement_tests;
#[cfg(test)]
mod sig_tests;
#[cfg(test)]
mod spec_lock_tests;
#[cfg(test)]
mod streaming_tests;
#[cfg(test)]
mod tests;
