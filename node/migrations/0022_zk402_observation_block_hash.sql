-- ===========================================================================
-- 0022_zk402_observation_block_hash.sql
--
-- Anchor each settlement observation to its block HASH, not just its height.
--
-- Reorg detection needs to know "the block we observed at height H had hash X".
-- A reorg replaces the canonical block at H with a different hash Y: the watcher
-- compares the stored anchor hash to the current canonical hash at that height
-- and, on a mismatch, reverts the affected published/confirmed intents via
-- `revert_reorged_intents` (Protocol Spec §3.7). Height alone cannot tell an
-- orphaned block from a still-canonical one.
--
-- Nullable: legacy/mempool observations (no confirming block yet) carry NULL and
-- are simply never treated as a reorg anchor (fail-closed — an un-anchored
-- observation cannot be "orphaned"). Non-custodial: still only on-chain facts,
-- no balances.
-- ===========================================================================

ALTER TABLE zk402_settlement_observations ADD COLUMN block_hash TEXT;
