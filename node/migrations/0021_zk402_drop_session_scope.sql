-- ===========================================================================
-- 0021_zk402_drop_session_scope.sql
--
-- Remove `zk402_agent_session_keys.scope_json`.
--
-- The column was stored free-form but never signature-covered (it is NOT part
-- of the `ZK402-AUTHORIZATION-V1` canonical message) and never enforced
-- (`validate_session_delegation` ignores it). A field that looks like it
-- scopes a delegated key but binds to nothing is a footgun — a client could
-- believe it constrains the key when it does not. The real scoping surface —
-- spend caps, validity window, and the (signed) allowed-merchant set — is
-- enforced. Drop the dead column rather than pretend it means something.
-- ===========================================================================

ALTER TABLE zk402_agent_session_keys DROP COLUMN scope_json;
