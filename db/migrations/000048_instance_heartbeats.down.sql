-- Dropping the heartbeat table reverts CleanupFailedUploads to attempts-only
-- gating: no instance can be proven gone, so uploads owned by a decommissioned
-- instance are never reaped (they accumulate instead of risking mail loss).
DROP TABLE IF EXISTS instance_heartbeats;
