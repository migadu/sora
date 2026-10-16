-- An account purge is requested on any node (the Admin API, including a proxy with no
-- object storage) and performed by a purge worker on a node that has it. The request is a
-- mark on the accounts row: durable, visible, and cleared only by the purge finishing
-- (the row goes) or by `accounts restore`.
--
-- purge_attempts / purge_next_attempt_at are the worker's per-account backoff: a purge
-- that failed (S3 refusing deletes, an upload in flight) is not retried before
-- purge_next_attempt_at, and a new request resets both.
--
-- accounts is small and the new columns have no non-NULL default except the counter,
-- which PostgreSQL stores as a catalog default; no table rewrite.

ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS purge_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS purge_attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS purge_next_attempt_at TIMESTAMPTZ;

-- The worker's poll and the pending-purge gauges read only marked rows, so the index is
-- partial: empty on a deployment that never purges.
CREATE INDEX IF NOT EXISTS idx_accounts_purge_requested
    ON accounts (purge_requested_at)
    WHERE purge_requested_at IS NOT NULL;
