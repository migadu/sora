-- Pending purge requests are lost with the columns; the accounts they marked stay
-- soft-deleted and are removed by the cleaner after the grace period.

DROP INDEX IF EXISTS idx_accounts_purge_requested;

ALTER TABLE accounts
    DROP COLUMN IF EXISTS purge_next_attempt_at,
    DROP COLUMN IF EXISTS purge_attempts,
    DROP COLUMN IF EXISTS purge_requested_at;
