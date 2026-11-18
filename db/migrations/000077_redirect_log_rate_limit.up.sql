-- Each redirect_log row carries the redirect_rate_limit it was charged under (#2020).
--
-- The redirect rate limit counts an account's redirect_log rows on every node, so it is one limit
-- only if every lmtp and http_admin_api server of every node has the same limits.redirect_rate_limit.
-- Rows record the window that charged them (expires_at, migration 75), which lets a node see a
-- differing window; rate_limit lets it see a differing limit the same way.
--
-- NULL on every row written before this migration and by older binaries during a rollout: nothing
-- compares those. No backfill, no default, no index: only the hourly consistency check reads it.
--
-- Metadata only (no default, no rewrite), but ADD COLUMN needs a brief ACCESS EXCLUSIVE lock on
-- redirect_log, which must not queue in front of delivery behind a long query. On a large live
-- database add the column out-of-band first, on the primary, not through pgbouncer:
--   SET lock_timeout = '3s';
--   ALTER TABLE redirect_log ADD COLUMN IF NOT EXISTS rate_limit INTEGER;
-- and retry on a lock timeout. Running binaries ignore the column. The statement below checks the
-- catalog first and takes no lock on redirect_log when the column is already there.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'redirect_log'::regclass AND attname = 'rate_limit' AND NOT attisdropped) THEN
        ALTER TABLE redirect_log ADD COLUMN IF NOT EXISTS rate_limit INTEGER;
    END IF;
END $$;
