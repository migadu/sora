-- Each redirect_log row carries the end of the redirect rate window it was charged under (#1959).
--
-- The redirect rate limit counts an account's redirect_log rows inside limits.redirect_rate_window
-- of the lmtp or http_admin_api server that delivers. The cleaner pruned the rows by its own node's
-- config, max(grace_period, the longest window of the node's lmtp and http_admin_api servers), and
-- every node with an imap, pop3 or lmtp server runs the cleaner: an IMAP-only node knows only the
-- default 1h window, so with a grace_period shorter than a delivering node's window it deleted rows
-- that window still counts. expires_at is redirect_date plus the window that charged the row, and
-- the cleaner keeps a row until it has passed, whatever the cleaning node's config.
--
-- NULL on every row written before this migration and by older binaries during a rollout: the
-- cleaner keeps those by its own config, as before. No backfill, no default, no index: the cleaner
-- narrows by redirect_date first.
--
-- Metadata only (no default, no rewrite), but ADD COLUMN needs a brief ACCESS EXCLUSIVE lock on
-- redirect_log, which must not queue in front of delivery behind a long query. On a large live
-- database add the column out-of-band first, on the primary, not through pgbouncer:
--   SET lock_timeout = '3s';
--   ALTER TABLE redirect_log ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
-- and retry on a lock timeout. Running binaries ignore the column. The statement below checks the
-- catalog first and takes no lock on redirect_log when the column is already there.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'redirect_log'::regclass AND attname = 'expires_at' AND NOT attisdropped) THEN
        ALTER TABLE redirect_log ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
    END IF;
END $$;
