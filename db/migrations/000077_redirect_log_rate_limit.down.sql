-- Drop the per-row redirect rate limit. Binaries that write rate_limit must be gone first.
-- Metadata only; on a large live database drop the column out-of-band with a short lock_timeout,
-- as the up migration describes for the add, and this migration then only inspects the catalog.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
               WHERE attrelid = 'redirect_log'::regclass AND attname = 'rate_limit' AND NOT attisdropped) THEN
        ALTER TABLE redirect_log DROP COLUMN IF EXISTS rate_limit;
    END IF;
END $$;
