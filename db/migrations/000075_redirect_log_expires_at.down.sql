-- Drop the per-row redirect window end. Binaries that write expires_at must be gone first. The
-- cleaner then keeps every row for its own node's retention again, as an older binary does.
-- Metadata only; on a large live database drop the column out-of-band with a short lock_timeout,
-- as the up migration describes for the add, and this migration then only inspects the catalog.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
               WHERE attrelid = 'redirect_log'::regclass AND attname = 'expires_at' AND NOT attisdropped) THEN
        ALTER TABLE redirect_log DROP COLUMN IF EXISTS expires_at;
    END IF;
END $$;
