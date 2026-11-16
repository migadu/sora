-- Drop the restored mark. Binaries that read restored_at must be gone first. The rows it marked
-- then read as deleted messages again, as they do to an older binary: they are listed, and a
-- restore of one is skipped while its restored copy is still live in the mailbox (same
-- Message-ID), until the cleaner purges them.
-- Metadata only; on a large live database drop the column out-of-band with a short
-- lock_timeout, as the up migration describes for the add, and this migration then only
-- inspects the catalog.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
               WHERE attrelid = 'messages'::regclass AND attname = 'restored_at' AND NOT attisdropped) THEN
        ALTER TABLE messages DROP COLUMN restored_at;
    END IF;
END $$;
