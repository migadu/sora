-- Drop the "no Date: header" mark. Binaries that read sent_date_unknown must be gone first.
-- Metadata only; on a large live database drop the column out-of-band with a short
-- lock_timeout, as the up migration describes for the add, and this migration then only
-- inspects the catalog.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
               WHERE attrelid = 'messages'::regclass AND attname = 'sent_date_unknown' AND NOT attisdropped) THEN
        ALTER TABLE messages DROP COLUMN sent_date_unknown;
    END IF;
END $$;
