-- Drop the Date: header's zone offset. Binaries that read sent_utc_offset must be gone first.
-- Metadata only; on a large live database drop the column out-of-band with a short
-- lock_timeout, as the up migration describes for the add, and this migration then only
-- inspects the catalog.

DROP FUNCTION IF EXISTS message_sent_utc_offset(bigint);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute
               WHERE attrelid = 'messages'::regclass AND attname = 'sent_utc_offset' AND NOT attisdropped) THEN
        ALTER TABLE messages DROP COLUMN sent_utc_offset;
    END IF;
END $$;
