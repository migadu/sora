-- Restore idx_messages_mailbox_headers (migration 000052) and drop extra_addresses. Binaries
-- that search extra_addresses must be gone first. On a large database build the old index
-- with CREATE INDEX CONCURRENTLY out-of-band (DDL in migration 000052, same session settings)
-- and drop the new one with DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v2; the
-- index statements below then no-op, and the column drop is metadata only.

DO $$
BEGIN
    IF to_regclass('idx_messages_mailbox_headers') IS NULL THEN
        CREATE INDEX idx_messages_mailbox_headers ON messages (mailbox_id)
          INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size,
                   subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort, cc_email_sort)
          WHERE expunged_at IS NULL;
    END IF;

    IF to_regclass('idx_messages_mailbox_headers_v2') IS NOT NULL THEN
        DROP INDEX idx_messages_mailbox_headers_v2;
    END IF;
END $$;

ALTER TABLE messages DROP COLUMN IF EXISTS extra_addresses;
