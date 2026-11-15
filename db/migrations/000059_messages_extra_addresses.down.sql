-- Restore idx_messages_mailbox_headers (migration 000052) and drop extra_addresses. Binaries
-- that search extra_addresses must be gone first.
--
-- On a large database (> 25,000 messages), prepare out-of-band on the primary (not through
-- pgbouncer) so this migration does not take a blocking index build/drop lock on messages:
--   1. Build the old index with CREATE INDEX CONCURRENTLY (DDL and session settings in
--      000052_messages_mailbox_headers_index.up.sql) and verify pg_index.indisvalid = true.
--      If a concurrent build failed and left an INVALID idx_messages_mailbox_headers, run
--      DROP INDEX CONCURRENTLY idx_messages_mailbox_headers; before retrying.
--   2. Once idx_messages_mailbox_headers is valid:
--        DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v2;
--   3. Run migrate down 1 (or also drop extra_addresses out-of-band with a short lock_timeout;
--      when valid_old and NOT has_v2, only the metadata-only column drop remains, and when
--      extra_addresses is already gone this migration only inspects catalogs).
--
-- If rollback refused, schema_migrations is recorded as 58 dirty even though all DDL rolled
-- back. Complete preparation above, clear the failed attempt with
--   sora-admin --config config.toml migrate force 59
-- and retry migrate down 1.

DO $$
DECLARE
    has_column boolean;
    has_old boolean;
    valid_old boolean;
    has_v2 boolean;
    message_rows bigint;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'extra_addresses' AND NOT attisdropped)
      INTO has_column;
    has_old := to_regclass('idx_messages_mailbox_headers') IS NOT NULL;
    SELECT EXISTS (SELECT 1 FROM pg_index
                   WHERE indexrelid = to_regclass('idx_messages_mailbox_headers') AND indisvalid AND indisready)
      INTO valid_old;
    has_v2 := to_regclass('idx_messages_mailbox_headers_v2') IS NOT NULL;

    -- Catalog-only fast path when out-of-band rollback preparation is already complete.
    IF valid_old AND NOT has_v2 THEN
        IF has_column THEN
            ALTER TABLE messages DROP COLUMN extra_addresses;
        END IF;
        RETURN;
    END IF;

    SELECT count(*) INTO message_rows FROM (SELECT 1 FROM messages LIMIT 25001) s;
    IF message_rows > 25000 THEN
        IF has_old AND NOT valid_old THEN
            RAISE EXCEPTION 'Migration 59 down: idx_messages_mailbox_headers is INVALID. Keep idx_messages_mailbox_headers_v2; DROP INDEX CONCURRENTLY idx_messages_mailbox_headers, rebuild it with CREATE INDEX CONCURRENTLY (see 000052_messages_mailbox_headers_index.up.sql), verify indisvalid, and DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v2 before retrying. If schema_migrations is 58 dirty, run sora-admin --config config.toml migrate force 59 and retry.';
        END IF;
        RAISE EXCEPTION 'Migration 59 down: messages has more than 25000 rows and out-of-band rollback preparation is incomplete. Refusing a blocking index rebuild/drop. Build idx_messages_mailbox_headers with CREATE INDEX CONCURRENTLY (see 000052_messages_mailbox_headers_index.up.sql), verify indisvalid, and DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v2 first. If schema_migrations is 58 dirty, run sora-admin --config config.toml migrate force 59 and retry.';
    END IF;

    IF has_old AND NOT valid_old THEN
        DROP INDEX idx_messages_mailbox_headers;
    END IF;

    IF NOT valid_old THEN
        CREATE INDEX idx_messages_mailbox_headers ON messages (mailbox_id)
          INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size,
                   subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort, cc_email_sort)
          WHERE expunged_at IS NULL;
    END IF;

    IF has_v2 THEN
        DROP INDEX idx_messages_mailbox_headers_v2;
    END IF;

    IF has_column THEN
        ALTER TABLE messages DROP COLUMN extra_addresses;
    END IF;
END $$;
