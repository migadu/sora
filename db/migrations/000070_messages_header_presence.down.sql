-- Stop binaries that read header_presence before down. No old-message data is
-- changed. On large tables first CREATE INDEX CONCURRENTLY the v2 definition in
-- migration59, verify indisvalid/indisready, then DROP INDEX CONCURRENTLY v3.
-- Drop header_presence with a short lock_timeout and retry on contention. With
-- those steps complete this is catalog-only; otherwise a large table refuses
-- blocking DDL. A failed down is69 dirty: verify preparation, force70 and retry.

DO $$
DECLARE
    has_column boolean;
    has_old boolean;
    valid_old boolean;
    has_v2 boolean;
    message_rows bigint;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'header_presence' AND NOT attisdropped)
      INTO has_column;
    has_old := to_regclass('idx_messages_mailbox_headers_v2') IS NOT NULL;
    SELECT EXISTS (SELECT 1 FROM pg_index
                   WHERE indexrelid = to_regclass('idx_messages_mailbox_headers_v2') AND indisvalid AND indisready)
      INTO valid_old;
    has_v2 := to_regclass('idx_messages_mailbox_headers_v3') IS NOT NULL;

    -- Catalog-only fast path when out-of-band rollback preparation is already complete.
    IF valid_old AND NOT has_v2 THEN
        IF has_column THEN
            ALTER TABLE messages DROP COLUMN header_presence;
        END IF;
        RETURN;
    END IF;

    SELECT count(*) INTO message_rows FROM (SELECT 1 FROM messages LIMIT 25001) s;
    IF message_rows > 25000 THEN
        IF has_old AND NOT valid_old THEN
            RAISE EXCEPTION 'Migration 70 down: idx_messages_mailbox_headers_v2 is INVALID. Keep idx_messages_mailbox_headers_v3; DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v2, rebuild it with CREATE INDEX CONCURRENTLY (see 000059_messages_extra_addresses.up.sql), verify indisvalid, and DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v3 before retrying. If schema_migrations is 69 dirty, run sora-admin --config config.toml migrate force 70 and retry.';
        END IF;
        RAISE EXCEPTION 'Migration 70 down: messages has more than 25000 rows and out-of-band rollback preparation is incomplete. Refusing a blocking index rebuild/drop. Build idx_messages_mailbox_headers_v2 with CREATE INDEX CONCURRENTLY (see 000059_messages_extra_addresses.up.sql), verify indisvalid, and DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v3 first. If schema_migrations is 69 dirty, run sora-admin --config config.toml migrate force 70 and retry.';
    END IF;

    IF has_old AND NOT valid_old THEN
        DROP INDEX idx_messages_mailbox_headers_v2;
    END IF;

    IF NOT valid_old THEN
        CREATE INDEX idx_messages_mailbox_headers_v2 ON messages (mailbox_id)
          INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size,
                   subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort, cc_email_sort, extra_addresses)
          WHERE expunged_at IS NULL;
    END IF;

    IF has_v2 THEN
        DROP INDEX idx_messages_mailbox_headers_v3;
    END IF;

    IF has_column THEN
        ALTER TABLE messages DROP COLUMN header_presence;
    END IF;
END $$;
