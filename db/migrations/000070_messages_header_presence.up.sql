-- Forward-only header-presence metadata. NULL means unknown: old rows, old
-- writers and legacy COPY/MOVE/restore retain accepted historical search results.
-- No data backfill or lazy old-message/S3 read is performed. A non-NULL mask
-- records the fixed field set in helpers.HeaderPresenceBit from final ingress headers.
--
-- Large databases must prepare this out of band on a direct primary connection:
-- SET lock_timeout = '3s';
-- ALTER TABLE messages ADD COLUMN IF NOT EXISTS header_presence SMALLINT;
-- CREATE INDEX CONCURRENTLY idx_messages_mailbox_headers_v3 ON messages (mailbox_id)
--   INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size,
--            subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort,
--            cc_email_sort, extra_addresses, header_presence) WHERE expunged_at IS NULL;
-- Verify pg_index.indisvalid AND indisready; a failed build must be dropped
-- CONCURRENTLY and retried. Only then DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v2.
-- Both indexes occupy space and receive writes during replacement; provision that
-- temporary disk/IO load. Older writers ignore the nullable column; v3 covers v2.
-- Deploy upgraded writers, but do not backfill rows created before/during rollout.
-- If migration70 refused, preparation must finish before forcing ONLY the failed
-- attempt to69 and retrying up. Do not force70 to bypass catalog verification.
-- The catalog-only prepared fast path takes no messages table lock.

DO $$
DECLARE
    has_column boolean;
    has_v3 boolean;
    valid_v3 boolean;
    has_old boolean;
    message_rows bigint;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'header_presence' AND NOT attisdropped)
      INTO has_column;
    has_v3 := to_regclass('idx_messages_mailbox_headers_v3') IS NOT NULL;
    SELECT EXISTS (SELECT 1 FROM pg_index
                   WHERE indexrelid = to_regclass('idx_messages_mailbox_headers_v3') AND indisvalid AND indisready)
      INTO valid_v3;
    has_old := to_regclass('idx_messages_mailbox_headers_v2') IS NOT NULL;

    -- Catalog-only fast path: even a bounded count would lock messages and wait behind
    -- an exclusive lock. A fully prepared production database needs no table access.
    IF has_column AND valid_v3 AND NOT has_old THEN
        RETURN;
    END IF;
    IF has_v3 AND NOT valid_v3 THEN
        RAISE EXCEPTION 'Migration 70: idx_messages_mailbox_headers_v3 is INVALID. Keep the old index; DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v3, then complete steps 1-3 in 000070_messages_header_presence.up.sql. If schema_migrations is 70 dirty, verify preparation, force 69 and retry.';
    END IF;

    SELECT count(*) INTO message_rows FROM (SELECT 1 FROM messages LIMIT 25001) s;
    IF message_rows > 25000 THEN
        RAISE EXCEPTION 'Migration 70: messages has more than 25000 rows and out-of-band preparation is incomplete. Refusing a blocking index rebuild/drop. Complete steps 1-3 in 000070_messages_header_presence.up.sql (add header_presence, CREATE INDEX CONCURRENTLY v3, verify indisvalid and indisready, DROP INDEX CONCURRENTLY v2). If schema_migrations is 70 dirty, verify preparation, run sora-admin --config config.toml migrate force 69 and retry.';
    END IF;

    IF NOT has_column THEN
        ALTER TABLE messages ADD COLUMN header_presence SMALLINT;
    END IF;

    IF NOT has_v3 THEN
        CREATE INDEX idx_messages_mailbox_headers_v3 ON messages (mailbox_id)
          INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size,
                   subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort,
                   cc_email_sort, extra_addresses, header_presence)
          WHERE expunged_at IS NULL;
    END IF;

    IF has_old THEN
        DROP INDEX idx_messages_mailbox_headers_v2;
    END IF;
END $$;
