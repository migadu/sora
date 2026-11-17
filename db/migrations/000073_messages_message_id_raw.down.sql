-- Stop binaries that reference message_id_raw before rolling back migration 73.
-- On large tables (> 25,000 rows), first run out of band on a direct primary
-- connection:
--   DROP INDEX CONCURRENTLY IF EXISTS idx_messages_mailbox_message_id_raw;
--   SET lock_timeout = '3s';
--   ALTER TABLE messages DROP COLUMN IF EXISTS message_id_raw;
-- With those steps complete, this down migration is catalog-only.

DO $$
DECLARE
    has_column boolean;
    has_idx boolean;
    message_rows bigint;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'message_id_raw' AND NOT attisdropped)
      INTO has_column;
    has_idx := to_regclass('idx_messages_mailbox_message_id_raw') IS NOT NULL;

    IF NOT has_idx AND NOT has_column THEN
        RETURN;
    END IF;

    SELECT count(*) INTO message_rows FROM (SELECT 1 FROM messages LIMIT 25001) s;
    IF message_rows > 25000 THEN
        RAISE EXCEPTION 'Migration 73 down: messages has more than 25000 rows and out-of-band rollback preparation is incomplete. Refusing blocking DDL. Run DROP INDEX CONCURRENTLY IF EXISTS idx_messages_mailbox_message_id_raw and ALTER TABLE messages DROP COLUMN IF EXISTS message_id_raw with a short lock_timeout first; if schema_migrations is 72 dirty, run sora-admin --config config.toml migrate force 73 and retry.';
    END IF;

    IF has_idx THEN
        DROP INDEX idx_messages_mailbox_message_id_raw;
    END IF;

    IF has_column THEN
        ALTER TABLE messages DROP COLUMN message_id_raw;
    END IF;
END $$;
