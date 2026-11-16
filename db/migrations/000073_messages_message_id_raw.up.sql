-- Forward-only raw Message-ID field text for non-canonical headers (#529).
--
-- Ordinary messages with a single canonical "Message-ID: <id@domain>" (and no
-- domain-literal brackets) store NULL in message_id_raw: their normalized
-- messages.message_id column reconstructs "<id@domain>" losslessly and serves
-- whole-ID equality lookups via idx_messages_message_id.
--
-- Messages whose Message-ID field has surrounding comments/CFWS, is present-empty,
-- is unparseable, uses obsolete quoted local-parts (<"<inner"@example.com>),
-- contains domain-literal brackets (<outer@[<inner@example.com>]>), or appears
-- multiple times store the unfolded field text in message_id_raw and are indexed
-- by idx_messages_mailbox_message_id_raw so whole-ID searches combine
-- idx_messages_message_id and idx_messages_mailbox_message_id_raw via BitmapOr
-- without scanning the mailbox heap.
--
-- Large databases (> 25,000 rows) must prepare this out of band on a direct
-- primary connection (not through PgBouncer):
--   SET lock_timeout = '3s';
--   ALTER TABLE messages ADD COLUMN IF NOT EXISTS message_id_raw TEXT;
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_mailbox_message_id_raw
--     ON messages (mailbox_id, id)
--     WHERE message_id_raw IS NOT NULL AND expunged_at IS NULL;
-- Verify pg_index.indisvalid AND indisready; if INVALID, DROP INDEX CONCURRENTLY
-- idx_messages_mailbox_message_id_raw and retry. If migration 73 refused, finish
-- preparation, run sora-admin --config config.toml migrate force 72, and retry.

DO $$
DECLARE
    has_column boolean;
    has_idx boolean;
    valid_idx boolean;
    message_rows bigint;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'message_id_raw' AND NOT attisdropped)
      INTO has_column;
    has_idx := to_regclass('idx_messages_mailbox_message_id_raw') IS NOT NULL;
    SELECT EXISTS (SELECT 1 FROM pg_index
                   WHERE indexrelid = to_regclass('idx_messages_mailbox_message_id_raw') AND indisvalid AND indisready)
      INTO valid_idx;

    -- Catalog-only fast path when out-of-band preparation is complete.
    IF has_column AND valid_idx THEN
        RETURN;
    END IF;
    IF has_idx AND NOT valid_idx THEN
        RAISE EXCEPTION 'Migration 73: idx_messages_mailbox_message_id_raw is INVALID. DROP INDEX CONCURRENTLY idx_messages_mailbox_message_id_raw, rebuild it with CREATE INDEX CONCURRENTLY (see 000073_messages_message_id_raw.up.sql), verify indisvalid, run sora-admin --config config.toml migrate force 72 and retry.';
    END IF;

    SELECT count(*) INTO message_rows FROM (SELECT 1 FROM messages LIMIT 25001) s;
    IF message_rows > 25000 THEN
        RAISE EXCEPTION 'Migration 73: messages has more than 25000 rows and out-of-band preparation is incomplete. Refusing a blocking index build. Add message_id_raw and run CREATE INDEX CONCURRENTLY idx_messages_mailbox_message_id_raw (see 000073_messages_message_id_raw.up.sql), verify indisvalid, run sora-admin --config config.toml migrate force 72 and retry.';
    END IF;

    IF NOT has_column THEN
        ALTER TABLE messages ADD COLUMN message_id_raw TEXT;
    END IF;

    IF NOT has_idx THEN
        CREATE INDEX idx_messages_mailbox_message_id_raw
            ON messages (mailbox_id, id)
            WHERE message_id_raw IS NOT NULL AND expunged_at IS NULL;
    END IF;
END $$;
