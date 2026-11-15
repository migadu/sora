-- SEARCH SENTBEFORE, SENTON and SENTSINCE match "Messages whose [RFC5322] Date: header field"
-- falls before, on or after the date (RFC 9051 §6.4.4). A message without a Date: header that
-- parses has none, yet its sent_date holds its INTERNALDATE, the sent date SORT and THREAD use
-- (RFC 5256 §2.2), so the keys leave out the rows migration 000061 marks sent_date_unknown
-- (#1118). sent_date_unknown is deliberately not in idx_messages_mailbox_headers_v2, and
-- testing it on the messages row would turn every date search back into a heap filter over
-- the whole mailbox (the 38 s case of migration 000052). The search instead tests for such
-- a row through this index (sentDateKnownCond in db/search.go), by anti-join or indexed lookup. It holds
-- only those rows: sent_date_unknown is NULL on every message with a Date: header and on
-- every row written before migration 000061, which keep matching by sent_date as before.
--
-- Production runbook. A plain CREATE INDEX holds a SHARE lock on messages, blocking delivery,
-- for a scan of the whole table, however few rows qualify. Build it out-of-band first, on the
-- primary, not through pgbouncer:
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_mailbox_sent_date_unknown
--     ON messages (mailbox_id, id) WHERE sent_date_unknown AND expunged_at IS NULL;
-- and check that it is valid:
--   SELECT indisvalid FROM pg_index WHERE indexrelid = 'idx_messages_mailbox_sent_date_unknown'::regclass;
-- A failed build leaves an INVALID index: DROP INDEX CONCURRENTLY idx_messages_mailbox_sent_date_unknown;
-- and retry. Running binaries ignore the index. This migration then only inspects the catalog.
--
-- On more than 25,000 messages it refuses to build the index itself, and it always refuses
-- an INVALID one, which the planner would not use. Startup then fails with version 62 dirty,
-- although the transaction rolled back: build the index as above, then
--   sora-admin --config config.toml migrate force 61
-- and restart. Older binaries keep serving meanwhile.

DO $$
DECLARE
    message_rows bigint;
BEGIN
    IF to_regclass('idx_messages_mailbox_sent_date_unknown') IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM pg_index
                       WHERE indexrelid = 'idx_messages_mailbox_sent_date_unknown'::regclass AND indisvalid AND indisready) THEN
            RAISE EXCEPTION 'Migration 62: idx_messages_mailbox_sent_date_unknown is INVALID. DROP INDEX CONCURRENTLY idx_messages_mailbox_sent_date_unknown, rebuild it with CREATE INDEX CONCURRENTLY (see 000062_messages_sent_date_unknown_index.up.sql), verify indisvalid, run sora-admin --config config.toml migrate force 61 and retry.';
        END IF;
        RETURN;
    END IF;

    SELECT count(*) INTO message_rows FROM (SELECT 1 FROM messages LIMIT 25001) s;
    IF message_rows > 25000 THEN
        RAISE EXCEPTION 'Migration 62: messages has more than 25000 rows and idx_messages_mailbox_sent_date_unknown was not built out-of-band. Refusing a blocking index build. Run CREATE INDEX CONCURRENTLY (see 000062_messages_sent_date_unknown_index.up.sql), verify indisvalid, run sora-admin --config config.toml migrate force 61 and retry.';
    END IF;

    CREATE INDEX idx_messages_mailbox_sent_date_unknown
        ON messages (mailbox_id, id) WHERE sent_date_unknown AND expunged_at IS NULL;
END $$;
