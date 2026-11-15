-- SEARCH SENTBEFORE, SENTON and SENTSINCE compare the Date: header "disregarding time and
-- timezone" (RFC 9051 §6.4.4), which is the calendar day the header names in its own zone.
-- sent_date holds only the instant, so the zone was lost at insert time and the keys matched
-- the UTC day instead (#867): "Tue, 31 Dec 2024 20:00:00 -0800" was found under SENTON
-- 1-Jan-2025. sent_utc_offset keeps the header's UTC offset in seconds (east positive), so
-- sent_date + sent_utc_offset is its wall-clock time. NULL on every row written before this
-- migration, and by older binaries during a rollout: such rows are searched by the UTC day of
-- sent_date, exactly as before. Existing rows cannot be filled from the database (the header is
-- only in the stored body).
--
-- No index, and deliberately not in idx_messages_mailbox_headers_v2: the SENT* keys decide
-- every message sent more than a day from the searched date by sent_date alone, and read the
-- offset by primary key only for the others (sentDayCond in db/search.go), so a date search
-- stays an Index Only Scan over the mailbox. They read it through message_sent_utc_offset()
-- rather than a subquery: the planner charges a subquery's cost to every row of the mailbox
-- although it runs only for that band, which swamps the difference between the index-only
-- scan and a heap scan of the mailbox and lets it pick the heap scan. A SQL function with a
-- FROM clause is never inlined, so its declared COST is what the planner sees.
--
-- Metadata only (no default, no rewrite), but ADD COLUMN needs a brief ACCESS EXCLUSIVE lock
-- on messages, which must not queue in front of delivery behind a long query. On a large live
-- database add the column out-of-band first, on the primary, not through pgbouncer:
--   SET lock_timeout = '3s';
--   ALTER TABLE messages ADD COLUMN IF NOT EXISTS sent_utc_offset INTEGER;
-- and retry on a lock timeout. Running binaries ignore the column. The statement below checks
-- the catalog first and takes no lock on messages when the column is already there.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'sent_utc_offset' AND NOT attisdropped) THEN
        ALTER TABLE messages ADD COLUMN sent_utc_offset INTEGER;
    END IF;
END $$;

-- $1 is the messages.id. (A parameter named message_id would resolve to the column instead.)
CREATE OR REPLACE FUNCTION message_sent_utc_offset(bigint) RETURNS integer
    LANGUAGE sql STABLE PARALLEL SAFE COST 1
    AS $$ SELECT sent_utc_offset FROM messages WHERE id = $1 $$;
