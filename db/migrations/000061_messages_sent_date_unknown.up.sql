-- A message without a Date: header that parses has no sent date. SORT and THREAD still order it,
-- by its INTERNALDATE (RFC 5256 §2.2: "If the sent date cannot be determined (a Date: header is
-- missing or cannot be parsed), the INTERNALDATE for that message is used as the sent date"), so
-- sent_date keeps holding a date, but the IMAP ENVELOPE must report the date member as NIL
-- (RFC 9051 §7.5.2) instead of passing that substitute off as the header (#1029).
-- sent_date_unknown is TRUE on such rows and NULL on every other one, so it costs the rows with a
-- Date: header nothing. NULL is also every row written before this migration, and by older
-- binaries during a rollout: those keep reporting sent_date, exactly as before. Existing rows
-- cannot be told apart from the database (the header is only in the stored body).
--
-- No index: only the readers that already fetch the message row look at it.
--
-- Metadata only (no default, no rewrite), but ADD COLUMN needs a brief ACCESS EXCLUSIVE lock
-- on messages, which must not queue in front of delivery behind a long query. On a large live
-- database add the column out-of-band first, on the primary, not through pgbouncer:
--   SET lock_timeout = '3s';
--   ALTER TABLE messages ADD COLUMN IF NOT EXISTS sent_date_unknown BOOLEAN;
-- and retry on a lock timeout. Running binaries ignore the column. The statement below checks
-- the catalog first and takes no lock on messages when the column is already there.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'sent_date_unknown' AND NOT attisdropped) THEN
        ALTER TABLE messages ADD COLUMN sent_date_unknown BOOLEAN;
    END IF;
END $$;
