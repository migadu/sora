-- A restored message is a new row, and the expunged row it was restored from is kept (#1712).
--
-- `messages restore` used to bring a message back by rewriting its expunged row in place: a new
-- UID, expunged_at and expunged_modseq cleared. That row was the only record that the old UID had
-- been expunged, and when, so a session not yet told of the expunge was never sent it, and QRESYNC
-- and UID FETCH (CHANGEDSINCE ... VANISHED) never reported the old UID (RFC 7162 section 3.2.5.1:
-- the server sends the expunges "that have occurred in this mailbox since the provided modification
-- sequence"). A restore now inserts a new row for the message, as MOVE does, and leaves the
-- expunged row in place as that record, until the cleaner purges it with the other expunged rows.
--
-- restored_at marks such a row: its message has been restored, so the row is neither listed as a
-- deleted message nor restored a second time. NULL on every other row, which is every row written
-- before this migration and by older binaries during a rollout.
--
-- No index: only the restore paths read it, after narrowing to one account's expunged rows.
--
-- Metadata only (no default, no rewrite), but ADD COLUMN needs a brief ACCESS EXCLUSIVE lock
-- on messages, which must not queue in front of delivery behind a long query. On a large live
-- database add the column out-of-band first, on the primary, not through pgbouncer:
--   SET lock_timeout = '3s';
--   ALTER TABLE messages ADD COLUMN IF NOT EXISTS restored_at TIMESTAMPTZ;
-- and retry on a lock timeout. Running binaries ignore the column. The statement below checks
-- the catalog first and takes no lock on messages when the column is already there.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'restored_at' AND NOT attisdropped) THEN
        ALTER TABLE messages ADD COLUMN IF NOT EXISTS restored_at TIMESTAMPTZ;
    END IF;
END $$;
