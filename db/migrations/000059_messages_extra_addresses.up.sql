-- SEARCH FROM/TO/CC must match every address of the header, not only the first one.
-- RFC 9051 §6.4.4 defines them on "the envelope structure's FROM [TO, CC] field", the list of
-- every address in that header. The *_sort columns hold the first address only and are the
-- RFC 5256 SORT keys, so they keep that meaning; extra_addresses holds, lowercased, every
-- other From/To/Cc name and address plus the first Cc's name (layout: extraAddressesSectionSep
-- in db/append.go). NULL means "written before this migration": the search treats it as no
-- further addresses, so such rows are matched on their first addresses only, exactly as
-- before, until scripts/backfill_extra_addresses.sql fills them.
--
-- Header search must stay an Index Only Scan (migration 000052: the heap filter measured 38 s
-- on a 534k-message mailbox, over the 30 s read timeout), so the covering index has to carry
-- the new column. INCLUDE lists cannot be altered, hence a second index, _v2, replacing
-- idx_messages_mailbox_headers. Its tuple stays under the 2704-byte btree limit because the
-- five sort columns and extra_addresses share a 1300-byte bound applied at write time
-- (helpers.MaxAddressColumnsBytes; extra_addresses gets what the five leave, at least 300).
-- Old rows are NULL here and cannot exceed it.
--
-- Production runbook. Do NOT let the migration do any of this on a large table: it runs as one
-- transaction, so the column's ACCESS EXCLUSIVE lock would be held across a plain CREATE INDEX
-- of the whole table, blocking every read and write on messages for hours. Out-of-band, on
-- the primary, not through pgbouncer:
--   1. Add the column. Metadata only (no default, no rewrite), but it needs a brief ACCESS
--      EXCLUSIVE lock, which must not queue in front of delivery behind a long query:
--        SET lock_timeout = '3s';
--        ALTER TABLE messages ADD COLUMN IF NOT EXISTS extra_addresses TEXT;
--      and retry on a lock timeout. Running binaries ignore the column.
--   2. Build the new index, in a session with the settings from migration 000052 step 2
--      (temp_file_limit = -1, maintenance_work_mem, max_parallel_maintenance_workers,
--      statement_timeout = 0). Expect the same build time and size as idx_messages_mailbox_headers
--      (~45-65 GB on 210M rows; the column is NULL in every existing row), and twice that on
--      disk until step 3; every insert maintains both indexes meanwhile.
--        CREATE INDEX CONCURRENTLY idx_messages_mailbox_headers_v2 ON messages (mailbox_id)
--          INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size,
--                   subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort,
--                   cc_email_sort, extra_addresses)
--          WHERE expunged_at IS NULL;
--      A failed build leaves an INVALID index: check
--        SELECT indisvalid FROM pg_index WHERE indexrelid = 'idx_messages_mailbox_headers_v2'::regclass;
--      and DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v2; before retrying.
--   3. Once it is valid: DROP INDEX CONCURRENTLY idx_messages_mailbox_headers;
--      Binaries without this migration search through the new index just as well (it carries
--      every column the old one did), so this can happen before the deploy.
--   4. Deploy the binary with this migration. Every statement below checks the catalog first
--      and takes no lock on messages when its work is already done.
--   5. Optional, once every node runs it: fill the rows written before step 4 (and by older
--      binaries during the rollout) with scripts/backfill_extra_addresses.sql. Until then those
--      messages are found by their first From/To/Cc address only, as before this migration.
--
-- On a large database, do not deploy the binary before steps 1-3. Without step 2 this
-- migration builds the index under the column's lock; without step 3 it drops the old index
-- with a plain DROP INDEX, an ACCESS EXCLUSIVE lock on messages that queues behind every
-- running query and blocks every new one.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'extra_addresses' AND NOT attisdropped) THEN
        ALTER TABLE messages ADD COLUMN extra_addresses TEXT;
    END IF;

    IF to_regclass('idx_messages_mailbox_headers_v2') IS NULL THEN
        CREATE INDEX idx_messages_mailbox_headers_v2 ON messages (mailbox_id)
          INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size,
                   subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort,
                   cc_email_sort, extra_addresses)
          WHERE expunged_at IS NULL;
    END IF;

    IF to_regclass('idx_messages_mailbox_headers') IS NOT NULL THEN
        DROP INDEX idx_messages_mailbox_headers;
    END IF;
END $$;
