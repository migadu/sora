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
-- On more than 25,000 messages, this migration refuses unfinished preparation before any
-- DDL. A small database can safely do the work here, as migration 000050 also does. A failed
-- concurrent build is always refused: an existing INVALID v2 index must never cause the
-- valid old covering index to be dropped.
--
-- Recovery if startup refused: stop the new binaries and complete steps 1-3 above using a
-- direct primary connection. A failed migration is recorded as version 59, dirty, even
-- though this transaction rolled back all its DDL. Verify that version/dirty state with
--   sora-admin --config config.toml migrate version
-- then clear ONLY that failed attempt with
--   sora-admin --config config.toml migrate force 58
-- and restart (or run migrate up). Do not force 59: the migration should run again and
-- verify the prepared catalog. Older binaries can keep serving during preparation.

DO $$
DECLARE
    has_column boolean;
    has_v2 boolean;
    valid_v2 boolean;
    has_old boolean;
    message_rows bigint;
BEGIN
    SELECT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'messages'::regclass AND attname = 'extra_addresses' AND NOT attisdropped)
      INTO has_column;
    has_v2 := to_regclass('idx_messages_mailbox_headers_v2') IS NOT NULL;
    SELECT EXISTS (SELECT 1 FROM pg_index
                   WHERE indexrelid = to_regclass('idx_messages_mailbox_headers_v2') AND indisvalid AND indisready)
      INTO valid_v2;
    has_old := to_regclass('idx_messages_mailbox_headers') IS NOT NULL;

    -- Catalog-only fast path: even a bounded count would lock messages and wait behind
    -- an exclusive lock. A fully prepared production database needs no table access.
    IF has_column AND valid_v2 AND NOT has_old THEN
        RETURN;
    END IF;
    IF has_v2 AND NOT valid_v2 THEN
        RAISE EXCEPTION 'Migration 59: idx_messages_mailbox_headers_v2 is INVALID. Keep the old index; DROP INDEX CONCURRENTLY idx_messages_mailbox_headers_v2, then complete steps 1-3 in 000059_messages_extra_addresses.up.sql. If schema_migrations is 59 dirty, verify preparation, force 58 and retry.';
    END IF;

    SELECT count(*) INTO message_rows FROM (SELECT 1 FROM messages LIMIT 25001) s;
    IF message_rows > 25000 THEN
        RAISE EXCEPTION 'Migration 59: messages has more than 25000 rows and out-of-band preparation is incomplete. Refusing a blocking index rebuild/drop. Complete steps 1-3 in 000059_messages_extra_addresses.up.sql (add extra_addresses, CREATE INDEX CONCURRENTLY v2, verify indisvalid, DROP INDEX CONCURRENTLY old). If schema_migrations is 59 dirty, verify preparation, run sora-admin --config config.toml migrate force 58 and retry.';
    END IF;

    IF NOT has_column THEN
        ALTER TABLE messages ADD COLUMN extra_addresses TEXT;
    END IF;

    IF NOT has_v2 THEN
        CREATE INDEX idx_messages_mailbox_headers_v2 ON messages (mailbox_id)
          INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size,
                   subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort,
                   cc_email_sort, extra_addresses)
          WHERE expunged_at IS NULL;
    END IF;

    IF has_old THEN
        DROP INDEX idx_messages_mailbox_headers;
    END IF;
END $$;
