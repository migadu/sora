-- Per-account FTS rows + composite GIN: scope body search to the mailbox owner.
--
-- PROBLEM
--   messages_fts is keyed by content_hash alone and deduplicated across ALL accounts, so
--   the mailbox predicate (on `messages`) and the tsvector (on `messages_fts`) live in
--   different tables. No index can combine predicates across two tables, so the planner has
--   only two plans for a BODY/TEXT search:
--     1. drive from messages(mailbox_id): one PK probe + TOAST detoast + @@ per message in
--        the mailbox -- cost proportional to mailbox size, whatever the term;
--     2. drive from the GIN: heap-fetch every row in the WHOLE corpus containing the term,
--        then join down to the mailbox -- cost proportional to global term frequency.
--   The dictionary is 'simple' with no stop words, so a common word pulls a large slice of
--   the corpus. Both plans blow through the 30s SEARCH timeout on large mailboxes.
--
-- FIX
--   One FTS row per (content_hash, account_id) and one multicolumn GIN over
--   (account_id, text_body_tsv), using btree_gin. PostgreSQL then intersects the account's
--   posting list with each lexeme's posting list inside the index, so the work is
--   proportional to that ACCOUNT's hits for the term. This is the case btree_gin documents:
--   "for queries that test both a GIN-indexable column and a B-tree-indexable column, it
--   might be more efficient to create a multicolumn GIN index that uses one of these
--   operator classes than to create two separate indexes that would have to be combined via
--   bitmap ANDing."
--
--   Per-mailbox or per-domain PARTIAL indexes cannot do this: there is no column to
--   predicate on, one CREATE INDEX per tenant is unbounded, the planner examines every index
--   of a table at plan time, and a prepared statement would need a custom plan per literal.
--
-- GRANULARITY is the ACCOUNT, not the mailbox: a hash lives in several mailboxes of one
--   account (COPY, multi-alias delivery), and MOVE must stay an FTS no-op. Intra-account
--   dedup is kept; only cross-account dedup is given up. account_id is the mailbox OWNER
--   (shared mailboxes included), the account every search scopes to. messages.account_id
--   holds the same for mail delivered since June 2026, but not for older mail that someone
--   else added to a shared mailbox, so the population below keys on the mailbox.
--
-- PK ORDER is (content_hash, account_id): the hot paths -- the worker's fan-out across
--   sibling rows, the delivery-time sibling probe, and the orphan sweep's content_hash > $1
--   windowing -- are all hash-first.
--
-- The GIN is PARTIAL on text_body_tsv IS NOT NULL. Queued rows (NULL vector) would otherwise
--   be indexed as placeholder nulls and then re-indexed when the worker fills the vector.
--   Every FTS predicate the query builders emit already carries `text_body_tsv IS NOT NULL`
--   (db/search.go), so the partial predicate is matchable.
--
-- ON A LIVE PRODUCTION DATABASE, DO ALL OF THIS OUT-OF-BAND FIRST so this migration no-ops
-- (every statement below is IF NOT EXISTS). Full runbook in docs/fts-v2-rollout.md.
-- Short form, all on the primary, direct (not via a transaction pooler):
--
--   1. CREATE EXTENSION IF NOT EXISTS btree_gin;
--   2. the CREATE TABLE below, plus ONLY the _queue and _sent_date indexes.
--      Do NOT create the composite GIN yet: the GIN documentation is explicit that for bulk
--      insertion it is better to load first and build the index afterwards.
--   3. run scripts/fts_v2_backfill.sql (batched, paced, resumable, recency-first), then its
--      catch-up procedure until it reports 0 rows twice.
--   4. SET maintenance_work_mem = '2GB';  -- GIN build time is very sensitive to this
--      then the two remaining CREATE INDEX statements below, WITHOUT CONCURRENTLY.
--      Nothing reads or writes this table until the new binary is deployed, so a plain build
--      takes a ShareLock that costs users nothing -- and it is one table scan instead of
--      CONCURRENTLY's two plus its two wait phases. (GIN has no parallel build: the
--      documentation states only B-tree supports it, so this is single-threaded either way.)
--      Do not run a large import or `sora-admin messages restore` during the build: those are
--      the only long xid-holding transactions in the system.
--   5. ANALYZE messages_fts_v2;  -- not optional: without stats the planner has no @@
--      selectivity and can pick the very plan this migration exists to escape.
--   6. verify all replicas have caught up and carry the table and index, then deploy.
--
-- A CONCURRENTLY build must NOT be put in a migration file here: migrations run under the
-- leader advisory lock while every other instance polls with a 3 x migration_timeout
-- deadline (6 minutes by default), so a multi-hour build inside a migration fails every
-- other node's startup.
--
-- messages_fts is NOT dropped here. text_body is nulled the moment its vector is computed
-- (db/fts.go), so the tsvector is the ONLY copy of that data -- it cannot be recomputed
-- without re-fetching and re-parsing every body from S3. The old table stays, dual-written
-- by the new binary, until a later migration retires it after a soak.

CREATE EXTENSION IF NOT EXISTS btree_gin;

CREATE TABLE IF NOT EXISTS messages_fts_v2 (
    content_hash  VARCHAR(64)  NOT NULL,
    account_id    BIGINT       NOT NULL,
    text_body     TEXT,
    text_body_tsv tsvector,
    sent_date     TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (content_hash, account_id)
);

-- Population. The new binary answers every body search from this table alone, so applying
-- this migration to a database whose messages_fts holds vectors, and leaving this table
-- empty, would make body search return nothing for all existing mail -- silently.
--
--   - Already populated (the out-of-band backfill ran): nothing to do.
--   - Empty, and messages_fts is small (dev, tests, small installs): populate it here, before
--     the GIN below exists, so the bulk insert does not pay per-row GIN maintenance.
--   - Empty, and messages_fts is large: refuse. Copying hundreds of millions of rows inside
--     a startup migration would blow the migration timeout on every node; that is what the
--     out-of-band backfill is for.
--
-- The pair logic mirrors scripts/fts_v2_backfill.sql: one row per (hash, mailbox owner), no
-- expunged_at filter (restore relies on the row), falling back to messages.account_id for a
-- message whose mailbox is gone. Queued v1 rows copy their text for the worker to tokenise.
DO $$
DECLARE
    v1_rows bigint;
BEGIN
    IF EXISTS (SELECT 1 FROM messages_fts_v2) THEN
        RETURN;
    END IF;
    SELECT count(*) INTO v1_rows FROM (SELECT 1 FROM messages_fts LIMIT 250001) s;
    IF v1_rows = 0 THEN
        RETURN;
    END IF;
    IF v1_rows > 250000 THEN
        RAISE EXCEPTION 'messages_fts_v2 is empty but messages_fts has more than 250000 rows. Run the out-of-band backfill first (docs/fts-v2-rollout.md): applying this migration now would leave body search empty for all existing mail.';
    END IF;

    INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, sent_date, created_at)
    SELECT f.content_hash, p.account_id, f.text_body, f.text_body_tsv, f.sent_date, f.created_at
    FROM messages_fts f
    CROSS JOIN LATERAL (
        SELECT DISTINCT COALESCE(mb.account_id, m.account_id) AS account_id
        FROM messages m LEFT JOIN mailboxes mb ON mb.id = m.mailbox_id
        WHERE m.content_hash = f.content_hash
    ) p
    ON CONFLICT (content_hash, account_id) DO NOTHING;
END $$;

-- The search index. See the PARTIAL note above.
CREATE INDEX IF NOT EXISTS idx_messages_fts_v2_account_tsv ON messages_fts_v2
    USING gin (account_id, text_body_tsv) WHERE text_body_tsv IS NOT NULL;

-- fastupdate off, matching migrations 000020 / 000033 / 000034: the pending list turns a
-- predictable per-insert cost into an unpredictable flush on whichever transaction happens
-- to cross gin_pending_list_limit.
ALTER INDEX idx_messages_fts_v2_account_tsv SET (fastupdate = off);

-- Batched per-account purge (account delete, purge-domain). Without it those deletes have no
-- access path but a full scan, since the PK leads with content_hash.
CREATE INDEX IF NOT EXISTS idx_messages_fts_v2_account_id ON messages_fts_v2 (account_id);

-- The FTS worker's queue.
CREATE INDEX IF NOT EXISTS idx_messages_fts_v2_queue ON messages_fts_v2 (created_at)
    WHERE text_body_tsv IS NULL;

-- Retention pruning range scan, mirroring idx_messages_fts_sent_date: rows with a NULL
-- sent_date are deliberately never selected for pruning.
CREATE INDEX IF NOT EXISTS idx_messages_fts_v2_sent_date ON messages_fts_v2 (sent_date)
    WHERE sent_date IS NOT NULL;

-- Shape guard. Everything above is IF NOT EXISTS, which silently accepts a pre-existing
-- table created out-of-band with a DIFFERENT shape -- a divergent PK column order or a
-- non-partial GIN would both be silently wrong (the first makes the fan-out and sweep do
-- full scans, the second makes searches unable to use the index). Fail loudly instead.
-- Precedent: migration 000041's collision guard.
DO $$
DECLARE
    pk_cols text;
    gin_def text;
BEGIN
    SELECT string_agg(a.attname, ',' ORDER BY k.ord)
      INTO pk_cols
      FROM pg_constraint c
      JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
     WHERE c.conrelid = 'messages_fts_v2'::regclass AND c.contype = 'p';

    IF pk_cols IS DISTINCT FROM 'content_hash,account_id' THEN
        RAISE EXCEPTION
            'messages_fts_v2 primary key is (%), expected (content_hash,account_id). The table was created out-of-band with a different shape; drop it and re-create it with the DDL in this migration.',
            pk_cols;
    END IF;

    SELECT indexdef INTO gin_def
      FROM pg_indexes
     WHERE tablename = 'messages_fts_v2' AND indexname = 'idx_messages_fts_v2_account_tsv';

    IF gin_def IS NULL THEN
        RAISE EXCEPTION 'idx_messages_fts_v2_account_tsv is missing.';
    END IF;

    IF gin_def NOT LIKE '%account_id%' OR gin_def NOT LIKE '%text_body_tsv%'
       OR gin_def NOT LIKE '%WHERE (text_body_tsv IS NOT NULL)%' THEN
        RAISE EXCEPTION
            'idx_messages_fts_v2_account_tsv has the wrong definition (%). It must be a multicolumn GIN on (account_id, text_body_tsv) partial on text_body_tsv IS NOT NULL.',
            gin_def;
    END IF;
END $$;
